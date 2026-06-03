/**
 * channel.js — клиентская сторона защищённого канала
 * ---------------------------------------------------
 * Объединяет crypto.js и WebSocket-связь со шлюзом.
 *
 * Состояния туннеля:
 *   IDLE → CONNECTING → JOINED → HANDSHAKING → ESTABLISHED → CLOSED
 */

import {
    generateECDHKeyPair, exportPublicKey, importPeerPublicKey,
    deriveSessionKeys, encryptPacket, decryptPacket
} from './crypto.js';

export class SecureChannel extends EventTarget {
    constructor({ gatewayUrl, tunnelId, peer, user }) {
        super();
        this.gatewayUrl = gatewayUrl;     // ws://localhost:8080
        this.tunnelId = tunnelId;         // общий ID для HQ и Remote
        this.peer = peer;                 // 'hq' | 'remote'
        this.user = user;

        this.state = 'IDLE';
        this.ws = null;
        this.keyPair = null;
        this.encKey = null;
        this.macKey = null;
        this.fingerprint = null;

        this.outCounter = 0;     // мой счётчик исходящих
        this.lastInCounter = -1; // последний полученный (для anti-replay)
    }

    setState(s, info = {}) {
        this.state = s;
        this.dispatchEvent(new CustomEvent('state', { detail: { state: s, ...info } }));
    }

    log(level, message, data = {}) {
        this.dispatchEvent(new CustomEvent('log', {
            detail: { level, message, data, ts: new Date().toISOString() }
        }));
    }

    async connect() {
        this.setState('CONNECTING');
        this.log('info', `Подключение к шлюзу ${this.gatewayUrl}`);

        this.ws = new WebSocket(this.gatewayUrl);

        this.ws.addEventListener('open', () => this.onOpen());
        this.ws.addEventListener('message', (e) => this.onMessage(e));
        this.ws.addEventListener('close', () => {
            this.log('warn', 'Соединение со шлюзом разорвано');
            this.setState('CLOSED');
        });
        this.ws.addEventListener('error', (e) => {
            this.log('error', 'Ошибка WebSocket', { error: String(e) });
        });
    }

    async onOpen() {
        this.log('info', 'TCP/WebSocket поднят. Отправляю JOIN...');

        // Сразу генерируем ECDH-пару — пригодится для handshake
        this.keyPair = await generateECDHKeyPair();
        this.log('info', 'Сгенерирована ECDH P-256 пара ключей');

        this.send({
            type: 'join',
            tunnelId: this.tunnelId,
            peer: this.peer,
            user: this.user
        });
    }

    async onMessage(event) {
        let msg;
        try {
            msg = JSON.parse(event.data);
        } catch {
            this.log('error', 'Не удалось распарсить сообщение от шлюза');
            return;
        }

        switch (msg.type) {
            case 'joined':
                this.setState('JOINED', { bothPresent: msg.bothPresent });
                this.log('info', `Подключён к туннелю ${msg.tunnelId} как ${msg.peer}`);
                if (msg.bothPresent) {
                    this.log('info', 'Обе стороны на месте — начинаю handshake');
                    await this.startHandshake();
                } else {
                    this.log('info', 'Жду подключения второй стороны...');
                }
                break;

            case 'ready_for_handshake':
                if (this.state === 'JOINED') {
                    await this.startHandshake();
                }
                break;

            case 'handshake':
                await this.onHandshake(msg);
                break;

            case 'data':
                await this.onData(msg);
                break;

            case 'peer_left':
                this.log('warn', `Партнёр (${msg.peer}) отключился. Туннель неактивен.`);
                this.setState('JOINED', { bothPresent: false });
                this.encKey = null;
                this.macKey = null;
                this.outCounter = 0;
                this.lastInCounter = -1;
                break;

            case 'error':
                this.log('error', `Шлюз вернул ошибку: ${msg.error}`, msg);
                break;

            case 'pong':
                break;
        }
    }

    async startHandshake() {
        this.setState('HANDSHAKING');
        const myPub = await exportPublicKey(this.keyPair);
        this.log('info', 'Отправляю свой ECDH публичный ключ', {
            publicKey: myPub.slice(0, 24) + '...'
        });
        this.send({
            type: 'handshake',
            publicKey: myPub
        });
    }

    async onHandshake(msg) {
        this.log('info', `Получен публичный ключ партнёра (${msg.from})`, {
            publicKey: msg.publicKey.slice(0, 24) + '...'
        });

        const peerPub = await importPeerPublicKey(msg.publicKey);
        const { encKey, macKey, fingerprint } = await deriveSessionKeys(
            this.keyPair.privateKey,
            peerPub
        );

        this.encKey = encKey;
        this.macKey = macKey;
        this.fingerprint = fingerprint;

        this.outCounter = 0;
        this.lastInCounter = -1;

        this.setState('ESTABLISHED', { fingerprint });
        this.log('success', `Сеансовый ключ выведен (HKDF). Туннель установлен.`, {
            fingerprint
        });
    }

    async send_secure(plaintext) {
        if (this.state !== 'ESTABLISHED') {
            throw new Error('Канал не установлен');
        }

        this.outCounter += 1;
        const packet = await encryptPacket(plaintext, this.encKey, this.macKey, this.outCounter);

        this.log('info', `Отправляю зашифрованный пакет #${this.outCounter}`, {
            ciphertextSize: packet.ciphertext.length,
            ivSize: packet.iv.length
        });

        this.send({
            type: 'data',
            ...packet
        });

        return packet;
    }

    async onData(msg) {
        try {
            const plaintext = await decryptPacket(
                {
                    iv: msg.iv,
                    ciphertext: msg.ciphertext,
                    hmac: msg.hmac,
                    counter: msg.counter
                },
                this.encKey,
                this.macKey,
                this.lastInCounter
            );

            this.lastInCounter = msg.counter;

            this.log('success', `Получен пакет #${msg.counter} от ${msg.from} — расшифрован`, {
                plaintext
            });

            this.dispatchEvent(new CustomEvent('message', {
                detail: { from: msg.from, plaintext, counter: msg.counter }
            }));
        } catch (e) {
            // Это очень важная ветка для демо: атака обнаружена
            this.log('error', `АТАКА ПЕРЕХВАЧЕНА: ${e.message}`, { packet: msg });
            this.dispatchEvent(new CustomEvent('attack', {
                detail: { reason: e.message, packet: msg }
            }));
        }
    }

    send(obj) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(obj));
        }
    }

    close() {
        if (this.ws) this.ws.close();
    }
}

// ============================================================
// Расширение SecureChannel: файлы и синхронизация DLP-правил
// ============================================================
// Добавляем методы прямо к прототипу, чтобы не трогать основной класс.

/**
 * Отправляет файл: сериализует в JSON-пакет, шифрует как обычное сообщение.
 * payload = { __type: 'file', name, mimeType, size, data: base64 }
 */
SecureChannel.prototype.send_file = async function(fileObj) {
    if (this.state !== 'ESTABLISHED') throw new Error('Канал не установлен');
    const payload = JSON.stringify(fileObj);
    return this.send_secure(payload);
};

/**
 * Отправляет обновление DLP-правил второй стороне.
 * payload = { __type: 'dlp_rules', rules: [...] }
 */
SecureChannel.prototype.sync_rules = async function(rules) {
    if (this.state !== 'ESTABLISHED') throw new Error('Канал не установлен');
    const payload = JSON.stringify({ __type: 'dlp_rules', rules });
    return this.send_secure(payload);
};
