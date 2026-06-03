/**
 * e2e_test.js — сквозной тест защищённого канала
 *
 * Эмулирует HQ и Remote через ws-клиент, проводит handshake,
 * отправляет сообщение, потом намеренно искажает пакет и проверяет,
 * что HMAC-валидация отвергает подмену.
 */

const WebSocket = require('ws');
const crypto = require('crypto');

// ----- Утилиты -----
function bufToB64(buf) { return Buffer.from(buf).toString('base64'); }
function b64ToBuf(b64) { return Buffer.from(b64, 'base64'); }

// ----- ECDH через Node crypto -----
function genEcdh() {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    return ecdh;
}

// Web Crypto использует raw uncompressed (0x04 || X || Y, 65 байт),
// Node ECDH тоже умеет такой формат
function exportPubRaw(ecdh) {
    return ecdh.getPublicKey(null, 'uncompressed');
}

function deriveKeys(ecdh, peerPubRaw) {
    const shared = ecdh.computeSecret(peerPubRaw);

    // HKDF-SHA256 — выводим 2 ключа из общего секрета
    const salt = Buffer.from('secure-channel-salt-v1');
    const enc = crypto.hkdfSync('sha256', shared, salt,
                                Buffer.from('aes-gcm-encryption-key'), 32);
    const mac = crypto.hkdfSync('sha256', shared, salt,
                                Buffer.from('hmac-sha256-mac-key'), 32);

    const fp = crypto.createHash('sha256').update(shared).digest('base64').slice(0, 16);
    return { encKey: Buffer.from(enc), macKey: Buffer.from(mac), fingerprint: fp };
}

function encryptPacket(plaintext, encKey, macKey, counter) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const ciphertext = Buffer.concat([ct, tag]); // совместимо с Web Crypto

    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));

    const macInput = Buffer.concat([iv, ciphertext, counterBuf]);
    const hmac = crypto.createHmac('sha256', macKey).update(macInput).digest();

    return {
        iv: iv.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        hmac: hmac.toString('base64'),
        counter
    };
}

function decryptPacket(packet, encKey, macKey, expectedMin) {
    const iv = b64ToBuf(packet.iv);
    const fullCt = b64ToBuf(packet.ciphertext);
    const hmac = b64ToBuf(packet.hmac);
    const counter = packet.counter;

    if (counter <= expectedMin) throw new Error('REPLAY');

    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));

    const expectedMac = crypto.createHmac('sha256', macKey)
        .update(Buffer.concat([iv, fullCt, counterBuf])).digest();

    if (!crypto.timingSafeEqual(hmac, expectedMac)) {
        throw new Error('HMAC_INVALID');
    }

    const ciphertext = fullCt.slice(0, fullCt.length - 16);
    const tag = fullCt.slice(fullCt.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

// ----- Эмулятор стороны -----
class Peer {
    constructor(name, peerId) {
        this.name = name;
        this.peerId = peerId;     // 'hq' | 'remote'
        this.ws = null;
        this.ecdh = null;
        this.encKey = null;
        this.macKey = null;
        this.outCounter = 0;
        this.lastInCounter = -1;
        this.received = [];
        this.attacks = [];
    }

    log(...args) { console.log(`[${this.name}]`, ...args); }

    async connect(tunnelId) {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket('ws://localhost:8080');
            this.ws.on('open', () => {
                this.log('connected to gateway');
                this.ecdh = genEcdh();
                this.send({ type: 'join', tunnelId, peer: this.peerId, user: this.name });
            });
            this.ws.on('message', (raw) => {
                const msg = JSON.parse(raw);
                this.handle(msg);
                if (msg.type === 'joined') resolve();
            });
            this.ws.on('error', reject);
            setTimeout(() => reject(new Error('connect timeout')), 3000);
        });
    }

    handle(msg) {
        switch (msg.type) {
            case 'joined':
                this.log(`joined tunnel as ${msg.peer}, both=${msg.bothPresent}`);
                if (msg.bothPresent) this.startHandshake();
                break;
            case 'ready_for_handshake':
                this.startHandshake();
                break;
            case 'handshake':
                this.onHandshake(msg);
                break;
            case 'data':
                this.onData(msg);
                break;
            case 'error':
                this.log('gateway error:', msg.error, msg.detail || '');
                break;
        }
    }

    startHandshake() {
        const pub = exportPubRaw(this.ecdh);
        this.log('sending ECDH public key');
        this.send({ type: 'handshake', publicKey: pub.toString('base64') });
    }

    onHandshake(msg) {
        const peerPub = b64ToBuf(msg.publicKey);
        const { encKey, macKey, fingerprint } = deriveKeys(this.ecdh, peerPub);
        this.encKey = encKey;
        this.macKey = macKey;
        this.fingerprint = fingerprint;
        this.log(`session established. fingerprint=${fingerprint}`);
    }

    sendSecure(text) {
        this.outCounter += 1;
        const pkt = encryptPacket(text, this.encKey, this.macKey, this.outCounter);
        this.log(`sending #${this.outCounter}: "${text}" -> ${pkt.ciphertext.slice(0, 30)}...`);
        this.send({ type: 'data', ...pkt });
        return pkt;
    }

    sendTampered(text) {
        // Шлём пакет с искажённым ciphertext (моделирует MITM)
        this.outCounter += 1;
        const pkt = encryptPacket(text, this.encKey, this.macKey, this.outCounter);
        const buf = b64ToBuf(pkt.ciphertext);
        buf[0] ^= 0xff;
        pkt.ciphertext = buf.toString('base64');
        this.log(`sending TAMPERED #${this.outCounter}`);
        this.send({ type: 'data', ...pkt });
    }

    onData(msg) {
        try {
            const text = decryptPacket(
                { iv: msg.iv, ciphertext: msg.ciphertext, hmac: msg.hmac, counter: msg.counter },
                this.encKey, this.macKey, this.lastInCounter
            );
            this.lastInCounter = msg.counter;
            this.received.push(text);
            this.log(`✓ received #${msg.counter}: "${text}"`);
        } catch (e) {
            this.attacks.push(e.message);
            this.log(`✗ ATTACK BLOCKED: ${e.message}`);
        }
    }

    send(obj) { this.ws.send(JSON.stringify(obj)); }
    close() { this.ws.close(); }
}

// ----- Сценарий теста -----
async function main() {
    console.log('=== E2E TEST: Secure Channel ===\n');

    const hq = new Peer('HQ', 'hq');
    const remote = new Peer('REMOTE', 'remote');

    const tunnelId = 'test-tunnel-' + Date.now();

    await hq.connect(tunnelId);
    await new Promise(r => setTimeout(r, 200));
    await remote.connect(tunnelId);

    // Ждём handshake
    await new Promise(r => setTimeout(r, 800));

    if (!hq.encKey || !remote.encKey) {
        console.error('\n❌ Handshake failed');
        process.exit(1);
    }

    if (hq.fingerprint !== remote.fingerprint) {
        console.error(`\n❌ Fingerprints differ: ${hq.fingerprint} vs ${remote.fingerprint}`);
        process.exit(1);
    }
    console.log(`\n✓ Handshake OK. Shared fingerprint: ${hq.fingerprint}\n`);

    // ТЕСТ 1: нормальная отправка HQ -> Remote
    hq.sendSecure('Привет из главного офиса! Это секретное сообщение.');
    await new Promise(r => setTimeout(r, 300));

    // ТЕСТ 2: ответ Remote -> HQ
    remote.sendSecure('Получено. Высылаем отчёт по проекту.');
    await new Promise(r => setTimeout(r, 300));

    // ТЕСТ 3: подмена пакета (MITM) — HMAC должен поймать
    hq.sendTampered('эту строку никто не увидит');
    await new Promise(r => setTimeout(r, 300));

    // ТЕСТ 4: ещё одно валидное сообщение после подмены — должно пройти
    hq.sendSecure('Канал работает после атаки.');
    await new Promise(r => setTimeout(r, 300));

    // Итоги
    console.log('\n=== RESULTS ===');
    console.log(`HQ received:     ${hq.received.length} messages`);
    console.log(`REMOTE received: ${remote.received.length} messages`);
    console.log(`Attacks blocked at REMOTE: ${remote.attacks.length} (expected: 1)`);
    console.log(`Attacks blocked at HQ:     ${hq.attacks.length}`);

    let pass = true;
    if (remote.received.length !== 2) { console.error('❌ REMOTE should have 2 messages'); pass = false; }
    if (hq.received.length !== 1)     { console.error('❌ HQ should have 1 message'); pass = false; }
    if (remote.attacks.length !== 1 || !remote.attacks[0].includes('HMAC')) {
        console.error('❌ REMOTE should have blocked 1 HMAC attack'); pass = false;
    }

    console.log(pass ? '\n✅ ALL TESTS PASSED' : '\n❌ TESTS FAILED');

    hq.close();
    remote.close();
    process.exit(pass ? 0 : 1);
}

main().catch(e => {
    console.error('Test error:', e);
    process.exit(1);
});
