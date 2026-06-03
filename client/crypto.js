/**
 * crypto.js — криптографический модуль защищённого канала
 * --------------------------------------------------------
 * Использует Web Crypto API (нативно в браузере, без библиотек).
 *
 * Схема:
 *   1) ECDH P-256 — обмен публичными ключами через шлюз.
 *   2) HKDF-SHA256 — из общего секрета выводим:
 *        - encKey  (AES-GCM 256)
 *        - macKey  (HMAC-SHA256)
 *   3) AES-GCM шифрует payload (даёт конфиденциальность + integrity tag).
 *   4) HMAC-SHA256 — дополнительная подпись поверх (iv|ciphertext|counter).
 *      В реальной системе AES-GCM достаточно, но HMAC включён по двум причинам:
 *        - нагляднее для защиты диплома (комиссия видит явный MAC),
 *        - демонстрирует принцип Encrypt-then-MAC.
 */

// ---------- Утилиты конвертации ----------

export function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

export function b64ToBuf(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- 1. ECDH: генерация пары ключей ----------

export async function generateECDHKeyPair() {
    return await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
    );
}

export async function exportPublicKey(keyPair) {
    const raw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    return bufToB64(raw);
}

export async function importPeerPublicKey(b64) {
    return await crypto.subtle.importKey(
        'raw',
        b64ToBuf(b64),
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
    );
}

// ---------- 2. ECDH + HKDF: вывод сеансовых ключей ----------

/**
 * Из приватного ключа стороны и публичного ключа партнёра выводим
 * общий секрет, затем через HKDF получаем encKey и macKey.
 */
export async function deriveSessionKeys(privateKey, peerPublicKey) {
    // Общий секрет ECDH (256 бит)
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: peerPublicKey },
        privateKey,
        256
    );

    // Импортируем как HKDF baseKey
    const baseKey = await crypto.subtle.importKey(
        'raw', sharedSecret, 'HKDF', false, ['deriveKey']
    );

    // Производим encKey (AES-GCM 256)
    const encKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: enc.encode('secure-channel-salt-v1'),
            info: enc.encode('aes-gcm-encryption-key')
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );

    // Производим macKey (HMAC-SHA256)
    const macKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: enc.encode('secure-channel-salt-v1'),
            info: enc.encode('hmac-sha256-mac-key')
        },
        baseKey,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign', 'verify']
    );

    // Fingerprint сеансового ключа (для UI, чтобы показать что обе стороны
    // получили одинаковый ключ)
    const fp = await crypto.subtle.digest('SHA-256', sharedSecret);
    const fingerprint = bufToB64(fp).slice(0, 16);

    return { encKey, macKey, fingerprint };
}

// ---------- 3. Шифрование пакета ----------

/**
 * encryptPacket — собирает защищённый пакет.
 *
 * Возвращает { iv, ciphertext, hmac, counter } — это и есть всё, что
 * уйдёт по проводу. Никакой открытой части полезной нагрузки.
 */
export async function encryptPacket(plaintext, encKey, macKey, counter) {
    // 96-битный IV для GCM (рекомендация NIST)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        encKey,
        enc.encode(plaintext)
    );

    // HMAC поверх iv|ciphertext|counter — Encrypt-then-MAC
    const counterBytes = new Uint8Array(8);
    new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter), false);

    const macInput = concatBytes([iv, new Uint8Array(ciphertext), counterBytes]);
    const macSig = await crypto.subtle.sign('HMAC', macKey, macInput);

    return {
        iv: bufToB64(iv),
        ciphertext: bufToB64(ciphertext),
        hmac: bufToB64(macSig),
        counter
    };
}

// ---------- 4. Расшифровка и проверка ----------

export async function decryptPacket(packet, encKey, macKey, expectedMinCounter) {
    const iv = new Uint8Array(b64ToBuf(packet.iv));
    const ciphertext = new Uint8Array(b64ToBuf(packet.ciphertext));
    const hmac = new Uint8Array(b64ToBuf(packet.hmac));
    const counter = packet.counter;

    // 1. Anti-replay: счётчик должен расти
    if (typeof counter !== 'number' || counter <= expectedMinCounter) {
        throw new Error(`REPLAY_DETECTED: counter ${counter} <= ${expectedMinCounter}`);
    }

    // 2. Проверка HMAC ПЕРЕД расшифровкой (Encrypt-then-MAC)
    const counterBytes = new Uint8Array(8);
    new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter), false);
    const macInput = concatBytes([iv, ciphertext, counterBytes]);

    const valid = await crypto.subtle.verify('HMAC', macKey, hmac, macInput);
    if (!valid) {
        throw new Error('HMAC_INVALID: пакет был изменён или подделан');
    }

    // 3. Расшифровка AES-GCM (тоже проверит свой integrity tag)
    let plaintextBuf;
    try {
        plaintextBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            encKey,
            ciphertext
        );
    } catch {
        throw new Error('AES_GCM_FAILED: невозможно расшифровать (неверный ключ или повреждён)');
    }

    return dec.decode(plaintextBuf);
}

// ---------- helpers ----------

function concatBytes(arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
        out.set(a, offset);
        offset += a.length;
    }
    return out;
}
