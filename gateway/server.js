/**
 * SECURE CHANNEL GATEWAY
 * ----------------------
 * Имитирует VPN-концентратор, через который соединяются HQ и Remote Office.
 *
 * Принципы:
 *  - Шлюз НЕ знает сеансовых ключей сторон (end-to-end).
 *  - Шлюз только маршрутизирует пакеты и ведёт аудит.
 *  - Все полезные данные передаются как { iv, ciphertext, hmac, counter }.
 *  - Handshake: ECDH P-256 публичные ключи проходят через шлюз,
 *    но без приватных ключей расшифровать трафик невозможно.
 *
 * Запуск: node server.js
 * Порт:   8080 (WebSocket) + 8081 (HTTP для эндпоинтов аудита)
 */

const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const { db } = require('./firebase');

const WS_PORT = 8080;
const HTTP_PORT = 8081;

// ===================== СОСТОЯНИЕ ШЛЮЗА =====================

/**
 * Активные туннели. Ключ — tunnelId, значение — { hq: ws, remote: ws, sessionMeta }
 */
const tunnels = new Map();

/**
 * Журнал событий канала (то, что в реальной жизни шло бы в Firebase).
 * Здесь храним в памяти, плюс отдаём через HTTP /audit
 */
const auditLog = [];

/**
 * Перехватываемый трафик — то, что увидел бы атакующий на проводе.
 * Используется для демо «перехвата» в учебных целях.
 */
const wireDump = [];

async function logEvent(type, data) {
    const entry = {
        ts: new Date().toISOString(),
        type,
        ...data
    };

    auditLog.push(entry);

    console.log("[AUDIT]", type, data);

    if (auditLog.length > 500) auditLog.shift();

    try {
        await db.collection("logs").add(entry);
    } catch (e) {
        console.log("Firebase error:", e);
    }
}
    


function dumpWire(direction, tunnelId, payload) {
    const entry = {
        ts: new Date().toISOString(),
        direction,    // 'hq->gw', 'gw->remote', и т.д.
        tunnelId,
        payload       // именно то, что прошло по проводу
    };
    wireDump.push(entry);
    if (wireDump.length > 200) wireDump.shift();
}

// ===================== HTTP АУДИТ =====================

const httpServer = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    if (req.url === '/audit') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(auditLog));
        return;
    }

    if (req.url === '/wire') {
        // Демо-эндпоинт: что видит атакующий, прослушивающий канал
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(wireDump));
        return;
    }

    if (req.url === '/tunnels') {
        const list = [];
        for (const [id, t] of tunnels.entries()) {
            list.push({
                tunnelId: id,
                hqConnected: !!t.hq,
                remoteConnected: !!t.remote,
                established: t.established,
                packetsRelayed: t.packetsRelayed
            });
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(list));
        return;
    }

    if (req.url === '/clear' && req.method === 'POST') {
        auditLog.length = 0;
        wireDump.length = 0;
        res.writeHead(200);
        res.end('cleared');
        return;
    }

    res.writeHead(404);
    res.end('not found');
});

httpServer.listen(HTTP_PORT, () => {
    console.log(`[HTTP] Audit endpoints on http://localhost:${HTTP_PORT}/audit`);
});

// ===================== WEBSOCKET ШЛЮЗ =====================

const wss = new WebSocket.Server({ port: WS_PORT });
console.log(`[WS]   Gateway listening on ws://localhost:${WS_PORT}`);

wss.on('connection', (ws, req) => {
    const ip = req.socket.remoteAddress;
    console.log(`[CONN] New connection from ${ip}`);

    ws.on('message', (raw) => {
        let msg;
        try {
            msg = JSON.parse(raw.toString());
        } catch {
            ws.send(JSON.stringify({ type: 'error', error: 'invalid_json' }));
            return;
        }

        handleMessage(ws, msg);
    });

    ws.on('close', () => {
        // Удаляем эту сторону из всех туннелей
        for (const [id, t] of tunnels.entries()) {
            if (t.hq === ws) {
                t.hq = null;
                logEvent('peer_disconnected', { tunnelId: id, peer: 'hq' });
                if (t.remote) t.remote.send(JSON.stringify({ type: 'peer_left', peer: 'hq' }));
            }
            if (t.remote === ws) {
                t.remote = null;
                logEvent('peer_disconnected', { tunnelId: id, peer: 'remote' });
                if (t.hq) t.hq.send(JSON.stringify({ type: 'peer_left', peer: 'remote' }));
            }
            if (!t.hq && !t.remote) tunnels.delete(id);
        }
    });
});

function handleMessage(ws, msg) {
    switch (msg.type) {
        case 'join':       return handleJoin(ws, msg);
        case 'handshake':  return handleHandshake(ws, msg);
        case 'data':       return handleData(ws, msg);
        case 'ping':       return ws.send(JSON.stringify({ type: 'pong' }));
        default:
            ws.send(JSON.stringify({ type: 'error', error: 'unknown_type' }));
    }
}

// ----- 1. JOIN: сторона объявляет, кто она -----
function handleJoin(ws, msg) {
    const { tunnelId, peer, user } = msg;
    if (!tunnelId || !['hq', 'remote'].includes(peer)) {
        ws.send(JSON.stringify({ type: 'error', error: 'bad_join' }));
        return;
    }

    let t = tunnels.get(tunnelId);
    if (!t) {
        t = {
            hq: null,
            remote: null,
            established: false,
            packetsRelayed: 0,
            counters: { hq: 0, remote: 0 }   // защита от replay
        };
        tunnels.set(tunnelId, t);
    }

    t[peer] = ws;
    ws._peer = peer;
    ws._tunnelId = tunnelId;
    ws._user = user || 'anonymous';

    logEvent('peer_joined', { tunnelId, peer, user: ws._user });

    ws.send(JSON.stringify({
        type: 'joined',
        tunnelId,
        peer,
        bothPresent: !!(t.hq && t.remote)
    }));

    // Если присутствуют обе стороны — уведомить их о готовности к handshake
    if (t.hq && t.remote) {
        const notify = JSON.stringify({ type: 'ready_for_handshake' });
        t.hq.send(notify);
        t.remote.send(notify);
        logEvent('tunnel_both_present', { tunnelId });
    }
}

// ----- 2. HANDSHAKE: пересылка ECDH публичных ключей -----
function handleHandshake(ws, msg) {
    const t = tunnels.get(ws._tunnelId);
    if (!t) return;

    const target = ws._peer === 'hq' ? t.remote : t.hq;
    if (!target) {
        ws.send(JSON.stringify({ type: 'error', error: 'peer_not_present' }));
        return;
    }

    // Шлюз ВИДИТ публичный ключ — это нормально, ECDH так и работает.
    // Но сеансовый ключ шлюзу недоступен (нужен приватный ключ).
    logEvent('handshake_relay', {
        tunnelId: ws._tunnelId,
        from: ws._peer,
        publicKeyFingerprint: shortHash(msg.publicKey)
    });

    dumpWire(`${ws._peer}->gw`, ws._tunnelId, {
        type: 'handshake',
        publicKey: msg.publicKey
    });

    target.send(JSON.stringify({
        type: 'handshake',
        from: ws._peer,
        publicKey: msg.publicKey
    }));

    // Когда обе стороны обменялись ключами — туннель установлен
    if (msg.final) {
        t.established = true;
        logEvent('tunnel_established', { tunnelId: ws._tunnelId });
    }
}

// ----- 3. DATA: передача зашифрованного payload -----
function handleData(ws, msg) {
    const t = tunnels.get(ws._tunnelId);
    if (!t) return;

    const target = ws._peer === 'hq' ? t.remote : t.hq;
    if (!target) {
        ws.send(JSON.stringify({ type: 'error', error: 'peer_not_present' }));
        return;
    }

    // Anti-replay: counter должен монотонно расти
    const senderCounter = t.counters[ws._peer];
    if (typeof msg.counter !== 'number' || msg.counter <= senderCounter) {
        logEvent('replay_blocked', {
            tunnelId: ws._tunnelId,
            from: ws._peer,
            expected: `> ${senderCounter}`,
            got: msg.counter
        });
        ws.send(JSON.stringify({
            type: 'error',
            error: 'replay_detected',
            detail: `counter must be > ${senderCounter}`
        }));
        return;
    }
    t.counters[ws._peer] = msg.counter;

    // ШЛЮЗ НЕ РАСШИФРОВЫВАЕТ. Только пересылает packet.
    const packet = {
        type: 'data',
        from: ws._peer,
        iv: msg.iv,
        ciphertext: msg.ciphertext,
        hmac: msg.hmac,
        counter: msg.counter
    };

    dumpWire(`${ws._peer}->gw`, ws._tunnelId, packet);
    dumpWire(`gw->${target._peer}`, ws._tunnelId, packet);

    target.send(JSON.stringify(packet));
    t.packetsRelayed++;

    logEvent('packet_relayed', {
        tunnelId: ws._tunnelId,
        from: ws._peer,
        counter: msg.counter,
        ciphertextSize: msg.ciphertext?.length || 0
    });
}

// ===================== УТИЛИТЫ =====================

function shortHash(str) {
    return crypto.createHash('sha256').update(str || '').digest('hex').slice(0, 16);
}

console.log('\n=== Secure Channel Gateway is running ===');
console.log(`WebSocket:  ws://localhost:${WS_PORT}`);
console.log(`Audit:      http://localhost:${HTTP_PORT}/audit`);
console.log(`Wire dump:  http://localhost:${HTTP_PORT}/wire`);
console.log(`Tunnels:    http://localhost:${HTTP_PORT}/tunnels`);
console.log('==========================================\n');
