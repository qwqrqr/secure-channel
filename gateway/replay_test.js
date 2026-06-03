/**
 * replay_test.js — проверка защиты от replay-атак
 *
 * Сценарий: HQ отправляет легальный пакет, потом REMOTE-злоумышленник
 * пытается повторно отправить тот же counter. Шлюз должен отклонить.
 */
const WebSocket = require('ws');

function ws(url) {
    return new Promise((resolve, reject) => {
        const w = new WebSocket(url);
        w.on('open', () => resolve(w));
        w.on('error', reject);
    });
}

async function main() {
    console.log('=== REPLAY ATTACK TEST ===\n');
    const tunnelId = 'replay-test-' + Date.now();

    const hq = await ws('ws://localhost:8080');
    const remote = await ws('ws://localhost:8080');

    let replayBlocked = false;

    hq.on('message', raw => {
        const m = JSON.parse(raw);
        if (m.type === 'error' && m.error === 'replay_detected') {
            console.log(`✓ Gateway blocked replay: ${m.detail}`);
            replayBlocked = true;
        }
    });

    hq.send(JSON.stringify({ type: 'join', tunnelId, peer: 'hq', user: 'hq' }));
    remote.send(JSON.stringify({ type: 'join', tunnelId, peer: 'remote', user: 'remote' }));
    await new Promise(r => setTimeout(r, 200));

    // Отправляем пакет с counter=5
    const fakePacket = {
        type: 'data',
        iv: 'AAAAAAAAAAAAAAAA',
        ciphertext: 'YmxhYmxh',
        hmac: 'aGFzaA==',
        counter: 5
    };

    hq.send(JSON.stringify(fakePacket));
    await new Promise(r => setTimeout(r, 200));

    // Теперь повторяем тот же counter — шлюз должен отклонить
    console.log('Replaying same counter=5...');
    hq.send(JSON.stringify(fakePacket));
    await new Promise(r => setTimeout(r, 200));

    // И counter=3 (меньше предыдущего) — тоже должен отклонить
    console.log('Sending lower counter=3...');
    hq.send(JSON.stringify({ ...fakePacket, counter: 3 }));
    await new Promise(r => setTimeout(r, 200));

    hq.close();
    remote.close();

    console.log(replayBlocked ? '\n✅ REPLAY PROTECTION WORKS' : '\n❌ REPLAY NOT BLOCKED');
    process.exit(replayBlocked ? 0 : 1);
}

main().catch(e => { console.error(e); process.exit(1); });
