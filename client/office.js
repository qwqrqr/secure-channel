/**
 * office.js — логика страницы офиса (HQ или Remote)
 * --------------------------------------------------
 * Роль определяется URL-параметром ?peer=hq|remote
 *
 * НОВЫЕ ВОЗМОЖНОСТИ:
 *  - Загрузка и просмотр файлов (PDF, Word, Excel, изображения, текст)
 *  - DLP-проверка файлов ДО шифрования
 *  - Отправка файлов через зашифрованный канал
 *  - Скачивание полученных файлов
 *  - Синхронизация DLP-правил между сторонами в реальном времени
 */

import { SecureChannel } from './channel.js';
import { DEFAULT_RULES, inspect, highlight } from './dlp.js';
import { encryptPacket } from './crypto.js';
import {
    ALLOWED_TYPES, MAX_FILE_SIZE,
    fileToBase64, inspectFile, buildFilePreview,
    downloadFile, getFileIcon, formatSize
} from './file-handler.js';

const GATEWAY_URL = 'ws://localhost:8080';

// -------- Роль по URL --------
const params = new URLSearchParams(location.search);
const peer = params.get('peer') === 'remote' ? 'remote' : 'hq';
const peerLabel = peer === 'hq' ? 'HQ' : 'REMOTE';

document.title = `Secure Channel — ${peerLabel}`;
const roleBadge = document.getElementById('roleBadge');
roleBadge.textContent = peerLabel;
roleBadge.className = `role-badge role-${peer}`;
document.getElementById('userInput').value = peer === 'hq' ? 'admin@hq' : 'user@remote';

// -------- Вкладки Текст / Файл --------
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${tab}`).classList.add('active');
    });
});

// -------- DLP правила --------
let rules = [...DEFAULT_RULES];
renderRules();

function renderRules() {
    const tb = document.getElementById('rulesBody');
    tb.innerHTML = rules.map((r, idx) => `
        <tr>
            <td>${escapeHtml(r.name)}</td>
            <td><code>${escapeHtml(r.regex)}</code></td>
            <td><span class="state-pill ${r.action === 'block' ? 'err' : 'warn'}">${r.action}</span></td>
            <td><button class="btn-sm" onclick="removeRule(${idx})" title="Удалить">✕</button></td>
        </tr>
    `).join('');
}

// Глобальная функция удаления правила (вызывается из inline onclick)
window.removeRule = async function(idx) {
    rules.splice(idx, 1);
    renderRules();
    await syncRulesToPeer('Правило удалено');
};

document.getElementById('addRuleBtn').addEventListener('click', async () => {
    const name = document.getElementById('ruleName').value.trim();
    const regex = document.getElementById('ruleRegex').value.trim();
    const action = document.getElementById('ruleAction').value;

    if (!name || !regex) return alert('Заполните название и regex');
    try { new RegExp(regex); } catch { return alert('Неверный regex'); }

    rules.push({ id: 'custom_' + Date.now(), name, regex, action });
    renderRules();
    document.getElementById('ruleName').value = '';
    document.getElementById('ruleRegex').value = '';

    await syncRulesToPeer('Добавлено новое правило');
});

/**
 * Отправляет текущий набор правил второй стороне через зашифрованный канал.
 */
async function syncRulesToPeer(reason = '') {
    if (!channel || channel.state !== 'ESTABLISHED') return;
    try {
        await channel.sync_rules(rules);
        addLog({ level: 'info', message: `🔄 DLP-правила синхронизированы с партнёром${reason ? ': ' + reason : ''}`, ts: new Date().toISOString() });
        flashSyncBadge();
    } catch (e) {
        addLog({ level: 'warn', message: 'Не удалось синхронизировать DLP-правила: ' + e.message, ts: new Date().toISOString() });
    }
}

function flashSyncBadge() {
    const badge = document.getElementById('syncBadge');
    badge.style.display = 'inline-block';
    clearTimeout(badge._timer);
    badge._timer = setTimeout(() => { badge.style.display = 'none'; }, 3000);
}

// -------- Работа с файлом --------
let selectedFile = null;
let selectedFileB64 = null;

const fileDropZone = document.getElementById('fileDropZone');
const fileInput = document.getElementById('fileInput');

// Клик на зону
fileDropZone.addEventListener('click', () => fileInput.click());

// Drag & Drop
fileDropZone.addEventListener('dragover', e => { e.preventDefault(); fileDropZone.classList.add('dragover'); });
fileDropZone.addEventListener('dragleave', () => fileDropZone.classList.remove('dragover'));
fileDropZone.addEventListener('drop', async e => {
    e.preventDefault();
    fileDropZone.classList.remove('dragover');
    const f = e.dataTransfer.files[0];
    if (f) await loadFile(f);
});

fileInput.addEventListener('change', async () => {
    const f = fileInput.files[0];
    if (f) await loadFile(f);
});

document.getElementById('clearFileBtn').addEventListener('click', () => {
    selectedFile = null;
    selectedFileB64 = null;
    document.getElementById('filePreviewArea').style.display = 'none';
    document.getElementById('fileDropZone').style.display = 'block';
    document.getElementById('fileDlpResult').innerHTML = '';
    fileInput.value = '';
});

async function loadFile(file) {
    // Проверка размера
    if (file.size > MAX_FILE_SIZE) {
        alert(`Файл слишком большой (${formatSize(file.size)}). Максимум — 10 МБ.`);
        return;
    }

    // Проверка типа
    const allowed = ALLOWED_TYPES[file.type];
    if (!allowed) {
        alert(`Тип файла «${file.type || 'неизвестный'}» не поддерживается.\n\nДопустимые форматы: PDF, Word, Excel, PowerPoint, изображения, текст.`);
        return;
    }

    selectedFile = file;
    fileDropZone.style.display = 'none';

    // Показываем метаданные
    document.getElementById('prevIcon').textContent = getFileIcon(file.type);
    document.getElementById('prevName').textContent = file.name;
    document.getElementById('prevSize').textContent = `${allowed.label} · ${formatSize(file.size)}`;

    // Читаем в base64
    selectedFileB64 = await fileToBase64(file);

    // Строим превью
    const preview = buildFilePreview(selectedFileB64, file.type, file.name);
    const inner = document.getElementById('filePreviewInner');
    inner.innerHTML = preview.html;

    // Слушаем download из office-превью
    inner.addEventListener('download-preview', () => {
        downloadFile(selectedFileB64, file.type, file.name);
    });

    document.getElementById('filePreviewArea').style.display = 'block';
    document.getElementById('sendFileBtn').disabled = (channel?.state !== 'ESTABLISHED');
}

// DLP-проверка файла
document.getElementById('checkFileDlpBtn').addEventListener('click', async () => {
    if (!selectedFile) return;
    await runFileDlpCheck();
});

async function runFileDlpCheck() {
    const result = await inspectFile(selectedFile, rules);
    const box = document.getElementById('fileDlpResult');

    let html = `<div class="dlp-result">
        <div class="dlp-status-${result.status}">
            DLP-статус файла: <b>${result.status.toUpperCase()}</b>
        </div>`;

    if (result.matches.length) {
        html += '<ul style="margin:6px 0 0 16px; font-size:13px;">';
        for (const m of result.matches) {
            html += `<li class="${m.action === 'block' ? 'dlp-file-block' : 'dlp-file-warn'}">
                <b>${escapeHtml(m.ruleName)}</b> [${m.action}] — ${m.samples.map(escapeHtml).join(', ')}
            </li>`;
        }
        html += '</ul>';
    } else {
        html += '<div style="color:var(--ok);font-size:13px;margin-top:4px;">✓ Запрещённых данных не обнаружено</div>';
    }
    html += '</div>';
    box.innerHTML = html;
    return result;
}

// Отправка файла
document.getElementById('sendFileBtn').addEventListener('click', async () => {
    if (!selectedFile || !selectedFileB64) return;

    // DLP-проверка
    const dlpResult = await runFileDlpCheck();

    if (dlpResult.status === 'block') {
        addLog({
            level: 'error',
            message: `🚫 DLP заблокировал отправку файла «${selectedFile.name}»: ${dlpResult.matches.map(m => m.ruleName).join(', ')}`,
            ts: new Date().toISOString()
        });
        return;
    }

    if (dlpResult.status === 'warning') {
        const ok = confirm(`DLP предупреждает: в файле «${selectedFile.name}» обнаружены подозрительные данные.\n\nВсё равно отправить?`);
        if (!ok) return;
    }

    // Формируем пакет файла
    const filePacket = {
        __type: 'file',
        name: selectedFile.name,
        mimeType: selectedFile.type,
        size: selectedFile.size,
        data: selectedFileB64
    };

    try {
        addLog({
            level: 'info',
            message: `📤 Отправляю файл «${selectedFile.name}» (${formatSize(selectedFile.size)}) — шифрую AES-GCM...`,
            ts: new Date().toISOString()
        });

        // send_file шифрует как обычный текстовый пакет (JSON)
        await channel.send_file(filePacket);

        // Показываем в чате как исходящий файл
        addFileMessage('out', filePacket, null);

        addLog({
            level: 'success',
            message: `✅ Файл «${selectedFile.name}» отправлен зашифрованным`,
            ts: new Date().toISOString()
        });

        // Сброс
        document.getElementById('clearFileBtn').click();
    } catch (e) {
        alert('Ошибка отправки файла: ' + e.message);
    }
});

// -------- Канал --------
let channel = null;

document.getElementById('connectBtn').addEventListener('click', async () => {
    const tunnelId = document.getElementById('tunnelInput').value.trim();
    const user = document.getElementById('userInput').value.trim() || 'anon';
    if (!tunnelId) return alert('Укажите ID туннеля');

    document.getElementById('tunnelLabel').textContent = tunnelId;

    channel = new SecureChannel({ gatewayUrl: GATEWAY_URL, tunnelId, peer, user });

    channel.addEventListener('state', e => {
        const { state, fingerprint } = e.detail;
        const lbl = document.getElementById('stateLabel');
        lbl.textContent = state;
        lbl.className = 'state-pill';
        if (state === 'ESTABLISHED') {
            lbl.classList.add('ok');
            document.getElementById('sendBtn').disabled = false;
            document.getElementById('fingerprintRow').style.display = 'block';
            document.getElementById('fingerprint').textContent = fingerprint;
            if (selectedFile) document.getElementById('sendFileBtn').disabled = false;
        } else if (state === 'CLOSED') {
            lbl.classList.add('err');
            document.getElementById('sendBtn').disabled = true;
            document.getElementById('sendFileBtn').disabled = true;
        } else {
            lbl.classList.add('warn');
        }
    });

    channel.addEventListener('log', e => addLog(e.detail));

    channel.addEventListener('message', e => {
        const { from, plaintext, counter } = e.detail;

        // Проверяем — это файловый пакет или DLP-синхронизация?
        if (plaintext.startsWith('{') && plaintext.includes('__type')) {
            try {
                const parsed = JSON.parse(plaintext);

                if (parsed.__type === 'file') {
                    // Входящий файл
                    addLog({
                        level: 'success',
                        message: `📥 Получен файл «${parsed.name}» от ${from.toUpperCase()} (${formatSize(parsed.size)}) — расшифрован`,
                        ts: new Date().toISOString()
                    });
                    addFileMessage('in', parsed, from);
                    return;
                }

                if (parsed.__type === 'dlp_rules' && Array.isArray(parsed.rules)) {
                    // Синхронизация DLP-правил от партнёра
                    rules = parsed.rules;
                    renderRules();
                    flashSyncBadge();
                    addLog({
                        level: 'info',
                        message: `🔄 DLP-правила обновлены партнёром (${from.toUpperCase()}) — ${rules.length} правил`,
                        ts: new Date().toISOString()
                    });
                    addMessage('system',
                        `⚡ DLP-правила обновлены партнёром: ${rules.length} правил активно`,
                        `от ${from.toUpperCase()} · #${counter}`
                    );
                    return;
                }
            } catch { /* не JSON — показываем как текст */ }
        }

        // Обычное текстовое сообщение
        addMessage('in', plaintext, `от ${from.toUpperCase()} · #${counter}`);
    });

    channel.addEventListener('attack', e => {
        const { reason, packet } = e.detail;
        addMessage('attack', `🚨 Пакет отвергнут: ${reason}`, `counter=${packet.counter}`);
    });

    await channel.connect();
    document.getElementById('connectBtn').disabled = true;
});

// -------- DLP проверка текста --------
document.getElementById('checkDlpBtn').addEventListener('click', () => runDlpCheck());

function runDlpCheck() {
    const text = document.getElementById('msgInput').value;
    if (!text.trim()) return;

    const result = inspect(text, rules);
    const box = document.getElementById('dlpResult');
    box.style.display = 'block';

    let html = `<div class="dlp-status-${result.status}">
        Статус: <b>${result.status.toUpperCase()}</b>
    </div>`;

    if (result.matches.length) {
        html += '<div style="margin-top:6px;">Совпадения:<ul style="margin:4px 0 0 16px;">';
        for (const m of result.matches) {
            html += `<li><b>${escapeHtml(m.ruleName)}</b> [${m.action}] — ${m.samples.map(escapeHtml).join(', ')}</li>`;
        }
        html += '</ul></div>';
    }

    html += `<div style="margin-top:8px; padding:8px; background:#020617; border-radius:4px;">
        ${highlight(text, rules)}
    </div>`;

    box.innerHTML = html;
}

// -------- Отправка текста --------
document.getElementById('sendBtn').addEventListener('click', async () => {
    const text = document.getElementById('msgInput').value;
    if (!text.trim()) return;

    // DLP перед шифрованием — принципиальный момент архитектуры
    const result = inspect(text, rules);

    if (result.status === 'block') {
        addLog({
            level: 'error',
            message: `🚫 DLP заблокировал отправку: ${result.matches.map(m => m.ruleName).join(', ')}`,
            ts: new Date().toISOString()
        });
        runDlpCheck();
        return;
    }

    if (result.status === 'warning') {
        const ok = confirm('DLP предупреждает: в сообщении есть подозрительные данные.\n\nВсё равно отправить?');
        if (!ok) return;
    }

    try {
        await channel.send_secure(text);
        addMessage('out', text, `→ зашифровано AES-GCM, подписано HMAC-SHA256`);
        document.getElementById('msgInput').value = '';
        document.getElementById('dlpResult').style.display = 'none';
    } catch (e) {
        alert('Ошибка отправки: ' + e.message);
    }
});

// -------- Атака: подмена пакета --------
document.getElementById('tamperBtn').addEventListener('click', async () => {
    if (!channel || channel.state !== 'ESTABLISHED') {
        alert('Сначала установите канал');
        return;
    }
    channel.outCounter += 1;
    const packet = await encryptPacket('LEGITIMATE_MESSAGE', channel.encKey, channel.macKey, channel.outCounter);

    const tampered = atob(packet.ciphertext);
    const buf = new Uint8Array(tampered.length);
    for (let i = 0; i < tampered.length; i++) buf[i] = tampered.charCodeAt(i);
    buf[0] ^= 0xff;
    let bin = '';
    for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
    packet.ciphertext = btoa(bin);

    addLog({ level: 'warn', message: '⚠ Намеренно отправляю изменённый пакет (моделирую MITM)', ts: new Date().toISOString() });
    channel.send({ type: 'data', ...packet });
});

// -------- Демо-кнопки --------
document.getElementById('openWireBtn').addEventListener('click', () => {
    window.open('eve.html', '_blank', 'width=900,height=700');
});
document.getElementById('openAuditBtn').addEventListener('click', () => {
    window.open('http://localhost:8081/audit', '_blank');
});

// -------- UI: просмотр и скачивание файлов в чате --------
const modal = document.getElementById('fileViewModal');
const modalBody = document.getElementById('modalBody');
const modalFileName = document.getElementById('modalFileName');
let modalCurrentFile = null;

document.getElementById('closeModalBtn').addEventListener('click', () => {
    modal.style.display = 'none';
    modalBody.innerHTML = '';
    modalCurrentFile = null;
});

document.getElementById('modalDownloadBtn').addEventListener('click', () => {
    if (modalCurrentFile) {
        downloadFile(modalCurrentFile.data, modalCurrentFile.mimeType, modalCurrentFile.name);
    }
});

// Закрыть по клику на фон
modal.addEventListener('click', e => {
    if (e.target === modal) document.getElementById('closeModalBtn').click();
});

function openFileModal(filePacket) {
    modalCurrentFile = filePacket;
    modalFileName.textContent = `${getFileIcon(filePacket.mimeType)} ${filePacket.name}`;
    const preview = buildFilePreview(filePacket.data, filePacket.mimeType, filePacket.name);
    modalBody.innerHTML = preview.html;

    // Слушаем download из office-превью внутри модалки
    modalBody.addEventListener('download-preview', () => {
        downloadFile(filePacket.data, filePacket.mimeType, filePacket.name);
    }, { once: true });

    modal.style.display = 'block';
}

/**
 * Добавляет сообщение о файле в чат-историю.
 */
function addFileMessage(direction, filePacket, from) {
    const box = document.getElementById('messages');
    const wrap = document.createElement('div');
    wrap.className = `message file-msg ${direction}`;

    const icon = getFileIcon(filePacket.mimeType);
    const label = direction === 'out'
        ? '→ Вы отправили'
        : `← ${from ? from.toUpperCase() : 'Партнёр'} отправил`;

    wrap.innerHTML = `
        <div class="file-msg-header">
            <span style="font-size:20px;">${icon}</span>
            <div>
                <div style="font-weight:600;">${escapeHtml(filePacket.name)}</div>
                <div class="meta">${label} · ${formatSize(filePacket.size)}</div>
            </div>
        </div>
        <div class="file-msg-actions">
            <button class="btn-sm accent view-btn">👁 Просмотреть</button>
            <button class="btn-sm download-btn">⬇ Скачать</button>
        </div>
    `;

    wrap.querySelector('.view-btn').addEventListener('click', () => openFileModal(filePacket));
    wrap.querySelector('.download-btn').addEventListener('click', () => {
        downloadFile(filePacket.data, filePacket.mimeType, filePacket.name);
    });

    box.appendChild(wrap);
    box.scrollTop = box.scrollHeight;
}

// -------- UI helpers --------
function addLog({ level, message, ts, data }) {
    const el = document.createElement('div');
    el.className = `log-entry ${level}`;
    const time = new Date(ts).toLocaleTimeString();
    el.innerHTML = `<span class="ts">${time}</span>${escapeHtml(message)}`;
    if (data && Object.keys(data).length) {
        el.innerHTML += ` <span class="muted">${escapeHtml(JSON.stringify(data))}</span>`;
    }
    const log = document.getElementById('log');
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
}

function addMessage(kind, text, meta) {
    const m = document.createElement('div');
    m.className = `message ${kind}`;
    m.innerHTML = `${escapeHtml(text)}<div class="meta">${escapeHtml(meta)}</div>`;
    const box = document.getElementById('messages');
    box.appendChild(m);
    box.scrollTop = box.scrollHeight;
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}
