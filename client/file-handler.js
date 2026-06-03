/**
 * file-handler.js — модуль работы с файлами
 * ------------------------------------------
 * Отвечает за:
 *  1. Загрузку файлов (PDF, Word, Excel, изображения, текст)
 *  2. Просмотр файлов прямо в браузере (без сторонних серверов)
 *  3. DLP-проверку содержимого файлов ДО шифрования
 *  4. Сериализацию файла в base64 для передачи через зашифрованный канал
 *  5. Получение и скачивание файла на стороне получателя
 */

import { inspect } from './dlp.js';

// ---------- Допустимые типы файлов ----------
export const ALLOWED_TYPES = {
    'application/pdf': { ext: 'pdf', label: 'PDF', viewer: 'pdf' },
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': { ext: 'docx', label: 'Word', viewer: 'office' },
    'application/msword': { ext: 'doc', label: 'Word (DOC)', viewer: 'office' },
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': { ext: 'xlsx', label: 'Excel', viewer: 'office' },
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': { ext: 'pptx', label: 'PowerPoint', viewer: 'office' },
    'text/plain': { ext: 'txt', label: 'Текст', viewer: 'text' },
    'text/csv': { ext: 'csv', label: 'CSV', viewer: 'text' },
    'image/png': { ext: 'png', label: 'PNG', viewer: 'image' },
    'image/jpeg': { ext: 'jpg', label: 'JPEG', viewer: 'image' },
    'image/gif': { ext: 'gif', label: 'GIF', viewer: 'image' },
    'image/webp': { ext: 'webp', label: 'WebP', viewer: 'image' },
};

export const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 МБ

/**
 * Читает файл в base64.
 */
export function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            // reader.result = "data:mime;base64,XXXX"
            const b64 = reader.result.split(',')[1];
            resolve(b64);
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}

/**
 * Читает файл как текст (для DLP-проверки).
 */
export function fileToText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        // Для бинарных файлов вернём пустую строку — DLP по имени файла
        if (file.type.startsWith('text/')) {
            reader.readAsText(file);
        } else {
            resolve(file.name); // DLP проверит хотя бы имя файла
        }
    });
}

/**
 * Конвертирует base64 обратно в Blob для скачивания.
 */
export function base64ToBlob(b64, mimeType) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new Blob([bytes], { type: mimeType });
}

/**
 * Скачивает файл через временную ссылку.
 */
export function downloadFile(b64, mimeType, fileName) {
    const blob = base64ToBlob(b64, mimeType);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
}

/**
 * Открывает файл для просмотра во встроенном вьюере.
 * Возвращает HTML-строку для отображения.
 */
export function buildFilePreview(b64, mimeType, fileName) {
    const info = ALLOWED_TYPES[mimeType];
    const viewer = info ? info.viewer : 'unknown';

    switch (viewer) {
        case 'pdf': {
            // PDF — встроенный <embed>
            const blob = base64ToBlob(b64, mimeType);
            const url = URL.createObjectURL(blob);
            return {
                type: 'pdf',
                url,
                html: `<embed src="${url}" type="application/pdf" width="100%" height="500px" style="border-radius:6px;border:1px solid var(--border);" />`
            };
        }
        case 'image': {
            return {
                type: 'image',
                html: `<img src="data:${mimeType};base64,${b64}" alt="${escHtml(fileName)}"
                     style="max-width:100%;max-height:400px;border-radius:6px;display:block;margin:0 auto;" />`
            };
        }
        case 'text': {
            const text = atob(b64);
            return {
                type: 'text',
                html: `<pre style="max-height:300px;overflow:auto;background:var(--bg);padding:10px;border-radius:6px;font-size:12px;color:var(--text);white-space:pre-wrap;">${escHtml(text)}</pre>`
            };
        }
        case 'office': {
            // Office-файлы — показываем через Microsoft Office Online viewer (iframe)
            // Но так как файл локальный — предлагаем скачать и открыть
            return {
                type: 'office',
                html: `<div style="padding:20px;text-align:center;background:var(--bg);border-radius:6px;">
                    <div style="font-size:32px;margin-bottom:12px;">${getFileIcon(mimeType)}</div>
                    <div style="color:var(--text);margin-bottom:8px;font-weight:bold;">${escHtml(fileName)}</div>
                    <div class="muted" style="margin-bottom:16px;">Предварительный просмотр Office-файлов доступен после скачивания</div>
                    <button class="secondary" onclick="this.closest('.file-preview-inner').dispatchEvent(new CustomEvent('download-preview', {bubbles:true}))">
                        ⬇ Скачать и открыть
                    </button>
                </div>`
            };
        }
        default:
            return {
                type: 'unknown',
                html: `<div style="padding:20px;text-align:center;color:var(--muted);">
                    Просмотр файла типа «${escHtml(mimeType)}» не поддерживается.
                </div>`
            };
    }
}

/**
 * DLP-проверка файла. Читает текстовое содержимое (если возможно).
 */
export async function inspectFile(file, rules) {
    const text = await fileToText(file);
    return inspect(text, rules);
}

/**
 * Иконка для типа файла.
 */
export function getFileIcon(mimeType) {
    if (!mimeType) return '📎';
    if (mimeType === 'application/pdf') return '📄';
    if (mimeType.includes('word')) return '📝';
    if (mimeType.includes('sheet') || mimeType.includes('excel') || mimeType === 'text/csv') return '📊';
    if (mimeType.includes('presentation')) return '📑';
    if (mimeType.startsWith('image/')) return '🖼️';
    if (mimeType.startsWith('text/')) return '📃';
    return '📎';
}

/**
 * Форматирование размера файла.
 */
export function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} Б`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`;
}

function escHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
