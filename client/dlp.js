/**
 * dlp.js — Data Loss Prevention
 * -----------------------------
 * Работает на стороне отправителя ДО шифрования: проверяет
 * содержимое сообщения по regex-правилам, и если правило с действием
 * "block" сработало — сообщение НЕ уходит в канал.
 *
 * Это правильное место для DLP в архитектуре:
 *  - после шифрования содержимое уже не видно (даже своему шлюзу)
 *  - на стороне получателя блокировать поздно — данные уже утекли
 */

// Базовые правила «из коробки» — то, что в реальности составляют комплаенс-офицеры.
// Админ в UI может добавить свои.
export const DEFAULT_RULES = [
    {
        id: 'iin_kz',
        name: 'ИИН (Казахстан)',
        regex: '\\b\\d{12}\\b',
        action: 'block'
    },
    {
        id: 'card_number',
        name: 'Номер банковской карты',
        regex: '\\b(?:\\d[ -]*?){13,19}\\b',
        action: 'block'
    },
    {
        id: 'password_keyword',
        name: 'Слово «пароль»',
        regex: 'парол[ьяею]|password',
        action: 'warning'
    },
    {
        id: 'secret_keyword',
        name: 'Слово «секрет»',
        regex: 'секрет(но)?|confidential|секретно',
        action: 'warning'
    },
    {
        id: 'email_addr',
        name: 'Email-адрес',
        regex: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}',
        action: 'warning'
    }
];

/**
 * Проверка текста по правилам.
 * Возвращает { status: 'allow' | 'warning' | 'block', matches: [...] }
 */
export function inspect(text, rules) {
    const matches = [];
    let status = 'allow';

    for (const rule of rules) {
        let re;
        try {
            re = new RegExp(rule.regex, 'gi');
        } catch {
            continue; // битый regex пропускаем
        }

        const found = text.match(re);
        if (found && found.length) {
            matches.push({
                ruleId: rule.id,
                ruleName: rule.name,
                action: rule.action,
                samples: found.slice(0, 3)
            });

            if (rule.action === 'block') status = 'block';
            else if (rule.action === 'warning' && status !== 'block') status = 'warning';
        }
    }

    return { status, matches };
}

/**
 * Подсветка совпадений в тексте — для UI.
 */
export function highlight(text, rules) {
    let html = escapeHtml(text);
    for (const rule of rules) {
        let re;
        try {
            re = new RegExp(rule.regex, 'gi');
        } catch {
            continue;
        }
        const cls = rule.action === 'block' ? 'dlp-block' : 'dlp-warn';
        html = html.replace(re, m => `<span class="${cls}" title="${escapeHtml(rule.name)}">${m}</span>`);
    }
    return html;
}

function escapeHtml(s) {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
