/**
 * static_server.js — простейший http-сервер для клиентских файлов.
 * Нужен потому что ES modules не загружаются через file://.
 *
 * Запуск: node static_server.js
 * Откроется: http://localhost:3000
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
const ROOT = path.join(__dirname, '..', 'client');

const TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js':   'application/javascript; charset=utf-8',
    '.css':  'text/css; charset=utf-8',
    '.json': 'application/json'
};

http.createServer((req, res) => {
    let url = req.url.split('?')[0];
    if (url === '/') url = '/index.html';
    const filePath = path.join(ROOT, url);

    if (!filePath.startsWith(ROOT)) {
        res.writeHead(403); res.end('forbidden'); return;
    }

    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404); res.end('not found'); return;
        }
        const ext = path.extname(filePath);
        res.writeHead(200, { 'Content-Type': TYPES[ext] || 'application/octet-stream' });
        res.end(data);
    });
}).listen(PORT, () => {
    console.log(`[STATIC] Client served at http://localhost:${PORT}`);
});
