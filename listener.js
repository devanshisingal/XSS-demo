// Attacker's listener: logs anything sent to it (e.g., a stolen cookie).
const http = require('http');
http.createServer((req, res) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${decodeURIComponent(req.url)}`);
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('ok');
}).listen(9000, '127.0.0.1', () => console.log('Attacker listener on http://localhost:9000'));
