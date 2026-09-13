/**
 * GALPÃO — servidor
 * -------------------------------------------------
 * Um único arquivo, sem dependências externas (só usa o que já vem
 * de fábrica no Node.js): http, fs, crypto, https, url.
 *
 * O que ele faz:
 *  1. Guarda os dados (usuários, produtos, pedidos) num arquivo db.json
 *     — isso É o "banco de dados" nesta versão MVP.
 *  2. Cadastro/login de usuários com senha criptografada.
 *  3. Cada usuário só vê os próprios produtos e pedidos.
 *  4. Conexão com o Mercado Livre via OAuth (login oficial deles).
 *
 * Para rodar:
 *   node server.js
 * Depois abra: http://localhost:3000
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');

// Credenciais do app no Mercado Livre (você cria o seu em
// https://developers.mercadolivre.com.br/devcenter). Sem isso preenchido,
// tudo funciona normalmente — só o botão "Conectar Mercado Livre" não vai.
const ML_CLIENT_ID = process.env.ML_CLIENT_ID || '';
const ML_CLIENT_SECRET = process.env.ML_CLIENT_SECRET || '';
const ML_REDIRECT_URI = process.env.ML_REDIRECT_URI || `http://localhost:${PORT}/api/ml/callback`;

// ---------------------------------------------------------------
// "Banco de dados" em arquivo — simples de entender, fácil de trocar
// depois por Postgres/MySQL sem mudar o resto do código.
// ---------------------------------------------------------------
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const seed = { users: [], produtos: [], pedidos: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(seed, null, 2));
    return seed;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Sessões ficam na memória do servidor (token -> userId).
// Simples de propósito: se o servidor reiniciar, todo mundo precisa
// logar de novo. Numa versão maior, isso também viraria parte do banco.
const sessions = new Map();

function newId(prefix) {
  return prefix + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

// ---------------------------------------------------------------
// Senhas: nunca guardamos a senha em texto puro. Guardamos um "hash"
// (uma mistura sem volta) feito com um tempero aleatório (salt).
// ---------------------------------------------------------------
function hashPassword(senha, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(senha, salt, 64).toString('hex');
  return { salt, hash };
}
function checkPassword(senha, salt, hash) {
  const tentativa = crypto.scryptSync(senha, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(tentativa), Buffer.from(hash));
}

// ---------------------------------------------------------------
// Helpers HTTP
// ---------------------------------------------------------------
function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => (data += chunk));
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}
function getUser(req, db) {
  const token = req.headers['authorization'];
  if (!token) return null;
  const userId = sessions.get(token);
  if (!userId) return null;
  return db.users.find(u => u.id === userId) || null;
}
function httpsPostForm(hostname, pathName, formObj) {
  return new Promise((resolve, reject) => {
    const body = Object.entries(formObj)
      .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v))
      .join('&');
    const req = https.request(
      { hostname, path: pathName, method: 'POST', headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'Accept': 'application/json',
      }},
      res => {
        let data = '';
        res.on('data', c => (data += c));
        res.on('end', () => {
          try { resolve({ status: res.statusCode, json: JSON.parse(data) }); }
          catch (e) { resolve({ status: res.statusCode, json: null }); }
        });
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
function httpsGet(hostname, pathName, accessToken) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname, path: pathName, method: 'GET', headers: { Authorization: `Bearer ${accessToken}` } },
      res => {
        let data = '';
        res.on('data', c => (data += c));
        res.on('end', () => {
          try { resolve({ status: res.statusCode, json: JSON.parse(data) }); }
          catch (e) { resolve({ status: res.statusCode, json: null }); }
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

// ---------------------------------------------------------------
// Servidor
// ---------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const db = loadDB();
  const parsed = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsed.pathname;

  try {
    // ---------- CADASTRO ----------
    if (pathname === '/api/signup' && req.method === 'POST') {
      const { email, senha } = await readBody(req);
      if (!email || !senha) return sendJSON(res, 400, { erro: 'Preencha email e senha.' });
      if (db.users.find(u => u.email === email)) return sendJSON(res, 400, { erro: 'Esse email já tem cadastro.' });
      const { salt, hash } = hashPassword(senha);
      const user = { id: newId('u'), email, salt, hash, ml: null };
      db.users.push(user);
      saveDB(db);
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, user.id);
      return sendJSON(res, 200, { token, email });
    }

    // ---------- LOGIN ----------
    if (pathname === '/api/login' && req.method === 'POST') {
      const { email, senha } = await readBody(req);
      const user = db.users.find(u => u.email === email);
      if (!user || !checkPassword(senha, user.salt, user.hash)) {
        return sendJSON(res, 401, { erro: 'Email ou senha incorretos.' });
      }
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, user.id);
      return sendJSON(res, 200, { token, email });
    }

    // A partir daqui, todas as rotas exigem estar logado
    if (pathname.startsWith('/api/')) {
      const user = getUser(req, db);
      if (!user) return sendJSON(res, 401, { erro: 'Faça login primeiro.' });

      // ---------- PRODUTOS ----------
      if (pathname === '/api/produtos' && req.method === 'GET') {
        return sendJSON(res, 200, db.produtos.filter(p => p.userId === user.id));
      }
      if (pathname === '/api/produtos' && req.method === 'POST') {
        const body = await readBody(req);
        const produto = { id: newId('p'), userId: user.id, ...body };
        db.produtos.push(produto);
        saveDB(db);
        return sendJSON(res, 200, produto);
      }
      const produtoMatch = pathname.match(/^\/api\/produtos\/(.+)$/);
      if (produtoMatch && (req.method === 'PUT' || req.method === 'DELETE')) {
        const id = produtoMatch[1];
        const idx = db.produtos.findIndex(p => p.id === id && p.userId === user.id);
        if (idx === -1) return sendJSON(res, 404, { erro: 'Produto não encontrado.' });
        if (req.method === 'DELETE') {
          db.produtos.splice(idx, 1);
          saveDB(db);
          return sendJSON(res, 200, { ok: true });
        }
        const body = await readBody(req);
        db.produtos[idx] = { ...db.produtos[idx], ...body };
        saveDB(db);
        return sendJSON(res, 200, db.produtos[idx]);
      }

      // ---------- PEDIDOS ----------
      if (pathname === '/api/pedidos' && req.method === 'GET') {
        return sendJSON(res, 200, db.pedidos.filter(p => p.userId === user.id));
      }
      if (pathname === '/api/pedidos' && req.method === 'POST') {
        const body = await readBody(req);
        const pedido = { id: newId('o'), userId: user.id, ...body };
        db.pedidos.push(pedido);
        saveDB(db);
        return sendJSON(res, 200, pedido);
      }
      const pedidoMatch = pathname.match(/^\/api\/pedidos\/(.+)$/);
      if (pedidoMatch && (req.method === 'PUT' || req.method === 'DELETE')) {
        const id = pedidoMatch[1];
        const idx = db.pedidos.findIndex(p => p.id === id && p.userId === user.id);
        if (idx === -1) return sendJSON(res, 404, { erro: 'Pedido não encontrado.' });
        if (req.method === 'DELETE') {
          db.pedidos.splice(idx, 1);
          saveDB(db);
          return sendJSON(res, 200, { ok: true });
        }
        const body = await readBody(req);
        db.pedidos[idx] = { ...db.pedidos[idx], ...body };
        saveDB(db);
        return sendJSON(res, 200, db.pedidos[idx]);
      }

      // ---------- MERCADO LIVRE: status ----------
      if (pathname === '/api/ml/status' && req.method === 'GET') {
        return sendJSON(res, 200, { conectado: !!(user.ml && user.ml.accessToken) });
      }

      // ---------- MERCADO LIVRE: iniciar conexão ----------
      if (pathname === '/api/ml/connect' && req.method === 'GET') {
        if (!ML_CLIENT_ID) return sendJSON(res, 400, { erro: 'ML_CLIENT_ID não configurado no servidor.' });
        const token = req.headers['authorization'];
        const authUrl = `https://auth.mercadolivre.com.br/authorization?response_type=code&client_id=${ML_CLIENT_ID}&redirect_uri=${encodeURIComponent(ML_REDIRECT_URI)}&state=${token}`;
        return sendJSON(res, 200, { url: authUrl });
      }

      // ---------- MERCADO LIVRE: buscar pedidos reais (exemplo simples) ----------
      if (pathname === '/api/ml/sync' && req.method === 'POST') {
        if (!user.ml || !user.ml.accessToken) return sendJSON(res, 400, { erro: 'Conecte sua conta do Mercado Livre primeiro.' });
        const me = await httpsGet('api.mercadolibre.com', '/users/me', user.ml.accessToken);
        if (me.status !== 200) return sendJSON(res, 400, { erro: 'Não foi possível falar com o Mercado Livre.' });
        const orders = await httpsGet('api.mercadolibre.com', `/orders/search?seller=${me.json.id}`, user.ml.accessToken);
        return sendJSON(res, 200, { usuario_ml: me.json.nickname, pedidos_encontrados: orders.json && orders.json.results ? orders.json.results.length : 0 });
      }

      return sendJSON(res, 404, { erro: 'Rota não encontrada.' });
    }

    // ---------- MERCADO LIVRE: callback do OAuth (o ML chama essa URL) ----------
    if (pathname === '/api/ml/callback' && req.method === 'GET') {
      const code = parsed.searchParams.get('code');
      const token = parsed.searchParams.get('state');
      const userId = sessions.get(token);
      const user = db.users.find(u => u.id === userId);
      if (!code || !user) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end('<p>Não foi possível conectar. Volte ao Galpão e tente de novo.</p>');
      }
      const tokenResp = await httpsPostForm('api.mercadolibre.com', '/oauth/token', {
        grant_type: 'authorization_code',
        client_id: ML_CLIENT_ID,
        client_secret: ML_CLIENT_SECRET,
        code,
        redirect_uri: ML_REDIRECT_URI,
      });
      if (tokenResp.status === 200 && tokenResp.json && tokenResp.json.access_token) {
        user.ml = {
          accessToken: tokenResp.json.access_token,
          refreshToken: tokenResp.json.refresh_token,
          mlUserId: tokenResp.json.user_id,
        };
        saveDB(db);
        res.writeHead(302, { Location: '/?ml=conectado' });
        return res.end();
      }
      res.writeHead(302, { Location: '/?ml=erro' });
      return res.end();
    }

    // ---------- ARQUIVOS DO SITE (frontend) ----------
    let filePath = pathname === '/' ? '/index.html' : pathname;
    filePath = path.join(__dirname, 'public', filePath);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath);
      const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' };
      res.writeHead(200, { 'Content-Type': (types[ext] || 'text/plain') + '; charset=utf-8' });
      return fs.createReadStream(filePath).pipe(res);
    }

    sendJSON(res, 404, { erro: 'Não encontrado.' });
  } catch (e) {
    console.error(e);
    sendJSON(res, 500, { erro: 'Erro interno no servidor.' });
  }
});

server.listen(PORT, () => {
  console.log(`Galpão rodando em http://localhost:${PORT}`);
});
