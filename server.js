// Stored XSS lab: one app, two modes.
//   /vulnerable -> renders stored comments WITHOUT encoding   (flaw)
//   /secure     -> renders stored comments WITH HTML encoding (fix)
// Run on localhost only.
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const DB_FILE = path.join(__dirname, 'db.json');

app.use(express.urlencoded({ extended: false }));

// ---------- tiny persistent store (comments survive restarts = "stored") ----------
function loadDb() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { vulnerable: [], secure: [] }; }
}
function saveDb(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
const db = loadDb();

// ---------- users + sessions ----------
const USERS = {
  alice: { password: 'alice123', role: 'user' },   // attacker
  admin: { password: 'admin123', role: 'admin' },  // victim
};
const sessions = {}; // token -> username

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function currentUser(req) {
  const sid = parseCookies(req).sid;
  return sid ? sessions[sid] : undefined;
}

// ---------- output encoding (THE FIX) ----------
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---------- pages ----------
function layout(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:740px;margin:2rem auto;padding:0 1rem;background:#f5f7fa;color:#222}
  nav{background:#1e1e2e;color:#fff;padding:.6rem 1rem;border-radius:8px;margin-bottom:1.5rem;font-size:.9rem}
  nav a{color:#a9b1d6;text-decoration:none;margin:0 .4rem}
  nav a:hover{color:#fff}
  h2{margin-top:0}
  .c{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:.6rem 1rem;margin:.5rem 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}
  .badge{padding:3px 10px;border-radius:12px;color:#fff;font-size:.78rem;font-weight:600;letter-spacing:.03em}
  .v{background:#e53e3e}.s{background:#38a169}
  form{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:1rem;margin-bottom:1rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}
  textarea{width:100%;height:80px;border:1px solid #ccc;border-radius:6px;padding:.4rem;font-size:.95rem;resize:vertical;box-sizing:border-box}
  button{margin-top:.5rem;padding:.4rem 1.2rem;background:#3b82f6;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:.95rem}
  button:hover{background:#2563eb}
  code{background:#eee;padding:1px 5px;border-radius:4px}
  .del{margin-top:0;padding:2px 7px;background:#e53e3e;font-size:.8rem;float:right}
  .del:hover{background:#c0392b}
  .video-wrap{background:#000;border-radius:10px;overflow:hidden;margin-bottom:1.2rem}
  .video-wrap video{width:100%;display:block;max-height:380px}
  .video-info{padding:.7rem 0 .2rem;font-size:.95rem;color:#444}
  .video-info b{font-size:1.05rem;color:#111}
</style></head><body>${body}</body></html>`;
}

app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  res.send(layout('Login', `
    <h2>🔐 XSS Lab — Login</h2>
    <form method="POST" action="/login">
      <p><input name="username" placeholder="username" required style="width:100%;padding:.4rem;border:1px solid #ccc;border-radius:6px;font-size:.95rem;box-sizing:border-box"></p>
      <p><input name="password" type="password" placeholder="password" required style="width:100%;padding:.4rem;border:1px solid #ccc;border-radius:6px;font-size:.95rem;box-sizing:border-box"></p>
      <button>Login</button>
    </form>
    <p>Demo users: <code>alice / alice123</code> (attacker) &nbsp;|&nbsp; <code>admin / admin123</code> (victim)</p>`));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const u = USERS[username];
  if (!u || u.password !== password) return res.status(401).send(layout('Login', '<p>Invalid credentials. <a href="/login">Back</a></p>'));
  const token = crypto.randomBytes(16).toString('hex');
  sessions[token] = username;
  // NOTE: deliberately NOT HttpOnly so document.cookie can read it (impact demo).
  // The same cookie is used in both modes, so ONLY output encoding differs.
  res.setHeader('Set-Cookie', `sid=${token}; Path=/`);
  res.redirect('/vulnerable');
});

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0');
  res.redirect('/login');
});

// ---------- the two modes ----------
function board(mode) {
  const isVuln = mode === 'vulnerable';

  app.get(`/${mode}`, (req, res) => {
    const user = currentUser(req);
    if (!user) return res.redirect('/login');

    const items = db[mode].map((c, i) => {
      // ============================================================
      // (a) VULNERABLE: stored text is inserted into HTML unencoded.
      // (d) SECURE:     stored text is HTML-encoded on output.
      // ============================================================
      const text = isVuln ? c.text : escapeHtml(c.text);
      const author = escapeHtml(c.author);
      // show delete button only to the comment's own author or admin
      const canDelete = (user === c.author || user === 'admin');
      const deleteBtn = canDelete
        ? `<form method="POST" action="/${mode}/delete" style="display:inline;margin:0;padding:0;background:none;border:none;box-shadow:none">
             <input type="hidden" name="index" value="${i}">
             <button class="del">🗑</button>
           </form>`
        : '';
      return `<div class="c"><b>${author}</b>: ${text} ${deleteBtn}</div>`;
    }).join('') || '<p><i>No comments yet.</i></p>';

    res.send(layout(`Guestbook (${mode})`, `
      <nav>
        <span class="badge ${isVuln ? 'v' : 's'}">${mode.toUpperCase()}</span>
        &nbsp;Logged in as <b>${escapeHtml(user)}</b>
        &nbsp;|&nbsp;<a href="/vulnerable">vulnerable</a>
        &nbsp;|&nbsp;<a href="/secure">secure</a>
        &nbsp;|&nbsp;<a href="/logout">logout</a>
      </nav>
      <!-- video player above comments, like a YouTube-style page -->
      <div class="video-wrap">
        <video controls>
          <source src="https://www.w3schools.com/html/mov_bbb.mp4" type="video/mp4">
          Your browser does not support the video tag.
        </video>
      </div>
      <div class="video-info">
        <b>Big Buck Bunny — Sample Video</b><br>
        <span>1,234,567 views &nbsp;&bull;&nbsp; Posted by <i>Blender Foundation</i></span>
      </div>
      <h2>💬 Comments</h2>
      <form method="POST" action="/${mode}/comment">
        <textarea name="text" placeholder="Write a comment..." required></textarea><br>
        <button>Post Comment</button>
      </form>
      ${items}`));
  });

  app.post(`/${mode}/comment`, (req, res) => {
    const user = currentUser(req);
    if (!user) return res.redirect('/login');
    // Input is stored raw in BOTH modes on purpose: the fix belongs at OUTPUT.
    db[mode].push({ author: user, text: req.body.text || '' });
    saveDb(db);
    res.redirect(`/${mode}`);
  });

  // delete a comment by index (only author or admin can delete)
  app.post(`/${mode}/delete`, (req, res) => {
    const user = currentUser(req);
    if (!user) return res.redirect('/login');
    const index = parseInt(req.body.index, 10);
    const comment = db[mode][index];
    if (comment && (user === comment.author || user === 'admin')) {
      db[mode].splice(index, 1); // remove 1 item at that index
      saveDb(db);
    }
    res.redirect(`/${mode}`);
  });
}
board('vulnerable');
board('secure');

// helper to wipe comments between demo takes
app.get('/reset', (req, res) => {
  db.vulnerable = []; db.secure = []; saveDb(db);
  res.redirect('/vulnerable');
});

app.listen(PORT, '127.0.0.1', () => console.log(`Lab running at http://localhost:${PORT}`));
