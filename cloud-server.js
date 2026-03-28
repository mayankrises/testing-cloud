/**
 * CivicGuard — Cloud Server (Community Approval Edition)
 *
 * Changes vs previous version:
 *   - /api/close REMOVED — closure is now community-only (auto via approval threshold)
 *   - POST /api/resolve still works → status = UNDER_APPROVAL (authority marks resolved)
 *   - issue_vote_update broadcast added (passthrough from local servers)
 *   - issue_closed broadcast added (triggered by community threshold, relayed from local)
 *   - approvals_count / rejections_count / total_votes / approval_percentage stored & returned
 *   - All existing behaviour (new_issue WS, /api/stats, keepalive, auth) unchanged
 *
 * Install:   npm install ws better-sqlite3
 * Run:       node cloud-server.js
 */

'use strict';

const WebSocket  = require('ws');
const http       = require('http');
const https      = require('https');
const fs         = require('fs');
const path       = require('path');
const Database   = require('better-sqlite3');

const PORT    = process.env.PORT || 8080;
const DB_PATH = path.join(__dirname, 'civicguard-cloud.db');

// ─── DATABASE ─────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    email      TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    role       TEXT    NOT NULL DEFAULT 'AUTHORITY',
    department TEXT    NOT NULL DEFAULT 'AUTHORITY',
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

  CREATE TABLE IF NOT EXISTS issues (
    id                  TEXT    PRIMARY KEY,
    title               TEXT    NOT NULL,
    description         TEXT    NOT NULL DEFAULT '',
    category            TEXT    NOT NULL DEFAULT 'OTHER',
    images              TEXT    NOT NULL DEFAULT '[]',
    geo_lat             REAL,
    geo_lng             REAL,
    region              TEXT    NOT NULL DEFAULT 'Unknown',
    room                TEXT    NOT NULL DEFAULT '',
    user_name           TEXT    NOT NULL DEFAULT 'Unknown',
    status              TEXT    NOT NULL DEFAULT 'OPEN',
    resolution_note     TEXT    DEFAULT '',
    resolution_images   TEXT    DEFAULT '[]',
    approvals_count     INTEGER NOT NULL DEFAULT 0,
    rejections_count    INTEGER NOT NULL DEFAULT 0,
    total_votes         INTEGER NOT NULL DEFAULT 0,
    approval_percentage REAL    NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_cloud_status     ON issues(status);
  CREATE INDEX IF NOT EXISTS idx_cloud_region     ON issues(region);
  CREATE INDEX IF NOT EXISTS idx_cloud_created_at ON issues(created_at DESC);
`);

// ─── SCHEMA MIGRATION ─────────────────────────────────────────────────────────
(function migrateSchema() {
  const cols = db.pragma('table_info(issues)').map(c => c.name);
  const migrations = [
    ['resolution_note',     "ALTER TABLE issues ADD COLUMN resolution_note TEXT DEFAULT ''"],
    ['resolution_images',   "ALTER TABLE issues ADD COLUMN resolution_images TEXT DEFAULT '[]'"],
    ['approvals_count',     'ALTER TABLE issues ADD COLUMN approvals_count INTEGER NOT NULL DEFAULT 0'],
    ['rejections_count',    'ALTER TABLE issues ADD COLUMN rejections_count INTEGER NOT NULL DEFAULT 0'],
    ['total_votes',         'ALTER TABLE issues ADD COLUMN total_votes INTEGER NOT NULL DEFAULT 0'],
    ['approval_percentage', 'ALTER TABLE issues ADD COLUMN approval_percentage REAL NOT NULL DEFAULT 0'],
  ];
  for (const [col, sql] of migrations) {
    if (!cols.includes(col)) {
      db.exec(sql);
      console.log(`[db-migrate] added column '${col}' to issues`);
    }
  }
})();

const stmts = {
  upsertIssue: db.prepare(`
    INSERT INTO issues
      (id, title, description, category, images, geo_lat, geo_lng, region,
       room, user_name, status, created_at, updated_at)
    VALUES
      (@id,@title,@description,@category,@images,@geo_lat,@geo_lng,@region,
       @room,@user_name,@status,@created_at,@updated_at)
    ON CONFLICT(id) DO UPDATE SET
      title       = excluded.title,
      description = excluded.description,
      updated_at  = excluded.updated_at
  `),

  resolveIssue: db.prepare(`
    UPDATE issues
    SET status='UNDER_APPROVAL', resolution_note=@note,
        resolution_images=@images, updated_at=@ts
    WHERE id=@id AND status='OPEN'
  `),

  // Closure is triggered by community vote threshold — not by authority directly
  autoCloseIssue: db.prepare(`
    UPDATE issues SET status='CLOSED', updated_at=@ts WHERE id=@id AND status='UNDER_APPROVAL'
  `),

  updateVoteCounts: db.prepare(`
    UPDATE issues
    SET approvals_count=@approvals_count,
        rejections_count=@rejections_count,
        total_votes=@total_votes,
        approval_percentage=@approval_percentage,
        updated_at=@ts
    WHERE id=@id
  `),

  getByStatus: db.prepare(
    `SELECT * FROM issues WHERE status=? ORDER BY created_at DESC LIMIT 200`
  ),
  getAll: db.prepare(
    `SELECT * FROM issues ORDER BY created_at DESC LIMIT 500`
  ),
  getById: db.prepare(`SELECT * FROM issues WHERE id=?`),
};

const authStmts = {
  createUser:    db.prepare(`INSERT INTO users (name, email, password, role, department, created_at) VALUES (@name, @email, @password, 'AUTHORITY', @department, @created_at)`),
  getUserByEmail: db.prepare(`SELECT * FROM users WHERE email=?`),
  getUserById:    db.prepare(`SELECT * FROM users WHERE id=?`),
};

// Simple in-memory token store
const tokenStore = new Map();
const crypto     = require('crypto');
function generateToken()   { return crypto.randomBytes(32).toString('hex'); }
function hashPassword(pw)  { return crypto.createHash('sha256').update('cg_salt_' + pw).digest('hex'); }

const regionCache = {};
function deriveRegion(lat, lng) {
  return new Promise(resolve => {
    if (!lat || !lng) { resolve('Unknown'); return; }
    const key = `${Number(lat).toFixed(3)}_${Number(lng).toFixed(3)}`;
    if (regionCache[key]) { resolve(regionCache[key]); return; }
    const url = `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lng}&format=json`;
    https.get(url, {headers:{'User-Agent':'CivicGuard/1.0'}}, r => {
      let body = '';
      r.on('data', c => body += c);
      r.on('end', () => {
        try {
          const j = JSON.parse(body);
          const a = j.address || {};
          const parts = [a.suburb||a.neighbourhood||a.quarter||a.village, a.city||a.town||a.county||a.state_district].filter(Boolean);
          const region = parts.length ? parts.join(', ') : (j.display_name||'Unknown').split(',')[0].trim();
          regionCache[key] = region; resolve(region);
        } catch { resolve('Unknown'); }
      });
    }).on('error', () => resolve('Unknown'));
  });
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
    req.on('error', reject);
  });
}
function jres(res, status, data) {
  res.writeHead(status, {'Content-Type':'application/json'});
  res.end(JSON.stringify(data));
}
function serveFile(res, filename) {
  const fp = path.join(__dirname, filename);
  if (!fs.existsSync(fp)) { res.writeHead(404); res.end(filename+' not found'); return; }
  res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
  res.end(fs.readFileSync(fp));
}
function parseIssueRow(r) {
  return r ? {
    ...r,
    images:            JSON.parse(r.images            || '[]'),
    resolution_images: JSON.parse(r.resolution_images || '[]'),
  } : null;
}

// ─── HTTP SERVER ──────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
  const url      = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // Auth
  if (pathname === '/api/auth/signup' && req.method === 'POST') {
    const body = await readBody(req);
    const {name,email,password,authority_code} = body;
    if (!name||!email||!password||!authority_code) { jres(res,400,{error:'All fields required'}); return; }
    const VALID_CODES = (process.env.AUTHORITY_CODES||'AUTH-DEMO-2024').split(',').map(s=>s.trim().toUpperCase());
    if (!VALID_CODES.includes(authority_code.toUpperCase())) { jres(res,403,{error:'Invalid authority invite code'}); return; }
    try {
      const result = authStmts.createUser.run({name:String(name).slice(0,100),email:String(email).toLowerCase().trim(),password:hashPassword(String(password)),department:'AUTHORITY',created_at:Date.now()});
      const user   = authStmts.getUserById.get(Number(result.lastInsertRowid));
      const token  = generateToken();
      tokenStore.set(token, Number(user.id));
      jres(res,201,{token,user:{id:user.id,name:user.name,email:user.email,role:user.role,department:user.department}});
    } catch(e) {
      if (e.message&&e.message.includes('UNIQUE')) jres(res,409,{error:'Email already registered'});
      else jres(res,500,{error:'Signup failed'});
    }
    return;
  }

  if (pathname === '/api/auth/login' && req.method === 'POST') {
    const body = await readBody(req);
    const {email,password} = body;
    if (!email||!password) { jres(res,400,{error:'Email and password required'}); return; }
    const user = authStmts.getUserByEmail.get(String(email).toLowerCase().trim());
    if (!user||user.password!==hashPassword(String(password))) { jres(res,401,{error:'Invalid email or password'}); return; }
    const token = generateToken();
    tokenStore.set(token, Number(user.id));
    jres(res,200,{token,user:{id:user.id,name:user.name,email:user.email,role:user.role,department:user.department}});
    return;
  }

  if (pathname === '/api/auth/me' && req.method === 'GET') {
    const authHeader = req.headers.authorization || '';
    const token  = authHeader.replace('Bearer ','').trim();
    const userId = tokenStore.get(token);
    if (!userId) { jres(res,401,{error:'Unauthorized'}); return; }
    const user = authStmts.getUserById.get(userId);
    if (!user)  { jres(res,401,{error:'User not found'}); return; }
    jres(res,200,{id:user.id,name:user.name,email:user.email,role:user.role,department:user.department});
    return;
  }

  // Health
  if (pathname==='/healthz'||pathname==='/health') { res.writeHead(200,{'Content-Type':'text/plain'}); res.end('ok'); return; }

  // Pages
  if (pathname==='/'||pathname==='/index.html')       { serveFile(res,'cloud-dashboard.html'); return; }
  if (pathname==='/authority'||pathname==='/authority.html') { serveFile(res,'authority.html'); return; }

  // ── GET /api/issues ──
  if (pathname==='/api/issues' && req.method==='GET') {
    const status   = url.searchParams.get('status');
    const category = url.searchParams.get('category');
    const region   = url.searchParams.get('region');
    let rows = status ? stmts.getByStatus.all(status) : stmts.getAll.all();
    if (category) rows = rows.filter(r=>r.category===category);
    if (region)   rows = rows.filter(r=>r.region.toLowerCase().includes(region.toLowerCase()));
    jres(res,200,{issues:rows.map(parseIssueRow),total:rows.length});
    return;
  }

  // ── POST /api/issues ──
  if (pathname==='/api/issues' && req.method==='POST') {
    const body = await readBody(req);
    if (!body.id||!body.title) { jres(res,400,{error:'id and title required'}); return; }
    const region = await deriveRegion(body.geo_lat,body.geo_lng);
    const now    = Date.now();
    const row    = {
      id:String(body.id), title:String(body.title).slice(0,120),
      description:String(body.description||'').slice(0,500),
      category:body.category||'OTHER',
      images:JSON.stringify(Array.isArray(body.images)?body.images:[]),
      geo_lat:body.geo_lat||null, geo_lng:body.geo_lng||null,
      region, room:String(body.room||'').toUpperCase(),
      user_name:String(body.user_name||'Unknown'),
      status:'OPEN', created_at:body.ts||now, updated_at:now,
    };
    stmts.upsertIssue.run(row);
    const issue=parseIssueRow({...row,resolution_note:'',resolution_images:'[]',approvals_count:0,rejections_count:0,total_votes:0,approval_percentage:0});
    broadcastAll({type:'new_issue',issue});
    jres(res,201,{issue});
    return;
  }

  // ── POST /api/resolve — Authority marks as resolved → UNDER_APPROVAL ──
  if (pathname==='/api/resolve' && req.method==='POST') {
    const body = await readBody(req);
    if (!body.issueId) { jres(res,400,{error:'issueId required'}); return; }
    const result = stmts.resolveIssue.run({
      id:String(body.issueId),
      note:String(body.note||'').slice(0,500),
      images:JSON.stringify(Array.isArray(body.images)?body.images:[]),
      ts:Date.now(),
    });
    if (result.changes===0) { jres(res,404,{error:'Issue not found or already resolved'}); return; }
    const updated = parseIssueRow(stmts.getById.get(String(body.issueId)));
    console.log(`[resolve] #${body.issueId} → UNDER_APPROVAL`);
    broadcastAll({type:'issue_resolved',issueId:String(body.issueId),status:'UNDER_APPROVAL',issue:updated});
    jres(res,200,{ok:true,issue:updated});
    return;
  }

  // ── /api/close IS REMOVED — closure is community-controlled only ──
  // The endpoint returns a 410 Gone with an explanation.
  if (pathname==='/api/close' && req.method==='POST') {
    jres(res,410,{error:'Direct issue closure is no longer available. Issues are closed automatically when community approval reaches 70%.'});
    return;
  }

  // ── GET /api/stats ──
  if (pathname==='/api/stats' && req.method==='GET') {
    const all      = stmts.getAll.all();
    const locals   = [...wss.clients].filter(c=>c._clientType==='local').length;
    const browsers = [...wss.clients].filter(c=>c._clientType!=='local').length;
    jres(res,200,{
      total_issues:            all.length,
      open_issues:             all.filter(i=>i.status==='OPEN').length,
      under_approval:          all.filter(i=>i.status==='UNDER_APPROVAL').length,
      closed_issues:           all.filter(i=>i.status==='CLOSED').length,
      unique_rooms:            new Set(all.map(i=>i.room)).size,
      connected_local_servers: locals,
      connected_browsers:      browsers,
      uptime_seconds:          Math.floor(process.uptime()),
    });
    return;
  }

  res.writeHead(404); res.end('Not found');
  } catch(err) {
    console.error('[request error]', req.method, req.url, err.message);
    if (!res.headersSent) jres(res,500,{error:'Internal server error'});
  }
});

// ─── WEBSOCKET ────────────────────────────────────────────────────────────────
const wss = new WebSocket.Server({server});

wss.on('connection', (ws, req) => {
  const origin   = req.socket.remoteAddress;
  ws._clientType = 'browser';

  ws.on('message', async data => {
    let msg; try { msg = JSON.parse(data); } catch { return; }

    // new_issue pushed by local server
    if (msg.type==='new_issue' && msg.issue) {
      if (ws._clientType!=='local') {
        ws._clientType='local';
        console.log(`[ws] local server connected from ${origin}`);
        ws.send(JSON.stringify({type:'connected',message:'CivicGuard cloud ready'}));
      }
      const issue  = msg.issue;
      const region = await deriveRegion(issue.geo_lat,issue.geo_lng);
      const now    = Date.now();
      const row    = {
        id:String(issue.id), title:String(issue.title||'').slice(0,120),
        description:String(issue.description||'').slice(0,500),
        category:issue.category||'OTHER',
        images:JSON.stringify(Array.isArray(issue.images)?issue.images:(issue.photo_url?[issue.photo_url]:[])),
        geo_lat:issue.geo_lat||null, geo_lng:issue.geo_lng||null,
        region, room:String(issue.room||'').toUpperCase(),
        user_name:String(issue.user_name||'Unknown'),
        status:'OPEN', created_at:issue.ts||now, updated_at:now,
      };
      stmts.upsertIssue.run(row);
      const stored = parseIssueRow({...row,resolution_note:'',resolution_images:'[]',approvals_count:0,rejections_count:0,total_votes:0,approval_percentage:0});
      broadcastToBrowsers({type:'new_issue',issue:stored});
      return;
    }

    // issue_resolved sent by authority dashboard (WS path)
    if (msg.type==='issue_resolve' && msg.issueId) {
      const result = stmts.resolveIssue.run({id:String(msg.issueId),note:String(msg.note||'').slice(0,500),images:JSON.stringify(Array.isArray(msg.images)?msg.images:[]),ts:Date.now()});
      if (result.changes>0) {
        const updated = parseIssueRow(stmts.getById.get(String(msg.issueId)));
        console.log(`[ws-resolve] #${msg.issueId} → UNDER_APPROVAL`);
        broadcastAll({type:'issue_resolved',issueId:String(msg.issueId),status:'UNDER_APPROVAL',issue:updated});
      }
      return;
    }

    // issue_vote_update relayed from local server
    if (msg.type==='issue_vote_update' && msg.issueId) {
      // Update vote counts in cloud DB
      try {
        stmts.updateVoteCounts.run({
          id:             String(msg.issueId),
          approvals_count:    msg.approvals_count    || 0,
          rejections_count:   msg.rejections_count   || 0,
          total_votes:        msg.total_votes        || 0,
          approval_percentage: msg.approval_percentage || 0,
          ts:             Date.now(),
        });
      } catch {}
      console.log(`[ws-vote] #${msg.issueId} → ${msg.approval_percentage}% (${msg.approvals_count}/${msg.total_votes})`);
      broadcastToBrowsers({type:'issue_vote_update',
        issueId:            String(msg.issueId),
        approvals_count:    msg.approvals_count,
        rejections_count:   msg.rejections_count,
        total_votes:        msg.total_votes,
        approval_percentage: msg.approval_percentage,
      });
      return;
    }

    // issue_closed relayed from local server (community threshold met)
    if (msg.type==='issue_closed' && msg.issueId) {
      try { stmts.autoCloseIssue.run({id:String(msg.issueId),ts:Date.now()}); } catch {}
      console.log(`[ws-auto-close] #${msg.issueId} → CLOSED (community approved)`);
      broadcastAll({type:'issue_closed',issueId:String(msg.issueId),status:'CLOSED'});
      return;
    }
  });

  ws.on('close', () => { if(ws._clientType==='local') console.log(`[ws] local disconnected (${origin})`); });
  ws.on('error', ()=>{});
});

function broadcastToBrowsers(msg) {
  const p=JSON.stringify(msg); let n=0;
  wss.clients.forEach(c=>{if(c._clientType!=='local'&&c.readyState===WebSocket.OPEN){c.send(p);n++;}});
  if(n) console.log(`[→browsers] ${msg.type} to ${n}`);
}
function broadcastAll(msg) {
  const p=JSON.stringify(msg); let n=0;
  wss.clients.forEach(c=>{if(c.readyState===WebSocket.OPEN){c.send(p);n++;}});
  if(n) console.log(`[→all] ${msg.type} to ${n}`);
}

// ─── KEEP-ALIVE ───────────────────────────────────────────────────────────────
const SELF_URL = process.env.RENDER_EXTERNAL_URL;
if (SELF_URL) {
  setInterval(()=>{
    https.get(SELF_URL+'/healthz',r=>console.log(`[keepalive] ${r.statusCode}`)).on('error',e=>console.warn('[keepalive] failed:',e.message));
  }, 14*60*1000);
  console.log(`  Keep-alive: ${SELF_URL}/healthz every 14 min`);
}

// ─── START ────────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  CivicGuard — Cloud Server (Community Approval Edition)');
  console.log('  ─────────────────────────────────────────────────────────');
  console.log(`  Public dashboard : http://0.0.0.0:${PORT}/`);
  console.log(`  Authority panel  : http://0.0.0.0:${PORT}/authority`);
  console.log(`  Issues API       : http://0.0.0.0:${PORT}/api/issues`);
  console.log(`  Resolve API      : POST http://0.0.0.0:${PORT}/api/resolve`);
  console.log(`  Stats API        : http://0.0.0.0:${PORT}/api/stats`);
  console.log(`  Health           : http://0.0.0.0:${PORT}/healthz`);
  console.log(`  Database         : ${DB_PATH}`);
  console.log('');
  console.log('  NOTE: /api/close removed — closure is community-only.');
  console.log('  Issues auto-close when approval >= 70% with >= 5 votes.');
  console.log('');
});