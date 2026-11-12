const express = require('express');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
// Admin password. (LECTURER_KEY is the older name and still works.)
const ADMIN_KEY = process.env.ADMIN_KEY || process.env.LECTURER_KEY || 'changeme';
if (process.env.NODE_ENV === 'production' && ADMIN_KEY === 'changeme') {
  console.error('Set ADMIN_KEY to a private password before running online.'); process.exit(1);
}
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const SELFIES = path.join(DATA, 'selfies');
const ROSTERS = path.join(DATA, 'rosters');
const COURSES = path.join(DATA, 'courses');
const TIMETABLES = path.join(DATA, 'timetables');
fs.mkdirSync(SELFIES, { recursive: true });
fs.mkdirSync(ROSTERS, { recursive: true });
fs.mkdirSync(COURSES, { recursive: true });
fs.mkdirSync(TIMETABLES, { recursive: true });

const file = (n) => path.join(DATA, n);
const load = (n, d) => { try { return JSON.parse(fs.readFileSync(file(n), 'utf8')); } catch { return d; } };
const save = (n, v) => { const t = file(n) + '.tmp'; fs.writeFileSync(t, JSON.stringify(v, null, 2)); fs.renameSync(t, file(n)); };

// Secret used to sign login tokens (kept in the data folder so logins survive restarts)
let SECRET = process.env.TOKEN_SECRET;
if (!SECRET) {
  try { SECRET = fs.readFileSync(file('secret.txt'), 'utf8').trim(); } catch {}
  if (!SECRET) { SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(file('secret.txt'), SECRET); }
}

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '4mb' }));
app.use((req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); next(); });
app.use(express.static(path.join(__dirname, 'public')));
app.get('/healthz', (req, res) => res.send('ok'));

// ---------- helpers ----------
function distanceKm(lat1, lon1, lat2, lon2) {
  const R = 6371, rad = (x) => (x * Math.PI) / 180;
  const dLat = rad(lat2 - lat1), dLon = rad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}
const validCoords = (lat, lng) =>
  Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180;
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const getSession = (code) => load('sessions.json', {})[String(code).toUpperCase()];
const publicStudent = (s) => ({ id: s.id, name: s.name, programme: s.programme, year: s.year });
const ownerOf = (s) => s.owner || 'admin';
// A QR code works only while the session is open AND inside its time window (default 2 hours from when it was started)
const isExpired = (s) => !!s.expiresAt && Date.parse(s.expiresAt) <= Date.now();
const isActive = (s) => !!s.open && !isExpired(s);

// ---------- accounts & tokens ----------
const lecturers = () => load('lecturers.json', []);
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString('hex');
function signToken(p) {
  const body = Buffer.from(JSON.stringify(p)).toString('base64url');
  return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
}
function readToken(t) {
  const [body, sig] = String(t || '').split('.');
  if (!body || !sig) return null;
  const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!safeEq(sig, good)) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p : null; } catch { return null; }
}

const fails = new Map(); // ip -> [timestamps]
function tooMany(ip) { const now = Date.now(); const a = (fails.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000); fails.set(ip, a); return a.length >= 8; }

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (tooMany(ip)) return res.status(429).json({ error: 'Too many wrong attempts. Wait 10 minutes and try again.' });
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  let user = null;
  if (username === 'admin') {
    if (safeEq(password, ADMIN_KEY)) user = { u: 'admin', r: 'admin', n: 'Admin' };
  } else {
    const l = lecturers().find((x) => x.username === username);
    if (l && safeEq(hashPw(password, l.salt), l.hash)) user = { u: l.username, r: 'lecturer', n: l.name };
  }
  if (!user) { fails.set(ip, (fails.get(ip) || []).concat(Date.now())); return res.status(401).json({ error: 'Wrong username or password.' }); }
  res.json({ token: signToken({ ...user, exp: Date.now() + 12 * 3600 * 1000 }), name: user.n, role: user.r, username: user.u });
});

function lecturerOnly(req, res, next) {
  const t = req.get('x-key') || req.query.key || '';
  const p = readToken(t);
  if (p) {
    if (p.r === 'lecturer' && !lecturers().some((l) => l.username === p.u)) return res.status(401).json({ error: 'Account removed.' });
    req.user = p; return next();
  }
  if (safeEq(t, ADMIN_KEY)) { req.user = { u: 'admin', r: 'admin', n: 'Admin' }; return next(); } // raw admin key still works
  res.status(401).json({ error: 'Please sign in again.' });
}
const adminOnly = (req, res, next) => (req.user.r === 'admin' ? next() : res.status(403).json({ error: 'Admin only.' }));
const canSee = (req, s) => req.user.r === 'admin' || ownerOf(s) === req.user.u;
function mine(req, res) {
  const s = getSession(req.params.code);
  if (!s || !canSee(req, s)) { res.status(404).json({ error: 'Session not found' }); return null; }
  return s;
}

// ---------- rosters (one class list per lecturer) ----------
const rosterFile = (u) => path.join(ROSTERS, u + '.json');
function loadRoster(u) {
  try { return JSON.parse(fs.readFileSync(rosterFile(u), 'utf8')); } catch {}
  return u === 'admin' ? load('students.json', []) : []; // older installs kept one list in students.json
}
const saveRoster = (u, list) => { const t = rosterFile(u) + '.tmp'; fs.writeFileSync(t, JSON.stringify(list, null, 2)); fs.renameSync(t, rosterFile(u)); };

// ---------- admin: manage lecturers ----------
app.get('/api/admin/lecturers', lecturerOnly, adminOnly, (req, res) =>
  res.json(lecturers().map((l) => ({ username: l.username, name: l.name, createdAt: l.createdAt, students: loadRoster(l.username).length }))));

app.post('/api/admin/lecturers', lecturerOnly, adminOnly, (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const name = String(req.body.name || '').trim().slice(0, 80);
  const password = String(req.body.password || '');
  if (!/^[a-z0-9._-]{3,30}$/.test(username) || username === 'admin') return res.status(400).json({ error: 'Username: 3–30 letters/numbers (no spaces), and not "admin".' });
  if (!name) return res.status(400).json({ error: 'Enter the lecturer’s name.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const list = lecturers();
  if (list.some((l) => l.username === username)) return res.status(409).json({ error: 'That username already exists.' });
  const salt = crypto.randomBytes(16).toString('hex');
  list.push({ username, name, salt, hash: hashPw(password, salt), createdAt: new Date().toISOString() });
  save('lecturers.json', list);
  res.json({ ok: true });
});

app.post('/api/admin/lecturers/:username/password', lecturerOnly, adminOnly, (req, res) => {
  const list = lecturers(); const l = list.find((x) => x.username === req.params.username);
  const password = String(req.body.password || '');
  if (!l) return res.status(404).json({ error: 'Not found' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  l.salt = crypto.randomBytes(16).toString('hex'); l.hash = hashPw(password, l.salt);
  save('lecturers.json', list); res.json({ ok: true });
});

app.delete('/api/admin/lecturers/:username', lecturerOnly, adminOnly, (req, res) => {
  const list = lecturers();
  if (!list.some((l) => l.username === req.params.username)) return res.status(404).json({ error: 'Not found' });
  save('lecturers.json', list.filter((l) => l.username !== req.params.username));
  res.json({ ok: true });
});

// ---------- lecturer API ----------
app.get('/api/lecturer/me', lecturerOnly, (req, res) => res.json({ username: req.user.u, name: req.user.n, role: req.user.r }));

app.post('/api/lecturer/session', lecturerOnly, (req, res) => {
  const { lat, lng, radiusKm } = req.body;
  let name = String(req.body.name || '').trim(), venue = '';
  if (req.body.course === 'auto' || !name) {            // work out the course from the timetable
    const slot = detectSlot(req.user.u);
    if (!slot) return res.status(400).json({ error: 'No class is on your timetable at this time. Choose the course yourself.' });
    name = slot.course; venue = slot.venue || '';
  } else {
    const slot = loadTimetable(req.user.u).find((e) => e.course === name); venue = slot ? slot.venue || '' : '';
  }
  if (!validCoords(+lat, +lng)) return res.status(400).json({ error: 'Valid lecturer location is required' });
  const r = Number(radiusKm);
  if (!(r > 0 && r <= 100)) return res.status(400).json({ error: 'Radius must be between 0 and 100 km' });
  const hours = req.body.hours === undefined || req.body.hours === '' ? 2 : Number(req.body.hours);
  if (!(hours >= 0.25 && hours <= 12)) return res.status(400).json({ error: 'Valid-for time must be between 0.25 and 12 hours.' });
  const code = crypto.randomBytes(4).toString('hex').slice(0, 6).toUpperCase();
  const sessions = load('sessions.json', {});
  sessions[code] = { code, name: name.slice(0, 80) || 'Class', venue, lat: +lat, lng: +lng, radiusKm: r, open: true, owner: req.user.u, ownerName: req.user.n, createdAt: new Date().toISOString(), hours, expiresAt: new Date(Date.now() + hours * 3600 * 1000).toISOString() };
  save('sessions.json', sessions);
  res.json({ ...sessions[code], active: true });
});

app.get('/api/lecturer/sessions', lecturerOnly, (req, res) => {
  const recs = load('records.json', []);
  res.json(Object.values(load('sessions.json', {}))
    .filter((s) => canSee(req, s))
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .map((s) => ({ ...s, active: isActive(s), count: recs.filter((r) => r.code === s.code).length })));
});

// Present + absent lists and totals for one session (absent = this lecturer's class list minus those who signed)
function buildSummary(s) {
  const records = load('records.json', []).filter((r) => r.code === s.code);
  const students = loadRoster(ownerOf(s));
  const signed = new Set(records.map((r) => r.studentId));
  const absent = students.filter((x) => !signed.has(x.id))
    .sort((a, b) => a.name.localeCompare(b.name)).map(publicStudent);
  const total = students.length;
  const presentCount = total - absent.length;
  return { session: { ...s, active: isActive(s) }, records, absent, total, presentCount, absentCount: absent.length,
    percent: total ? Math.round((presentCount / total) * 1000) / 10 : 0 };
}
app.get('/api/lecturer/session/:code/summary', lecturerOnly, (req, res) => {
  const s = mine(req, res); if (s) res.json(buildSummary(s));
});

app.post('/api/lecturer/session/:code/close', lecturerOnly, (req, res) => {
  const s0 = mine(req, res); if (!s0) return;
  const sessions = load('sessions.json', {});
  const t = sessions[s0.code];
  t.open = req.body.open === true;
  if (t.open && isExpired(t)) t.expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // reopening an ended class gives 30 more minutes
  save('sessions.json', sessions);
  res.json({ ...t, active: isActive(t) });
});

// Give a class more time (for example a lecture that runs late)
app.post('/api/lecturer/session/:code/extend', lecturerOnly, (req, res) => {
  const s0 = mine(req, res); if (!s0) return;
  const mins = Math.min(Math.max(Number(req.body.minutes) || 30, 5), 240);
  const sessions = load('sessions.json', {}); const t = sessions[s0.code];
  const from = Math.max(Date.now(), Date.parse(t.expiresAt || 0) || 0);
  t.expiresAt = new Date(from + mins * 60 * 1000).toISOString(); t.open = true;
  save('sessions.json', sessions);
  res.json({ ...t, active: isActive(t) });
});

app.get('/api/lecturer/session/:code/qr', lecturerOnly, async (req, res) => {
  const s = mine(req, res); if (!s) return;
  let base = String(req.query.base || '').trim().replace(/\/+$/, '').replace(/\/lecturer\.html$/i, '');
  if (!/^https?:\/\/[\w.-]+(:\d+)?$/i.test(base)) base = `${req.protocol}://${req.get('host')}`;
  const url = `${base}/s/${s.code}`;
  res.json({ url, qr: await QRCode.toDataURL(url, { width: 520, margin: 1 }) });
});

app.get('/api/lecturer/session/:code/records', lecturerOnly, (req, res) => {
  const s = mine(req, res); if (s) res.json(load('records.json', []).filter((r) => r.code === s.code));
});

app.get('/api/lecturer/session/:code/csv', lecturerOnly, (req, res) => {
  const s = mine(req, res); if (!s) return;
  const sum = buildSummary(s);
  const q = (v) => { let t = String(v ?? ''); if (/^[=+\-@]/.test(t)) t = "'" + t; return `"${t.replace(/"/g, '""')}"`; };
  const csv = ['Student ID,Name,Programme,Status,Time,Distance (km),Accuracy (m)']
    .concat(sum.records.map((r) => [r.studentId, r.name, r.programme, 'Present', r.time, r.distanceKm, r.accuracy].map(q).join(',')))
    .concat(sum.absent.map((a) => [a.id, a.name, a.programme, 'Absent', '', '', ''].map(q).join(',')))
    .join('\r\n');
  res.set({ 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="attendance-${s.code}.csv"` }).send(csv);
});

app.get('/api/lecturer/selfie/:file', lecturerOnly, (req, res) => {
  const f = path.basename(req.params.file);
  const s = getSession(f.split('_')[0]);
  if (!s || !canSee(req, s)) return res.status(404).end();
  res.sendFile(path.join(SELFIES, f), (e) => e && res.status(404).end());
});

app.get('/api/lecturer/students', lecturerOnly, (req, res) => res.json({ total: loadRoster(req.user.u).length }));

// Paste a class list: one student per line -> ID, Name, Programme, Year (tab or comma separated; Excel paste works)
app.post('/api/lecturer/students', lecturerOnly, (req, res) => {
  const lines = String(req.body.text || '').split(/\r?\n/);
  const students = loadRoster(req.user.u);
  const byId = new Map(students.map((x) => [x.id, x]));
  let added = 0, updated = 0; const skipped = [];
  for (const raw of lines) {
    const line = raw.trim(); if (!line) continue;
    const parts = (line.includes('\t') ? line.split('\t') : line.split(',')).map((x) => x.trim().replace(/^"|"$/g, ''));
    const id = (parts[0] || '').replace(/\D/g, '');
    if (!/^\d{10}$/.test(id)) { skipped.push(line.slice(0, 40)); continue; }
    const rec = { id, name: (parts[1] || 'Unknown').slice(0, 100), programme: (parts[2] || '').slice(0, 100), year: parseInt(parts[3], 10) || '' };
    if (byId.has(id)) { Object.assign(byId.get(id), rec); updated++; } else { byId.set(id, rec); added++; }
  }
  const out = [...byId.values()];
  saveRoster(req.user.u, out);
  res.json({ added, updated, skipped: skipped.length, skippedExamples: skipped.slice(0, 3), total: out.length });
});

app.delete('/api/lecturer/students', lecturerOnly, (req, res) => { saveRoster(req.user.u, []); res.json({ ok: true }); });


// ---------- courses (each lecturer keeps a list of the courses they teach) ----------
const courseFile = (u) => path.join(COURSES, u + '.json');
const loadCourses = (u) => { try { return JSON.parse(fs.readFileSync(courseFile(u), 'utf8')); } catch { return []; } };
const saveCourses = (u, list) => { const t = courseFile(u) + '.tmp'; fs.writeFileSync(t, JSON.stringify(list, null, 2)); fs.renameSync(t, courseFile(u)); };
app.get('/api/lecturer/courses', lecturerOnly, (req, res) => res.json(loadCourses(req.user.u)));
app.post('/api/lecturer/courses', lecturerOnly, (req, res) => {
  // one course per line, so a whole list can be pasted at once
  const names = String(req.body.name || '').split(/\r?\n/).map((x) => x.replace(/\s+/g, ' ').trim().slice(0, 80)).filter(Boolean);
  if (!names.length) return res.status(400).json({ error: 'Type the course name.' });
  const list = loadCourses(req.user.u); let added = 0;
  for (const name of names) {
    if (list.some((c) => c.toLowerCase() === name.toLowerCase()) || list.length >= 40) continue;
    list.push(name); added++;
  }
  if (!added) return res.status(409).json({ error: 'Already in your list.' });
  saveCourses(req.user.u, list); res.json(list);
});
app.post('/api/lecturer/courses/remove', lecturerOnly, (req, res) => {
  const name = String(req.body.name || '');
  saveCourses(req.user.u, loadCourses(req.user.u).filter((c) => c !== name)); res.json(loadCourses(req.user.u));
});

// One table for a whole course: every student, how many classes they attended, and the percentage
function buildReport(req, course) {
  const sessions = Object.values(load('sessions.json', {}))
    .filter((s) => ownerOf(s) === req.user.u && s.name === course)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const signed = new Map(sessions.map((s) => [s.code, new Set()]));
  for (const r of load('records.json', [])) if (signed.has(r.code)) signed.get(r.code).add(r.studentId);
  const rows = loadRoster(req.user.u).slice().sort((a, b) => a.name.localeCompare(b.name)).map((st) => {
    const marks = sessions.map((s) => signed.get(s.code).has(st.id));
    const attended = marks.filter(Boolean).length;
    return { id: st.id, name: st.name, programme: st.programme, attended, total: sessions.length,
      percent: sessions.length ? Math.round((attended / sessions.length) * 1000) / 10 : 0, marks };
  });
  return { course, sessions: sessions.map((s) => ({ code: s.code, createdAt: s.createdAt, count: signed.get(s.code).size })), rows };
}
app.get('/api/lecturer/report', lecturerOnly, (req, res) => res.json(buildReport(req, String(req.query.course || ''))));
app.get('/api/lecturer/report.csv', lecturerOnly, (req, res) => {
  const rep = buildReport(req, String(req.query.course || ''));
  const q = (v) => { let t = String(v ?? ''); if (/^[=+\-@]/.test(t)) t = "'" + t; return `"${t.replace(/"/g, '""')}"`; };
  const head = ['Student ID', 'Name', 'Classes attended', 'Total classes', 'Percent']
    .concat(rep.sessions.map((s) => new Date(s.createdAt).toISOString().slice(0, 16).replace('T', ' ')));
  const lines = [head.map(q).join(',')].concat(rep.rows.map((r) =>
    [r.id, r.name, r.attended, r.total, r.percent + '%'].concat(r.marks.map((m) => (m ? 'Present' : 'Absent'))).map(q).join(',')));
  const fn = rep.course.replace(/[^\w.-]+/g, '_').slice(0, 40) || 'course';
  res.set({ 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="report-${fn}.csv"` }).send(lines.join('\r\n'));
});


// ---------- weekly timetable: lets the app know which course is on right now ----------
const TZ_OFFSET = Number(process.env.TZ_OFFSET_MIN || 0); // Ghana (GMT) = 0
const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const ttFile = (u) => path.join(TIMETABLES, u + '.json');
const loadTimetable = (u) => { try { return JSON.parse(fs.readFileSync(ttFile(u), 'utf8')); } catch { return []; } };
const saveTimetable = (u, list) => { const t = ttFile(u) + '.tmp'; fs.writeFileSync(t, JSON.stringify(list, null, 2)); fs.renameSync(t, ttFile(u)); };
const toMin = (t) => { const [h, m] = String(t).split(':').map(Number); return h * 60 + m; };
function localNow() { const d = new Date(Date.now() + TZ_OFFSET * 60000); return { day: d.getUTCDay(), min: d.getUTCHours() * 60 + d.getUTCMinutes() }; }
// The class that is on now (a QR can be made from 30 minutes before it starts until it ends)
function detectSlot(u) {
  const { day, min } = localNow(); const today = loadTimetable(u).filter((e) => e.day === day);
  return today.find((e) => min >= toMin(e.start) && min < toMin(e.end))          // a class that is in progress
    || today.find((e) => min >= toMin(e.start) - 30 && min < toMin(e.start)) || null; // or one starting within 30 minutes
}
const sortTT = (l) => l.sort((a, b) => a.day - b.day || toMin(a.start) - toMin(b.start));

app.get('/api/lecturer/timetable', lecturerOnly, (req, res) => res.json(sortTT(loadTimetable(req.user.u))));
app.get('/api/lecturer/timetable/now', lecturerOnly, (req, res) => res.json({ now: detectSlot(req.user.u) }));
app.post('/api/lecturer/timetable', lecturerOnly, (req, res) => {
  const day = Number(req.body.day), start = String(req.body.start || ''), end = String(req.body.end || '');
  const course = String(req.body.course || '').trim().slice(0, 80), venue = String(req.body.venue || '').trim().slice(0, 40);
  if (!(day >= 0 && day <= 6) || !/^\d{1,2}:\d{2}$/.test(start) || !/^\d{1,2}:\d{2}$/.test(end) || toMin(end) <= toMin(start)) return res.status(400).json({ error: 'Choose the day and a start time that is before the end time.' });
  if (!course) return res.status(400).json({ error: 'Choose the course.' });
  const list = loadTimetable(req.user.u); list.push({ day, start, end, course, venue });
  saveTimetable(req.user.u, sortTT(list)); res.json(list);
});
app.post('/api/lecturer/timetable/remove', lecturerOnly, (req, res) => {
  const { day, start, course } = req.body;
  saveTimetable(req.user.u, loadTimetable(req.user.u).filter((e) => !(e.day === Number(day) && e.start === start && e.course === course)));
  res.json(loadTimetable(req.user.u));
});
// One-click: BSc IT 2C timetable (courses + weekly slots)
const PRESET = [
  [1, '10:00', '13:00', 'DATABASE CONCEPTS AND DESIGN (ICT231)', 'ICT 231'],
  [3, '07:00', '10:00', 'WEB TECHNOLOGIES 1 (ICT233)', 'UMT 211'],
  [3, '10:00', '13:00', 'PROGRAMMING WITH JAVA (ICT232)', 'ICT 232'],
  [3, '14:00', '17:00', 'MICRO ECONOMICS (ECH231)', 'MFB 201'],
  [4, '07:00', '10:00', 'COURTSHIP AND MARRIAGE (GPD231CA)', 'ESA SP 4'],
  [4, '10:00', '13:00', 'PROBABILITY AND STATISTICS (MAT239)', 'MFB 101'],
].map(([day, start, end, course, venue]) => ({ day, start, end, course, venue }));
app.post('/api/lecturer/timetable/preset', lecturerOnly, (req, res) => {
  saveTimetable(req.user.u, PRESET);
  const courses = loadCourses(req.user.u);
  for (const e of PRESET) if (!courses.includes(e.course)) courses.push(e.course);
  saveCourses(req.user.u, courses);
  res.json(PRESET);
});

// ---------- student API ----------
app.get('/api/session/:code', (req, res) => {
  const s = getSession(req.params.code);
  if (!s) return res.status(404).json({ error: 'This attendance link is not valid.' });
  res.json({ name: s.name, venue: s.venue || '', open: isActive(s), expired: isExpired(s), closesAt: s.expiresAt || null, radiusKm: s.radiusKm });
});

// Look up a student in the class list of the lecturer who owns this session
app.get('/api/student/:id', (req, res) => {
  if (!/^\d{10}$/.test(req.params.id)) return res.status(400).json({ error: 'ID must be 10 digits' });
  const s = getSession(req.query.code || '');
  if (!s) return res.status(404).json({ error: 'This attendance link is not valid.' });
  const st = loadRoster(ownerOf(s)).find((x) => x.id === req.params.id);
  if (!st) return res.status(404).json({ error: 'Student ID not found' });
  res.json(publicStudent(st));
});

// Early distance check so the student sees "too far" before taking a selfie
app.post('/api/check', (req, res) => {
  const s = getSession(req.body.code || '');
  const lat = +req.body.lat, lng = +req.body.lng;
  if (!s) return res.status(404).json({ error: 'Invalid session' });
  if (!validCoords(lat, lng)) return res.status(400).json({ error: 'Invalid location' });
  const d = distanceKm(s.lat, s.lng, lat, lng);
  res.json({ distanceKm: +d.toFixed(2), allowed: d <= s.radiusKm, radiusKm: s.radiusKm });
});

app.post('/api/attend', (req, res) => {
  const { code, studentId, selfie } = req.body;
  const lat = +req.body.lat, lng = +req.body.lng, accuracy = Math.round(+req.body.accuracy || 0);
  const s = getSession(code || '');
  if (!s) return res.status(404).json({ error: 'Invalid attendance link.' });
  if (isExpired(s)) return res.status(403).json({ error: 'This QR code has expired. The attendance time for this class has ended.' });
  if (!s.open) return res.status(403).json({ error: 'This attendance session is closed.' });
  if (!/^\d{10}$/.test(studentId || '')) return res.status(400).json({ error: 'Invalid student ID.' });
  const student = loadRoster(ownerOf(s)).find((x) => x.id === studentId);
  if (!student) return res.status(404).json({ error: 'Student ID not found.' });
  if (!validCoords(lat, lng)) return res.status(400).json({ error: 'Location is required to sign attendance.' });

  const d = distanceKm(s.lat, s.lng, lat, lng);
  if (d > s.radiusKm)
    return res.status(403).json({ error: `You are ${d.toFixed(1)} km from class. Attendance is only allowed within ${s.radiusKm} km.`, distanceKm: +d.toFixed(2) });

  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(selfie || '');
  if (!m) return res.status(400).json({ error: 'A selfie is required.' });

  const records = load('records.json', []);
  if (records.some((r) => r.code === s.code && r.studentId === studentId))
    return res.status(409).json({ error: 'Attendance already recorded for this ID.' });

  const selfieFile = `${s.code}_${studentId}.jpg`;
  fs.writeFileSync(path.join(SELFIES, selfieFile), Buffer.from(m[1], 'base64'));
  const rec = {
    code: s.code, studentId, name: student.name, programme: student.programme,
    time: new Date().toISOString(), distanceKm: +d.toFixed(2), accuracy, lat, lng, selfie: selfieFile,
  };
  records.push(rec);
  save('records.json', records);
  res.json({ ok: true, name: student.name, studentId, programme: student.programme, time: rec.time });
});

// Student page: /s/<code>
app.get('/s/:code', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student.html')));

app.listen(PORT, (err) => {
  if (err) { console.error(err); process.exit(1); }
  console.log(`Attendance running on http://localhost:${PORT}  (lecturer: /lecturer.html)`);
});
