'use strict';
/* =============================================================================
 * SMART DIGITAL SERVICES (SDS) — single-server web application
 * -----------------------------------------------------------------------------
 * Node.js + Express + SQLite (built-in node:sqlite). Frontend, admin dashboard,
 * APIs, database initialisation and uploads are all served from this file.
 *
 * Sections:
 *   1. Configuration & paths          8. Public layout, icons & CSS
 *   2. Encryption & password hashing  9. Public pages
 *   3. Database schema               10. Public form APIs
 *   4. Helpers                        11. Certificates, quotations, SVG media
 *   5. Default settings & content    12. Admin resources (generic CRUD)
 *   6. Seed data                     13. Admin APIs & pages
 *   7. Security middleware           14. Client JavaScript (site + admin)
 *                                    15. Start-up
 * ========================================================================== */

process.removeAllListeners('warning');
process.on('warning', (w) => { if (w.name !== 'ExperimentalWarning') console.warn(w); });

require('dotenv').config({ quiet: true });
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const multer = require('multer');
const sanitizeHtmlLib = require('sanitize-html');
const nodemailer = require('nodemailer');
const { DatabaseSync } = require('node:sqlite');

/* ============================== 1. CONFIGURATION ============================= */
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const IS_PROD = process.env.NODE_ENV === 'production';
const ROOT = __dirname;
// On Vercel (serverless) only /tmp is writable and it is temporary — fine for testing, not for production.
const ON_VERCEL = !!process.env.VERCEL;
const DATA_DIR = path.resolve(ROOT, process.env.DATA_DIR || (ON_VERCEL ? '/tmp/sds/data' : 'data'));
const UPLOAD_DIR = path.resolve(ROOT, process.env.UPLOAD_DIR || (ON_VERCEL ? '/tmp/sds/uploads' : 'uploads'));
const DIRS = {
  images: path.join(UPLOAD_DIR, 'images'),       // public: site images, blog, products, team
  documents: path.join(UPLOAD_DIR, 'documents'), // public: admin-uploaded PDF documents
  private: path.join(UPLOAD_DIR, 'private'),     // PRIVATE: scheme documents (admin download only)
};
for (const d of [DATA_DIR, UPLOAD_DIR, ...Object.values(DIRS)]) fs.mkdirSync(d, { recursive: true });

const SESSION_IDLE_MS = Math.max(5, parseInt(process.env.SESSION_IDLE_MINUTES || '120', 10)) * 60 * 1000;
const SESSION_MAX_MS = Math.max(1, parseInt(process.env.SESSION_MAX_HOURS || '12', 10)) * 3600 * 1000;
const MAX_IMAGE_BYTES = 3 * 1024 * 1024;
const MAX_DOC_BYTES = 5 * 1024 * 1024;
const ASSET_VERSION = Date.now().toString(36);

/* ===================== 2. ENCRYPTION & PASSWORD HASHING ===================== */
function loadDataKey() {
  const hex = (process.env.DATA_ENCRYPTION_KEY || '').trim();
  if (/^[0-9a-fA-F]{64}$/.test(hex)) return Buffer.from(hex, 'hex');
  const keyFile = path.join(DATA_DIR, '.data-key');
  if (fs.existsSync(keyFile)) return Buffer.from(fs.readFileSync(keyFile, 'utf8').trim(), 'hex');
  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyFile, key.toString('hex'), { mode: 0o600 });
  console.warn('[security] No DATA_ENCRYPTION_KEY set. Generated data/.data-key — back this file up; without it encrypted CNIC numbers cannot be read.');
  return key;
}
const DATA_KEY = loadDataKey();

function encrypt(text) {
  if (text === null || text === undefined || text === '') return '';
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', DATA_KEY, iv);
  const enc = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return `v1:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${enc.toString('base64')}`;
}
function decrypt(value) {
  if (!value || !String(value).startsWith('v1:')) return value || '';
  try {
    const [, iv, tag, data] = String(value).split(':');
    const d = crypto.createDecipheriv('aes-256-gcm', DATA_KEY, Buffer.from(iv, 'base64'));
    d.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(data, 'base64')), d.final()]).toString('utf8');
  } catch { return '[unreadable — encryption key changed]'; }
}
const blindIndex = (v) => crypto.createHmac('sha256', DATA_KEY).update(String(v)).digest('hex');
const sha256 = (v) => crypto.createHash('sha256').update(String(v)).digest('hex');
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString('base64')}$${hash.toString('base64')}`;
}
function verifyPassword(password, stored) {
  try {
    const [algo, N, r, p, salt, hash] = String(stored).split('$');
    if (algo !== 'scrypt') return false;
    const expected = Buffer.from(hash, 'base64');
    const actual = crypto.scryptSync(String(password), Buffer.from(salt, 'base64'), expected.length, { N: +N, r: +r, p: +p });
    return crypto.timingSafeEqual(expected, actual);
  } catch { return false; }
}
const DUMMY_HASH = hashPassword(randomToken(8)); // used to equalise timing for unknown users
function safeEqual(a, b) {
  const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || ''));
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
}

/* ============================== 3. DATABASE ============================== */
const db = new DatabaseSync(path.join(DATA_DIR, 'sds.sqlite'));
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');

db.exec(`
CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', active INTEGER NOT NULL DEFAULT 1,
  last_login TEXT, created_at TEXT NOT NULL, updated_at TEXT);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL, ip TEXT, user_agent TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT, grp TEXT NOT NULL DEFAULT 'main', title TEXT NOT NULL, slug TEXT,
  icon TEXT DEFAULT 'monitor', summary TEXT, description TEXT, link TEXT, sort_order INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS blog_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, description TEXT,
  icon TEXT DEFAULT 'file', sort_order INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS blog_tags (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS blog_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, excerpt TEXT, content TEXT,
  featured_image TEXT, category_id INTEGER REFERENCES blog_categories(id) ON DELETE SET NULL, author TEXT,
  status TEXT NOT NULL DEFAULT 'draft', featured INTEGER DEFAULT 0, allow_comments INTEGER DEFAULT 1,
  seo_title TEXT, meta_description TEXT, published_at TEXT, views INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS blog_post_tags (
  post_id INTEGER NOT NULL REFERENCES blog_posts(id) ON DELETE CASCADE,
  tag_id INTEGER NOT NULL REFERENCES blog_tags(id) ON DELETE CASCADE, PRIMARY KEY (post_id, tag_id));
CREATE TABLE IF NOT EXISTS blog_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL REFERENCES blog_posts(id) ON DELETE CASCADE,
  name TEXT NOT NULL, email TEXT, comment TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', ip_hash TEXT,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS courses (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, tagline TEXT, description TEXT,
  objectives TEXT, syllabus TEXT, fee REAL NOT NULL DEFAULT 300, fee_period TEXT DEFAULT 'month', duration TEXT,
  schedule TEXT, requirements TEXT, image TEXT, enrollment_open INTEGER DEFAULT 1, active INTEGER DEFAULT 1,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, father_name TEXT, gender TEXT, phone TEXT NOT NULL,
  email TEXT, city TEXT, address TEXT, education TEXT, notes TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS enrollments (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE, preferred_timing TEXT,
  status TEXT NOT NULL DEFAULT 'pending', fee_status TEXT DEFAULT 'unpaid', months_paid INTEGER DEFAULT 0,
  start_date TEXT, completion_date TEXT, certificate_eligible INTEGER DEFAULT 0, message TEXT, notes TEXT,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT, certificate_id TEXT NOT NULL UNIQUE,
  student_id INTEGER REFERENCES students(id) ON DELETE SET NULL, enrollment_id INTEGER REFERENCES enrollments(id) ON DELETE SET NULL,
  student_name TEXT NOT NULL, father_name TEXT, course_name TEXT NOT NULL, completion_date TEXT NOT NULL, grade TEXT,
  status TEXT NOT NULL DEFAULT 'valid', revoke_reason TEXT, revoked_at TEXT, issued_by TEXT, issued_at TEXT NOT NULL,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS certificate_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT, certificate_id TEXT NOT NULL, result TEXT NOT NULL, ip_hash TEXT, checked_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS product_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, icon TEXT DEFAULT 'cctv',
  sort_order INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, sku TEXT,
  category_id INTEGER REFERENCES product_categories(id) ON DELETE SET NULL, brand TEXT, short_description TEXT,
  description TEXT, specs TEXT, price REAL NOT NULL DEFAULT 0, unit TEXT DEFAULT 'piece', image TEXT,
  stock_status TEXT DEFAULT 'in_stock', stock_qty INTEGER DEFAULT 0, installable INTEGER DEFAULT 0,
  featured INTEGER DEFAULT 0, active INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS quotations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, number TEXT NOT NULL UNIQUE, access_token TEXT NOT NULL,
  customer_name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT, city TEXT, address TEXT,
  include_installation INTEGER DEFAULT 0, include_delivery INTEGER DEFAULT 0, subtotal REAL DEFAULT 0,
  installation_charge REAL DEFAULT 0, delivery_charge REAL DEFAULT 0, discount REAL DEFAULT 0, total REAL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'new', customer_notes TEXT, notes TEXT, valid_until TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS quotation_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, quotation_id INTEGER NOT NULL REFERENCES quotations(id) ON DELETE CASCADE,
  product_id INTEGER REFERENCES products(id) ON DELETE SET NULL, product_name TEXT NOT NULL, sku TEXT,
  unit_price REAL NOT NULL, quantity INTEGER NOT NULL, line_total REAL NOT NULL, installable INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS service_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT, city TEXT,
  address TEXT, service_type TEXT, cameras INTEGER, preferred_date TEXT, details TEXT, status TEXT NOT NULL DEFAULT 'new',
  notes TEXT, ip_hash TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS scheme_submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, full_name TEXT NOT NULL, father_name TEXT NOT NULL,
  cnic_enc TEXT NOT NULL, cnic_index TEXT, cnic_last4 TEXT, gender TEXT, marital_status TEXT, mobile TEXT NOT NULL,
  alt_mobile TEXT, email TEXT, city TEXT NOT NULL, district TEXT, address TEXT NOT NULL, occupation TEXT,
  monthly_income TEXT, family_members INTEGER, owns_plot TEXT, plot_size TEXT, plot_location TEXT, additional_info TEXT,
  documents TEXT, consent INTEGER NOT NULL DEFAULT 0, consent_at TEXT, status TEXT NOT NULL DEFAULT 'pending',
  notes TEXT, ip_hash TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS team_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, position TEXT NOT NULL, photo TEXT, bio TEXT,
  email TEXT, phone TEXT, facebook TEXT, linkedin TEXT, instagram TEXT, x TEXT, sort_order INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS contact_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT,
  subject TEXT, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', notes TEXT, ip_hash TEXT,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS testimonials (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, role TEXT, city TEXT, content TEXT NOT NULL,
  rating INTEGER DEFAULT 5, photo TEXT, is_demo INTEGER DEFAULT 0, active INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS activity_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, actor TEXT, action TEXT NOT NULL, entity TEXT, entity_id TEXT,
  details TEXT, ip TEXT, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_posts_status ON blog_posts(status, published_at);
CREATE INDEX IF NOT EXISTS idx_posts_cat ON blog_posts(category_id);
CREATE INDEX IF NOT EXISTS idx_products_cat ON products(category_id);
CREATE INDEX IF NOT EXISTS idx_enroll_student ON enrollments(student_id);
CREATE INDEX IF NOT EXISTS idx_scheme_status ON scheme_submissions(status);
CREATE INDEX IF NOT EXISTS idx_scheme_cnic ON scheme_submissions(cnic_index);
CREATE INDEX IF NOT EXISTS idx_activity_time ON activity_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
`);

const toDb = (v) => (v === undefined ? null : typeof v === 'boolean' ? (v ? 1 : 0) : v);
const stmtCache = new Map();
function prep(sql) { let s = stmtCache.get(sql); if (!s) { s = db.prepare(sql); stmtCache.set(sql, s); } return s; }
const q = {
  all: (sql, ...p) => prep(sql).all(...p.map(toDb)).map((r) => ({ ...r })),
  get: (sql, ...p) => { const r = prep(sql).get(...p.map(toDb)); return r ? { ...r } : undefined; },
  run: (sql, ...p) => prep(sql).run(...p.map(toDb)),
  val: (sql, ...p) => { const r = prep(sql).get(...p.map(toDb)); return r ? Object.values(r)[0] : undefined; },
};
function tx(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
}
const tableColumns = {};
function columnsOf(table) {
  if (!tableColumns[table]) tableColumns[table] = new Set(q.all(`PRAGMA table_info(${table})`).map((c) => c.name));
  return tableColumns[table];
}

/* ============================== 4. HELPERS ============================== */
const nowIso = () => new Date().toISOString();
const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const escXml = esc;
const stripTags = (h) => String(h || '').replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
const truncate = (s, n) => { s = String(s || ''); return s.length > n ? s.slice(0, n - 1).replace(/\s+\S*$/, '') + '…' : s; };
const nl2br = (s) => esc(s).replace(/\r?\n/g, '<br>');
const lines = (s) => String(s || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
const pairs = (s) => lines(s).map((l) => { const [a, ...b] = l.split('|'); return { title: a.trim(), text: b.join('|').trim() }; });
function slugify(s) {
  return String(s || '').toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 90) || 'item';
}
function uniqueSlug(table, base, excludeId) {
  let slug = slugify(base), i = 2;
  while (q.get(`SELECT id FROM ${table} WHERE slug = ? AND id != ?`, slug, excludeId || 0)) slug = `${slugify(base)}-${i++}`;
  return slug;
}
function makeRef(prefix) {
  const d = new Date();
  const ymd = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  return `${prefix}-${ymd}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}
function money(n) {
  const c = S().currency;
  const num = Math.round(Number(n) || 0).toLocaleString('en-PK');
  return c.position === 'after' ? `${num} ${c.symbol}` : `${c.symbol} ${num}`;
}
function fmtDate(d, opts = { day: 'numeric', month: 'long', year: 'numeric' }) {
  if (!d) return '';
  const dt = new Date(d.length === 10 ? d + 'T00:00:00' : d);
  return isNaN(dt) ? '' : dt.toLocaleDateString('en-GB', opts);
}
const readMinutes = (html) => Math.max(1, Math.round(stripTags(html).split(' ').length / 200));
const clientIp = (req) => req.ip || req.socket?.remoteAddress || '';
const ipHash = (req) => sha256('ip:' + clientIp(req)).slice(0, 24);

function cleanHtml(html) {
  return sanitizeHtmlLib(String(html || ''), {
    allowedTags: ['h2', 'h3', 'h4', 'p', 'br', 'strong', 'b', 'em', 'i', 'u', 's', 'blockquote', 'ul', 'ol', 'li', 'a', 'img',
      'code', 'pre', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'figure', 'figcaption', 'span', 'div', 'mark', 'small', 'sub', 'sup'],
    allowedAttributes: { a: ['href', 'title', 'target', 'rel'], img: ['src', 'alt', 'title', 'width', 'height', 'loading'],
      td: ['colspan', 'rowspan'], th: ['colspan', 'rowspan'], '*': ['class'] },
    allowedClasses: { '*': ['note', 'tip', 'warning', 'lead', 'steps', 'align-center', 'wide'] },
    allowedSchemes: ['http', 'https', 'mailto', 'tel'], allowedSchemesByTag: { img: ['http', 'https'] },
    allowProtocolRelative: false,
    transformTags: {
      a: (tag, a) => ({ tagName: 'a', attribs: { ...a, rel: 'noopener noreferrer', ...(a.target ? { target: '_blank' } : {}) } }),
      img: (tag, a) => ({ tagName: 'img', attribs: { ...a, loading: 'lazy' } }),
      h1: 'h2',
    },
  });
}
const cleanText = (s, max = 500) => String(s ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, max);

function logActivity(req, action, entity, entityId, details) {
  try {
    q.run('INSERT INTO activity_logs (admin_id, actor, action, entity, entity_id, details, ip, created_at) VALUES (?,?,?,?,?,?,?,?)',
      req?.admin?.id || null, req?.admin ? req.admin.name : 'Website visitor', action, entity || null,
      entityId != null ? String(entityId) : null, details ? String(details).slice(0, 500) : null,
      req ? clientIp(req) : null, nowIso());
  } catch (e) { console.error('activity log failed', e.message); }
}

/* Validators used by public forms */
const V = {
  phone: (s) => /^[+]?[0-9][0-9\s-]{8,16}$/.test(String(s || '').trim()),
  email: (s) => /^[^\s@<>]{1,64}@[^\s@<>]{1,190}\.[a-z]{2,24}$/i.test(String(s || '').trim()),
  cnic: (s) => /^\d{5}-?\d{7}-?\d$/.test(String(s || '').trim()),
  date: (s) => /^\d{4}-\d{2}-\d{2}$/.test(String(s || '')) && !isNaN(new Date(s)),
};
const normCnic = (s) => { const d = String(s || '').replace(/\D/g, ''); return `${d.slice(0, 5)}-${d.slice(5, 12)}-${d.slice(12)}`; };
class HttpError extends Error { constructor(status, message, fields) { super(message); this.status = status; this.fields = fields; } }
function requireFields(body, spec) {
  const errors = {};
  for (const [name, label] of Object.entries(spec)) if (!String(body[name] ?? '').trim()) errors[name] = `${label} is required.`;
  if (Object.keys(errors).length) throw new HttpError(422, 'Please complete the required fields.', errors);
}

/* ===================== 5. DEFAULT SETTINGS & CONTENT ===================== */
const DEFAULT_SETTINGS = {
  general: {
    site_name: 'Smart Digital Services', short_name: 'SDS',
    tagline: 'IT Education, CCTV Solutions & Digital Services',
    logo: '', favicon: '', service_area: 'Punjab, Pakistan',
  },
  contact: {
    phone: '+92 300 0000000', email: 'support@smartdigitalservices.pk', whatsapp: '923000000000',
    address: 'Main Bazaar, Punjab, Pakistan', hours: 'Monday – Saturday, 9:00 AM – 7:00 PM',
    map_link: '', support_note: 'We usually reply to emails within one working day.',
  },
  social: { facebook: '', instagram: '', youtube: '', tiktok: '', linkedin: '', x: '' },
  seo: {
    meta_title: 'Smart Digital Services (SDS) — IT Education, CCTV & Digital Services in Punjab',
    meta_description: 'Smart Digital Services offers a Basic Computer Course, CCTV installation and maintenance across Punjab, a CCTV product catalogue with instant quotations, a technology blog and online application assistance.',
    keywords: 'computer course, CCTV installation Punjab, CCTV cameras price Pakistan, DVR NVR, Windows troubleshooting, Android tips',
    og_image: '', base_url: process.env.BASE_URL || '', google_verification: '',
  },
  footer: {
    about: 'Smart Digital Services (SDS) helps people and businesses across Punjab get more from technology — through practical computer training, reliable CCTV security systems and honest technical support.',
    copyright: '© {year} Smart Digital Services. All rights reserved.',
    note: 'SDS is a private service provider. We are not a government organisation.',
  },
  currency: { code: 'PKR', symbol: 'Rs', position: 'before' },
  charges: {
    installation_base: 2000, installation_per_camera: 1200, delivery_charge: 800, free_delivery_above: 60000,
    discount_percent: 0, discount_threshold: 0, quotation_validity_days: 7,
    terms: 'Prices are in Pakistani Rupees and are valid for 7 days from the quotation date.\nStock availability and prices are subject to change without prior notice.\nInstallation charges cover standard wall/ceiling mounting; extra cabling, conduits or civil work are charged separately after site survey.\nA site visit may be required to confirm the final quotation.\nWarranty is provided as per the manufacturer’s policy for each product.\nThis quotation is not a tax invoice.',
  },
  certificate: {
    title: 'Certificate of Completion', subtitle: 'This certificate is proudly presented to',
    body: 'for successfully completing the',
    footer_text: 'Issued by Smart Digital Services (SDS) — a private IT training and services provider.',
    signatory_name: 'Chief Executive Officer', signatory_title: 'Smart Digital Services',
    signature_image: '', logo: '', background_image: '', accent: '#1d4ed8', prefix: 'SDS', public_download: true,
  },
  smtp: { enabled: false, host: '', port: 587, secure: false, user: '', pass: '', from: '', notify_to: '' },
  blog: { posts_per_page: 9, comments_enabled: true, default_author: 'SDS Editorial Team' },
  scheme: {
    form_enabled: true, uploads_enabled: true,
    notice: 'Smart Digital Services is a private service provider offering application assistance only. We are NOT a government department, we are not affiliated with or approved by the Government of Punjab, and we cannot guarantee eligibility or approval. Final decisions are made solely by the relevant government authority.',
  },
  legal: { privacy_html: '', terms_html: '' },
};

const DEFAULT_HOME = {
  banner: { enabled: false, text: 'Admissions open for the Basic Computer Course — only Rs 300 per month.', link_text: 'Enrol now', link: '/course#enrol' },
  hero: {
    eyebrow: 'Technology services across Punjab',
    title: 'Smart technology support for homes, students & businesses',
    subtitle: 'From learning your first computer skills to securing your shop with HD CCTV — Smart Digital Services delivers practical, honest and affordable technology solutions.',
    primary_text: 'Explore Services', primary_link: '/services',
    secondary_text: 'Get a CCTV Quote', secondary_link: '/cctv/products',
    image: '',
    stat1_value: '15+', stat1_label: 'CCTV services offered',
    stat2_value: 'Rs 300', stat2_label: 'Monthly course fee',
    stat3_value: 'Punjab', stat3_label: 'Service coverage',
  },
  intro: {
    enabled: true, eyebrow: 'About SDS', title: 'One trusted partner for everyday technology',
    text: 'Smart Digital Services (SDS) is a technology services company built around a simple idea: technology should be easy to learn, safe to use and affordable to maintain. We teach practical computer skills, design and install CCTV security systems, publish free troubleshooting guides and help people complete online applications correctly.',
    points: 'Practical training with real computers\nCCTV installation, repair & maintenance\nTransparent quotations in PKR\nFriendly support in English and Urdu',
    image: '',
  },
  services: { enabled: true, eyebrow: 'What we do', title: 'Services built for real-world needs', subtitle: 'Everything we offer is designed to solve a practical problem — quickly, clearly and at a fair price.' },
  blog: { enabled: true, eyebrow: 'Smart Digital Blog', title: 'Free guides to fix everyday tech problems', subtitle: 'Step-by-step articles on Android phones, Windows computers and CCTV systems — written in plain language.' },
  course: {
    enabled: true, eyebrow: 'Basic Computer Course', title: 'Learn computer skills that open doors',
    text: 'A beginner-friendly course covering Windows, MS Office, the internet, email and online safety. Classes are hands-on, the fee is affordable and every successful student receives a verifiable SDS certificate.',
    button_text: 'View course details',
  },
  cctv: {
    enabled: true, eyebrow: 'CCTV Security Solutions', title: 'Professional CCTV installation & maintenance across Punjab',
    text: 'Homes, shops, offices, schools and warehouses — we survey your site, recommend the right cameras and recorders, install neatly and configure mobile viewing so you can check your property from anywhere.',
    button_text: 'Request a site visit',
  },
  products: { enabled: true, eyebrow: 'CCTV Product Catalogue', title: 'Choose your equipment, get an instant quotation', subtitle: 'Browse cameras, recorders and accessories, add them to your quotation and download a printable estimate in seconds.' },
  scheme: {
    enabled: true, eyebrow: 'Application Assistance', title: 'Apna Ghar Apni Chat — application assistance',
    text: 'Need help applying? Share your details with our team and we will guide you through the application process and help prepare your information. SDS provides assistance only — we are not a government body and approval is never guaranteed.',
    button_text: 'Request assistance',
  },
  team: { enabled: true, eyebrow: 'Our Team', title: 'The people behind Smart Digital Services', subtitle: 'A small, dedicated team of trainers, engineers and technicians who care about getting it right.' },
  certificate: {
    enabled: true, eyebrow: 'Verified Certificates', title: 'Certificates you can verify online',
    text: 'Every student who completes the Basic Computer Course receives a professionally designed certificate with a unique ID. Employers and institutions can confirm its authenticity instantly on our verification page.',
  },
  why: {
    enabled: true, eyebrow: 'Why choose SDS', title: 'Reasons people trust us with their technology',
    items: 'Honest advice | We recommend what you actually need — never the most expensive option by default.\nTransparent pricing | Clear quotations in PKR with no hidden charges.\nPractical training | Students learn by doing, on real computers, at their own pace.\nNeat, reliable installation | Tidy cabling, labelled connections and proper testing on every CCTV job.\nAfter-sales support | Maintenance, repairs and remote help when something stops working.\nPrivacy first | Personal information is stored securely and only used to provide the service you asked for.',
  },
  testimonials: { enabled: true, eyebrow: 'Testimonials', title: 'What our customers say' },
  contact: { enabled: true, eyebrow: 'Contact & Support', title: 'Talk to the SDS team', text: 'Have a question about a course, a CCTV system or an application? Send us a message or reach us on WhatsApp — we are happy to help.' },
  cta: { enabled: true, title: 'Ready to secure your property or start learning?', text: 'Get a free CCTV consultation or reserve your seat in the next computer course batch.', button_text: 'Contact us today', button_link: '/contact' },
};

let SETTINGS = {};
let HOME = {};
function loadSettings() {
  const rows = q.all('SELECT key, value FROM settings');
  const stored = {};
  for (const r of rows) { try { stored[r.key] = JSON.parse(r.value); } catch { /* ignore */ } }
  const out = {};
  for (const [k, def] of Object.entries(DEFAULT_SETTINGS)) out[k] = { ...def, ...(stored[k] || {}) };
  const home = {};
  for (const [k, def] of Object.entries(DEFAULT_HOME)) home[k] = { ...def, ...((stored.home || {})[k] || {}) };
  SETTINGS = out; HOME = home;
}
const S = () => SETTINGS;
function saveSettingGroup(key, value) {
  q.run('INSERT INTO settings (key, value, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at',
    key, JSON.stringify(value), nowIso());
  loadSettings();
}
function baseUrl(req) {
  const b = (S().seo.base_url || '').replace(/\/+$/, '');
  if (b) return b;
  return req ? `${req.protocol}://${req.get('host')}` : `http://localhost:${PORT}`;
}

/* ============================== 6. SEED DATA ============================== */
const SEED_BLOG_CATEGORIES = [
  { name: 'Smart Digital & Mobile Technology', slug: 'mobile-technology', icon: 'phone', description: 'Android troubleshooting, phone performance, battery, storage, WhatsApp, Google accounts, mobile security and everyday smartphone tips.' },
  { name: 'Computer & Windows Troubleshooting', slug: 'computer-windows', icon: 'monitor', description: 'Windows 10 and 11, installation, drivers, BIOS, boot problems, upgrades, networking, printers, virus protection and maintenance.' },
  { name: 'CCTV Camera Information', slug: 'cctv-cameras', icon: 'cctv', description: 'Choosing, installing and maintaining CCTV systems — DVR, NVR, IP and analog cameras, remote viewing, recording and troubleshooting.' },
];

const SEED_POSTS = [
  {
    cat: 'mobile-technology', featured: 1, title: 'Why Your Android Phone Is Slow — and 9 Fixes That Actually Work',
    tags: ['Android', 'Performance', 'Phone Tips'],
    excerpt: 'A slow phone is rarely “just old”. Learn the real causes of Android lag — full storage, heavy apps, outdated software — and how to fix each one in minutes.',
    content: `<p class="lead">If your Android phone takes ages to open apps, freezes while typing or heats up during simple tasks, the cause is usually fixable. Before you think about buying a new phone, work through these steps in order.</p>
<h2>1. Check your free storage first</h2>
<p>Android needs breathing room. When internal storage is more than about 90% full, the system struggles to create temporary files and everything slows down. Open <strong>Settings → Storage</strong> and aim to keep at least 10–15% free. Our storage clean-up guide explains exactly what is safe to delete.</p>
<h2>2. Restart the phone regularly</h2>
<p>A restart clears memory leaks and stuck background processes. Restarting once every few days is a simple habit that keeps most phones responsive.</p>
<h2>3. Update Android and your apps</h2>
<p>Go to <strong>Settings → System → Software update</strong> (the exact menu name differs by brand) and install pending updates. Then open the Play Store, tap your profile picture and choose <em>Manage apps &amp; device → Update all</em>. Updates often include performance and battery fixes.</p>
<h2>4. Remove apps you do not use</h2>
<p>Every installed app can run background services, send notifications and use storage. Uninstall apps you have not opened in a month. For apps you must keep, consider “Lite” versions which use less memory.</p>
<h2>5. Limit background activity</h2>
<p>Open <strong>Settings → Apps</strong>, choose a heavy app (social media apps are common culprits) and restrict its background battery use. This reduces both lag and battery drain.</p>
<h2>6. Clear the cache of problem apps</h2>
<p>If one app is slow, open its App info page and tap <em>Storage → Clear cache</em>. This removes temporary files without deleting your account or data. Avoid “Clear data” unless you know the app’s data is backed up.</p>
<h2>7. Replace live wallpapers and heavy launchers</h2>
<p>Animated wallpapers and widget-heavy home screens use processor time constantly. A static wallpaper and fewer widgets can make an older phone noticeably smoother.</p>
<h2>8. Reduce animation scale</h2>
<p>Enable Developer options (tap <em>Build number</em> seven times in <em>About phone</em>), then set Window, Transition and Animator scale to 0.5x. The phone does not become faster, but it <em>feels</em> much quicker.</p>
<h2>9. Factory reset as a last resort</h2>
<p>If the phone is still slow after all of the above, back up your photos, contacts and WhatsApp chats, then perform a factory reset. This returns the software to a clean state and solves most stubborn performance problems.</p>
<p class="tip"><strong>SDS tip:</strong> If your phone is still slow after a reset, the storage chip or battery may be wearing out. A technician can test the hardware before you spend money on a replacement.</p>`,
  },
  {
    cat: 'mobile-technology', title: 'Phone Storage Full? A Practical Clean-Up Guide for Android',
    tags: ['Android', 'Storage', 'WhatsApp'],
    excerpt: '“Storage space running out” is one of the most common phone problems. Here is a safe, step-by-step way to free several gigabytes without losing anything important.',
    content: `<p class="lead">Running out of storage stops your camera from saving photos, blocks app updates and slows the whole phone. The good news: most phones are full of files nobody needs.</p>
<h2>Find out what is using the space</h2>
<p>Open <strong>Settings → Storage</strong>. You will see a breakdown of images, videos, apps, audio and “other” files. Start with the largest category.</p>
<h2>WhatsApp media is usually the biggest culprit</h2>
<p>Forwarded videos, images and voice notes pile up quickly. In WhatsApp, open <strong>Settings → Storage and data → Manage storage</strong>. You can sort by size and delete large forwarded files in bulk. Then turn off automatic media download for mobile data and Wi-Fi so the problem does not return.</p>
<h2>Back up photos and videos</h2>
<p>Use Google Photos or copy your gallery to a computer or USB drive. Once you have confirmed the backup is complete, you can safely remove the local copies. Always check a few files open correctly before deleting anything.</p>
<h2>Clear app caches</h2>
<p>Browsers, social media and video apps keep large caches. Clearing the cache for these apps is safe and can free hundreds of megabytes each.</p>
<h2>Delete old downloads and duplicate files</h2>
<p>Open the <em>Files</em> app and check the Downloads folder — old PDFs, APK installers and duplicate images are common. The Files by Google app also suggests junk files and duplicates automatically.</p>
<h2>Move apps or files to an SD card</h2>
<p>If your phone supports a memory card, move photos, videos and music to it. Choose a reputable Class 10 / U1 card or better — very cheap cards are slow and fail more often.</p>
<p class="note"><strong>Keep it healthy:</strong> Try to keep at least 10–15% of storage free at all times. Phones with almost-full storage slow down and update less reliably.</p>`,
  },
  {
    cat: 'mobile-technology', title: 'WhatsApp Not Working? Step-by-Step Troubleshooting for Messages, Calls and Backups',
    tags: ['WhatsApp', 'Internet', 'Android'],
    excerpt: 'Messages stuck on one tick, calls not connecting or backups failing? Follow this checklist to identify whether the problem is your internet, the app or your phone settings.',
    content: `<p class="lead">When WhatsApp misbehaves, the problem is usually the internet connection, a permission setting or an outdated app. Work through these checks from the simplest to the most advanced.</p>
<h2>Messages stuck on one grey tick</h2>
<ul><li>Confirm your internet works by opening a website in your browser.</li><li>Switch between Wi-Fi and mobile data to see which connection is failing.</li><li>Turn Airplane mode on for ten seconds, then off again.</li><li>Check that Data Saver or battery saver is not blocking WhatsApp in the background.</li></ul>
<p>One tick means your message left your phone but has not reached the recipient. If it affects only one contact, their phone may simply be off or offline.</p>
<h2>Calls not connecting or poor quality</h2>
<p>Voice and video calls need a stable connection. Move closer to your Wi-Fi router, close video streaming apps and make sure WhatsApp has Microphone and Camera permissions under <strong>Settings → Apps → WhatsApp → Permissions</strong>.</p>
<h2>Not receiving notifications</h2>
<p>Open WhatsApp’s notification settings and confirm they are enabled. Then on the phone, check that battery optimisation is set to “Unrestricted” or “Not optimised” for WhatsApp. Many brands aggressively close background apps to save battery.</p>
<h2>Chat backup failing</h2>
<ul><li>Make sure you are signed in to a Google account with enough Google Drive space.</li><li>Use Wi-Fi for the first backup — they can be large.</li><li>Delete large media you no longer need to reduce backup size.</li></ul>
<h2>Update or reinstall the app</h2>
<p>Update WhatsApp from the Play Store. If problems continue, back up your chats first, then uninstall and reinstall. Never install WhatsApp versions from unofficial websites — modified apps can steal your data and may get your number banned.</p>
<p class="warning"><strong>Security reminder:</strong> Never share the six-digit WhatsApp verification code with anyone, even if they claim to be from WhatsApp, a bank or a delivery company. Turn on <em>Two-step verification</em> in Settings → Account.</p>`,
  },
  {
    cat: 'computer-windows', featured: 1, title: 'Windows 11 Running Slow? A Complete Speed-Up Checklist',
    tags: ['Windows 11', 'Windows 10', 'Performance'],
    excerpt: 'From startup apps to failing hard drives, here are the real reasons Windows slows down over time — and a practical checklist to make your PC fast again.',
    content: `<p class="lead">Windows rarely slows down for one single reason. Usually it is a combination of too many startup programs, low storage, outdated drivers and — very often — an old mechanical hard drive. Use this checklist from top to bottom.</p>
<h2>1. Check what is using your resources</h2>
<p>Press <strong>Ctrl + Shift + Esc</strong> to open Task Manager. Sort by CPU, Memory and Disk. If “Disk” sits at 100% for long periods, your hard drive is the bottleneck (see step 7).</p>
<h2>2. Disable unnecessary startup apps</h2>
<p>In Task Manager, open the <em>Startup apps</em> tab and disable programs you do not need immediately after login — chat apps, updaters, game launchers. Keep your antivirus enabled.</p>
<h2>3. Free up disk space</h2>
<p>Open <strong>Settings → System → Storage</strong> and turn on <em>Storage Sense</em>. Use <em>Cleanup recommendations</em> to remove temporary files and old Windows update files. Keep at least 15–20% of the C: drive free.</p>
<h2>4. Install Windows and driver updates</h2>
<p>Go to <strong>Settings → Windows Update</strong>, install all updates, then check <em>Advanced options → Optional updates</em> for driver updates. For graphics drivers, use the manufacturer’s official tool.</p>
<h2>5. Scan for malware</h2>
<p>Run a full scan in <strong>Windows Security → Virus &amp; threat protection</strong>. Malware, browser hijackers and crypto-miners can consume huge amounts of CPU in the background.</p>
<h2>6. Adjust power and visual settings</h2>
<p>On laptops, select the <em>Best performance</em> power mode while plugged in. On older PCs, search for “Adjust the appearance and performance of Windows” and choose <em>Adjust for best performance</em>.</p>
<h2>7. Upgrade to an SSD — the single biggest improvement</h2>
<p>If your computer still uses a mechanical hard disk (HDD), replacing it with a solid-state drive (SSD) can make boot times three to five times faster. This one upgrade often makes a five-year-old laptop feel new.</p>
<h2>8. Consider more RAM</h2>
<p>For Windows 11 with a browser and Office open, 8 GB is a practical minimum and 16 GB is comfortable. If Task Manager shows memory above 85% regularly, a RAM upgrade will help.</p>
<p class="tip"><strong>SDS tip:</strong> Before upgrading, check whether your laptop has a free RAM slot and which SSD type it supports (2.5-inch SATA or M.2 NVMe). Our technicians can check compatibility for you.</p>`,
  },
  {
    cat: 'computer-windows', title: 'SSD and RAM Upgrade Guide: The Best Value Boost for an Old Laptop',
    tags: ['SSD', 'RAM', 'Hardware', 'Laptop'],
    excerpt: 'Thinking of replacing your laptop? An SSD and RAM upgrade costs a fraction of a new machine. Learn what to buy, how to check compatibility and what to expect.',
    content: `<p class="lead">For most everyday users, a slow laptop does not need replacing — it needs a faster drive and enough memory. Here is how to plan a sensible upgrade.</p>
<h2>Why an SSD makes such a difference</h2>
<p>A traditional hard disk drive (HDD) reads data from a spinning platter. A solid-state drive (SSD) uses flash memory with no moving parts. The result: faster boot, near-instant app launches and a computer that no longer freezes when several programs open at once.</p>
<h2>Which SSD type do you need?</h2>
<ul><li><strong>2.5-inch SATA SSD</strong> — fits laptops and desktops that currently use a 2.5-inch hard disk. Widely compatible and affordable.</li><li><strong>M.2 SATA</strong> — a small stick-shaped drive; check your laptop’s manual to confirm support.</li><li><strong>M.2 NVMe</strong> — the fastest option for newer laptops with an NVMe-capable M.2 slot.</li></ul>
<h2>How much RAM is enough?</h2>
<table><thead><tr><th>Usage</th><th>Recommended RAM</th></tr></thead><tbody><tr><td>Browsing, email, Office</td><td>8 GB</td></tr><tr><td>Heavy multitasking, many browser tabs</td><td>16 GB</td></tr><tr><td>Photo/video editing, design</td><td>16–32 GB</td></tr></tbody></table>
<p>Check the RAM type (DDR3, DDR4 or DDR5), speed and number of slots before buying. Some thin laptops have memory soldered to the motherboard and cannot be upgraded.</p>
<h2>Moving your data</h2>
<p>You can either clone your old drive to the new SSD or perform a fresh Windows installation. A fresh installation usually gives the best performance, but remember to back up your documents, photos, browser bookmarks and licence keys first.</p>
<h2>What to expect after upgrading</h2>
<p>A typical laptop upgraded from HDD to SSD boots in under 20 seconds instead of one or two minutes. Combined with enough RAM, it becomes perfectly comfortable for study, office work and online classes.</p>
<p class="note"><strong>Good practice:</strong> Keep the old hard disk in an external USB enclosure — it makes an excellent backup drive.</p>`,
  },
  {
    cat: 'computer-windows', title: 'How to Fix Common Windows Boot Problems',
    tags: ['Windows 11', 'BIOS', 'Boot Problems', 'Troubleshooting'],
    excerpt: 'Black screen, “Automatic Repair” loop or “No bootable device”? Learn what each boot error means and the safe steps to try before taking your PC to a technician.',
    content: `<p class="lead">Boot problems are stressful because the computer will not even reach the desktop. The key is to identify <em>where</em> the start-up process fails.</p>
<h2>No power, no lights</h2>
<p>Check the power cable, wall socket and, for desktops, the switch on the back of the power supply. For laptops, remove the charger, hold the power button for 30 seconds, reconnect the charger and try again.</p>
<h2>Fans spin but the screen stays black</h2>
<ul><li>For desktops, make sure the monitor cable is connected to the graphics card if one is installed.</li><li>Remove and re-seat RAM sticks — loose memory is a very common cause.</li><li>Disconnect USB devices; a faulty device can block the start-up.</li></ul>
<h2>“No bootable device” or “Operating system not found”</h2>
<p>This means the computer cannot find a drive with Windows on it. Enter the BIOS/UEFI setup (usually F2, F10, F12 or Del during power-on) and confirm the correct drive is first in the boot order. If the drive is not detected at all, it may have failed or become disconnected.</p>
<h2>Stuck in the “Automatic Repair” loop</h2>
<p>From the blue recovery screen choose <strong>Advanced options → Troubleshoot</strong>. Try these in order:</p>
<ol><li><em>Startup Repair</em></li><li><em>Uninstall Updates</em> — remove the latest quality update</li><li><em>System Restore</em> — return to an earlier restore point</li><li><em>Startup Settings → Safe Mode</em> to remove a recently installed driver or program</li></ol>
<h2>Blue screen errors (BSOD)</h2>
<p>Write down the stop code shown on the screen. Codes mentioning memory suggest a RAM issue; “INACCESSIBLE_BOOT_DEVICE” often relates to storage or BIOS storage-mode settings; driver names point to the faulty driver.</p>
<p class="warning"><strong>Protect your data:</strong> If the drive makes clicking noises or repeatedly disappears, stop trying to repair Windows. Continued use can make data recovery impossible. Have the drive checked and your files recovered first.</p>`,
  },
  {
    cat: 'cctv-cameras', featured: 1, title: 'DVR vs NVR: Which CCTV Recorder Is Right for Your Home or Shop?',
    tags: ['DVR', 'NVR', 'IP Camera', 'CCTV Basics'],
    excerpt: 'DVR and NVR systems both record CCTV footage, but they work very differently. Understand cabling, picture quality, cost and expandability before you buy.',
    content: `<p class="lead">The recorder is the heart of every CCTV system. Choosing between a DVR and an NVR decides which cameras you can use, how they are wired and how easily the system can grow.</p>
<h2>What is a DVR?</h2>
<p>A <strong>Digital Video Recorder (DVR)</strong> works with analog HD cameras (often called AHD, TVI or CVI). Each camera connects to the DVR with a coaxial cable using BNC connectors, plus a separate power cable — commonly bundled together as “3+1” CCTV cable.</p>
<ul><li>Lower overall cost, especially for 4–8 camera systems</li><li>Simple, proven technology</li><li>Ideal for upgrading older systems that already have coaxial cabling</li></ul>
<h2>What is an NVR?</h2>
<p>A <strong>Network Video Recorder (NVR)</strong> works with IP cameras. Each camera connects through a network cable (Cat6 is recommended). With a PoE (Power over Ethernet) NVR or switch, one cable carries both video and power.</p>
<ul><li>Higher resolutions and better image processing</li><li>Smart features such as human and vehicle detection on many models</li><li>Flexible cabling through network switches — easier to expand</li></ul>
<h2>Side-by-side comparison</h2>
<table><thead><tr><th></th><th>DVR (Analog HD)</th><th>NVR (IP)</th></tr></thead><tbody><tr><td>Cable</td><td>Coaxial + power</td><td>Cat6 network (PoE)</td></tr><tr><td>Typical resolution</td><td>2MP–5MP</td><td>4MP–8MP and above</td></tr><tr><td>Initial cost</td><td>Lower</td><td>Moderate to higher</td></tr><tr><td>Smart detection</td><td>Basic on most models</td><td>Advanced on many models</td></tr><tr><td>Best for</td><td>Homes, small shops, budget systems</td><td>Offices, larger sites, future expansion</td></tr></tbody></table>
<h2>Our recommendation</h2>
<p>For a small home or shop with four cameras and a limited budget, a good 2MP or 5MP DVR system is excellent value. For businesses, schools or anyone who wants sharper images and room to expand, an IP camera and NVR system is the better long-term investment.</p>
<p class="tip"><strong>Planning tip:</strong> Always buy a recorder with more channels than you need today — an 8-channel unit for 5 cameras leaves space to add more later.</p>`,
  },
  {
    cat: 'cctv-cameras', title: 'How to Choose the Right CCTV Camera: Resolution, Dome, Bullet or PTZ',
    tags: ['CCTV Basics', 'Camera Selection', 'Security'],
    excerpt: 'More megapixels is not always better. Learn how resolution, lens size, night vision and camera style affect what you actually see on screen.',
    content: `<p class="lead">The best CCTV camera is the one that clearly captures what matters at each location — a face at the door, a number plate at the gate or the cash counter in a shop.</p>
<h2>Resolution: 2MP, 5MP or 8MP?</h2>
<ul><li><strong>2MP (1080p)</strong> — good general coverage for small rooms, corridors and entrances at short distance.</li><li><strong>5MP</strong> — noticeably sharper detail; a popular balance of quality and storage use.</li><li><strong>8MP (4K)</strong> — excellent detail for large areas such as parking lots and warehouses, but needs more storage and a compatible recorder.</li></ul>
<h2>Lens size and field of view</h2>
<p>A <strong>2.8 mm</strong> lens shows a wide area but less detail at a distance. A <strong>6 mm</strong> or longer lens shows a narrower view with more detail further away. Use wide lenses inside rooms and longer lenses for gates and driveways.</p>
<h2>Camera styles</h2>
<ul><li><strong>Dome cameras</strong> — discreet, vandal-resistant and ideal for ceilings inside shops, offices and homes.</li><li><strong>Bullet cameras</strong> — visible deterrent for outdoor walls, gates and boundaries; usually better long-range night vision.</li><li><strong>PTZ cameras</strong> — pan, tilt and zoom remotely to follow activity across large open areas.</li></ul>
<h2>Night vision</h2>
<p>Standard infrared (IR) cameras record black-and-white video at night. “Full colour” or warm-light cameras record colour at night using a small built-in light — useful where identifying clothing or vehicle colour matters.</p>
<h2>Weather and placement</h2>
<p>Outdoor cameras should be rated at least IP66 for dust and water resistance. Mount cameras around 2.5–3 metres high, avoid pointing directly at bright lights or the sun, and make sure faces are captured from the front at entrances.</p>
<p class="note"><strong>Free advice:</strong> Our technicians can survey your property and suggest the right camera for each location — so you only pay for what you need.</p>`,
  },
  {
    cat: 'cctv-cameras', title: 'CCTV Not Recording? Hard Disk and Recording Problems Explained',
    tags: ['DVR', 'NVR', 'Hard Disk', 'Troubleshooting'],
    excerpt: 'Live view works but there is no playback? Discover the most common causes of CCTV recording failures — from hard disk errors to incorrect schedules — and how to fix them.',
    content: `<p class="lead">Many people only discover their CCTV was not recording after an incident. A few minutes of regular checks can prevent that from ever happening to you.</p>
<h2>Check the hard disk status</h2>
<p>Open the recorder’s menu and go to <strong>Storage</strong> or <strong>HDD Management</strong>. The disk should show as “Normal”. Statuses such as “Uninitialised”, “Error” or “Unformatted” mean the recorder cannot save video.</p>
<ul><li><strong>Uninitialised:</strong> a new disk must be formatted inside the recorder before use (this erases it).</li><li><strong>Error or not detected:</strong> check the SATA and power cables inside the recorder; the disk may be failing.</li></ul>
<h2>Confirm the recording schedule</h2>
<p>Each camera needs a recording schedule. Check that it is set to continuous recording or motion recording for all days and hours. After a reset or firmware update, schedules sometimes return to default.</p>
<h2>Enable overwrite</h2>
<p>When the disk is full, the recorder should overwrite the oldest footage. If <em>Overwrite</em> is disabled, recording stops once the disk fills up.</p>
<h2>Use a surveillance-grade hard disk</h2>
<p>CCTV recorders write video 24 hours a day. Surveillance-rated drives are designed for this workload and last much longer than ordinary desktop drives. As a rough guide, a 1 TB disk stores about 10–15 days of continuous 2MP footage from four cameras, depending on compression and motion.</p>
<h2>Power problems</h2>
<p>Frequent power cuts can corrupt recordings and damage disks. A UPS or a stable power supply for the recorder and cameras protects your system and keeps it recording during short outages.</p>
<h2>Check the date and time</h2>
<p>An incorrect date makes footage hard to find. Enable NTP time sync on the recorder or set the date and time manually after power failures.</p>
<p class="tip"><strong>Maintenance habit:</strong> Once a week, play back a few minutes of recording from each camera. It takes two minutes and confirms the system is working when you need it most.</p>`,
  },
];

const SEED_COURSE = {
  name: 'Basic Computer Course', slug: 'basic-computer-course',
  tagline: 'Practical computer skills for study, work and everyday life.',
  description: 'The SDS Basic Computer Course is designed for complete beginners, students, job seekers, shopkeepers and anyone who wants to use a computer confidently. Every class is hands-on: you learn a skill, then practise it straight away on a real computer with guidance from our trainers. By the end of the course you will be able to manage files, create professional documents and spreadsheets, prepare presentations, use the internet and email safely and solve common computer problems on your own.',
  objectives: 'Understand computer parts and how they work together\nUse Windows confidently to manage files, folders and settings\nCreate and format documents in Microsoft Word\nBuild spreadsheets with formulas and charts in Microsoft Excel\nDesign clear presentations in Microsoft PowerPoint\nBrowse the internet, search effectively and use email professionally\nStay safe online and protect personal information\nFix everyday computer problems without help',
  syllabus: 'Introduction to Computers | What a computer is, types of computers, uses in daily life and work.\nComputer Hardware | CPU, RAM, storage, monitor, printer and other parts — what each one does.\nKeyboard and Mouse | Typing practice, shortcuts, mouse skills and efficient navigation.\nWindows Basics | Desktop, Start menu, taskbar, settings, user accounts and shutting down safely.\nFile and Folder Management | Creating, renaming, copying, moving and organising files; USB drives.\nMicrosoft Word | Typing, formatting, tables, images, page layout, CVs, letters and printing.\nMicrosoft Excel | Cells, formulas, functions, formatting, simple charts and practical worksheets.\nMicrosoft PowerPoint | Slides, layouts, images, transitions and presenting with confidence.\nInternet Basics | Browsers, searching effectively, downloading safely and using online services.\nEmail | Creating an account, writing professional emails, attachments and organising the inbox.\nInternet Safety | Strong passwords, scams, phishing, privacy settings and safe social media use.\nBasic Troubleshooting | Fixing slow PCs, printer problems, internet issues and common errors.\nPractical Computer Skills | Real-world tasks: online forms, scanning documents, and a final practical project.',
  fee: 300, fee_period: 'month', duration: '3 months (flexible)',
  schedule: 'Morning, afternoon and evening batches available. Classes run Monday to Saturday.',
  requirements: 'No prior experience needed. Students should be able to read basic English or Urdu. Minimum age 10 years.',
};

const SEED_SERVICES = [
  ['main', 'Basic Computer Course', 'book', 'Hands-on computer training for beginners — Windows, MS Office, internet and email — for only Rs 300 per month.', '/course'],
  ['main', 'CCTV Installation & Maintenance', 'cctv', 'Site survey, professional installation, configuration, repair and maintenance of CCTV systems across Punjab.', '/cctv'],
  ['main', 'CCTV Products & Quotations', 'cart', 'Browse cameras, DVRs, NVRs and accessories and generate a printable quotation instantly.', '/cctv/products'],
  ['main', 'Computer & Laptop Support', 'monitor', 'Windows installation, software setup, upgrades, virus removal and troubleshooting for PCs and laptops.', '/contact'],
  ['main', 'Mobile Technology Guidance', 'phone', 'Practical help and free guides for Android problems, storage, battery, WhatsApp and phone security.', '/blog/category/mobile-technology'],
  ['main', 'Online Application Assistance', 'file', 'Guidance and help preparing online applications, including the Apna Ghar Apni Chat scheme.', '/apna-ghar-apni-chat'],
  ['cctv', 'CCTV Installation', 'cctv', 'Complete installation of camera systems for homes, shops, offices and warehouses.'],
  ['cctv', 'CCTV Camera Configuration', 'settings', 'Image settings, motion detection, recording schedules and user accounts.'],
  ['cctv', 'DVR Installation', 'server', 'Setup of analog HD recorders with neat cabling and hard disk configuration.'],
  ['cctv', 'NVR Installation', 'server', 'IP recorder setup with PoE switching and network configuration.'],
  ['cctv', 'IP Camera Setup', 'globe', 'Network camera installation, addressing and smart detection features.'],
  ['cctv', 'Remote Mobile Viewing', 'phone', 'Watch your cameras live on Android or iPhone from anywhere.'],
  ['cctv', 'CCTV Networking', 'wifi', 'Router, switch and cabling setup for reliable recording and remote access.'],
  ['cctv', 'Camera Repair', 'wrench', 'Diagnosis and repair of faulty cameras, connectors, adapters and cables.'],
  ['cctv', 'DVR/NVR Troubleshooting', 'cpu', 'Fixing recording failures, no-video errors, password and playback issues.'],
  ['cctv', 'Hard Disk Replacement', 'drive', 'Surveillance-grade hard disk supply, installation and formatting.'],
  ['cctv', 'Camera Maintenance', 'shield', 'Scheduled health checks to keep your system recording reliably.'],
  ['cctv', 'CCTV Cleaning', 'eye', 'Lens and housing cleaning for clear day and night images.'],
  ['cctv', 'CCTV System Upgrades', 'layers', 'Upgrade old analog systems to HD or IP without starting from scratch.'],
  ['cctv', 'Security Camera Consultation', 'chat', 'Expert advice on coverage, camera types and budget planning.'],
  ['cctv', 'New CCTV System Installation', 'plus', 'Complete turnkey systems — equipment, installation, testing and training.'],
];

const SEED_PRODUCT_CATEGORIES = [
  ['Cameras', 'cameras', 'cctv'], ['Recorders (DVR / NVR)', 'recorders', 'server'], ['Storage', 'storage', 'drive'],
  ['Power & Networking', 'power-networking', 'wifi'], ['Cables & Connectors', 'cables-connectors', 'layers'], ['Accessories & Kits', 'accessories', 'wrench'],
];
// [name, category, price, unit, installable, featured, short description, specs]
const SEED_PRODUCTS = [
  ['2MP HD CCTV Camera (1080p)', 'cameras', 4200, 'piece', 1, 1, 'Reliable 1080p analog HD camera for homes and shops.', 'Resolution: 2MP 1080p\nNight vision: up to 20 m IR\nLens: 3.6 mm\nWeather rating: IP66'],
  ['5MP HD CCTV Camera', 'cameras', 6800, 'piece', 1, 1, 'Sharper detail for entrances, counters and outdoor areas.', 'Resolution: 5MP\nNight vision: up to 25 m IR\nLens: 3.6 mm\nWeather rating: IP66'],
  ['8MP 4K CCTV Camera', 'cameras', 12500, 'piece', 1, 0, 'Ultra-HD 4K detail for large areas and parking lots.', 'Resolution: 8MP (4K)\nNight vision: up to 30 m\nLens: 2.8 mm\nWeather rating: IP67'],
  ['4MP IP Network Camera (PoE)', 'cameras', 10500, 'piece', 1, 1, 'IP camera with PoE and smart human/vehicle detection.', 'Resolution: 4MP\nPower: PoE 802.3af\nSmart detection: Human & vehicle\nWeather rating: IP67'],
  ['2MP Dome Camera (Indoor)', 'cameras', 3900, 'piece', 1, 0, 'Discreet ceiling dome camera for indoor coverage.', 'Resolution: 2MP\nNight vision: up to 20 m\nLens: 2.8 mm wide angle\nHousing: Indoor dome'],
  ['5MP Bullet Camera (Outdoor)', 'cameras', 7200, 'piece', 1, 0, 'Weatherproof bullet camera with long-range night vision.', 'Resolution: 5MP\nNight vision: up to 40 m\nLens: 6 mm\nWeather rating: IP67'],
  ['4MP PTZ Camera (25x Zoom)', 'cameras', 46000, 'piece', 1, 0, 'Pan, tilt and zoom camera for large open areas.', 'Resolution: 4MP\nOptical zoom: 25x\nRotation: 360° pan\nNight vision: up to 100 m'],
  ['4-Channel DVR (5MP Lite)', 'recorders', 8500, 'piece', 0, 1, 'Compact recorder for up to 4 analog HD cameras.', 'Channels: 4\nSupports: Up to 5MP Lite\nHDD bays: 1 (up to 8 TB)\nMobile viewing: Yes'],
  ['8-Channel DVR (5MP)', 'recorders', 14500, 'piece', 0, 0, 'Recorder for growing systems with up to 8 cameras.', 'Channels: 8\nSupports: Up to 5MP\nHDD bays: 1 (up to 10 TB)\nMobile viewing: Yes'],
  ['8-Channel NVR (4K)', 'recorders', 17500, 'piece', 0, 0, 'Network video recorder for IP camera systems.', 'Channels: 8 IP\nSupports: Up to 8MP\nHDD bays: 1\nSmart playback: Yes'],
  ['1TB Surveillance Hard Drive', 'storage', 13500, 'piece', 0, 0, '24/7-rated hard disk designed for CCTV recording.', 'Capacity: 1 TB\nRated: 24/7 surveillance\nInterface: SATA'],
  ['2TB Surveillance Hard Drive', 'storage', 18500, 'piece', 0, 0, 'Longer recording history for multi-camera systems.', 'Capacity: 2 TB\nRated: 24/7 surveillance\nInterface: SATA'],
  ['12V 10A CCTV Power Supply', 'power-networking', 3200, 'piece', 0, 0, 'Centralised power supply for up to 8 cameras.', 'Output: 12V DC, 10A\nChannels: 9 outputs\nProtection: Short-circuit'],
  ['8-Port PoE Switch', 'power-networking', 9500, 'piece', 0, 0, 'Powers and connects up to 8 IP cameras.', 'PoE ports: 8\nUplink: 2 x Gigabit\nPoE budget: 120 W'],
  ['BNC Connectors (Pack of 10)', 'cables-connectors', 550, 'pack', 0, 0, 'Twist-on BNC connectors for coaxial cable.', 'Quantity: 10 pieces\nType: Twist-on'],
  ['CCTV Cable 3+1 (90 m Roll)', 'cables-connectors', 6200, 'roll', 0, 0, 'Combined video and power cable for analog cameras.', 'Length: 90 m\nType: Coaxial + 2-core power'],
  ['Cat6 Network Cable (305 m Box)', 'cables-connectors', 17000, 'box', 0, 0, 'Pure-copper Cat6 cable for IP camera systems.', 'Length: 305 m\nCategory: Cat6 UTP'],
  ['CCTV Installation Kit', 'accessories', 2400, 'kit', 0, 0, 'Clips, screws, wall plugs, junction boxes and ties.', 'Includes: Cable clips, junction boxes, screws, wall plugs, cable ties'],
  ['Camera Mounting Brackets (Set of 2)', 'accessories', 650, 'set', 0, 0, 'Wall and pole brackets for bullet and dome cameras.', 'Material: Aluminium\nQuantity: 2'],
  ['Connectors & Accessories Pack', 'accessories', 1200, 'pack', 0, 0, 'DC jacks, power splitters, baluns and tape.', 'Includes: DC connectors, 1-to-4 splitter, insulation tape'],
];

const SEED_TEAM = [
  ['Team Member Name', 'Chief Executive Officer (CEO)', 'Leads Smart Digital Services with a focus on honest advice, quality work and making technology accessible to everyone in Punjab.'],
  ['Team Member Name', 'Assistant', 'Coordinates appointments, course admissions and customer communication so every request is followed up on time.'],
  ['Team Member Name', 'Software Engineer', 'Builds and maintains our digital systems and helps clients with software, websites and online services.'],
  ['Team Member Name', 'IT Technician / Technical Support Specialist', 'Installs and maintains CCTV systems, repairs computers and provides on-site and remote technical support.'],
];

const DEFAULT_PRIVACY = `<h2>Introduction</h2><p>Smart Digital Services (“SDS”, “we”, “us”) respects your privacy. This policy explains what information we collect through this website, why we collect it and how we protect it.</p>
<h2>Information we collect</h2><ul><li><strong>Contact and enquiry forms:</strong> name, email, phone number and your message.</li><li><strong>Course enrolment:</strong> student name, father’s name, phone, city, address and education level.</li><li><strong>CCTV service requests and quotations:</strong> name, phone, city, address and the products or services you select.</li><li><strong>Application assistance forms:</strong> name, father’s name, CNIC number, contact numbers, address, household information and any documents you choose to upload.</li></ul>
<h2>How we use your information</h2><p>We use your information only to respond to your request, provide the service you asked for, issue certificates, prepare quotations and contact you about your enquiry. We do not sell or rent your personal information.</p>
<h2>Sensitive information</h2><p>CNIC numbers are encrypted in our database. Submitted documents are stored privately and are accessible only to authorised SDS staff. Application assistance information is used solely to help you prepare and submit your application manually, with your consent.</p>
<h2>Data retention</h2><p>We keep information only as long as necessary to provide our services or meet legal obligations. You may request deletion of your data at any time by contacting us.</p>
<h2>Cookies</h2><p>This website uses essential cookies for security (form protection) and admin login. A small amount of browser storage remembers the items in your quotation cart. We do not use advertising trackers.</p>
<h2>Your rights</h2><p>You may ask us to access, correct or delete your personal information. Contact us using the details on our Contact page.</p>`;

const DEFAULT_TERMS = `<h2>Use of this website</h2><p>By using this website you agree to these terms. Content is provided for general information and education. While we take care to keep guides accurate, you follow troubleshooting instructions at your own risk; back up your data before making changes to any device.</p>
<h2>Courses</h2><p>Course fees, schedules and syllabus may change. Certificates are issued only to students who complete the course requirements. Certificates issued by Smart Digital Services are private training certificates and can be verified on this website.</p>
<h2>CCTV products and quotations</h2><p>Quotations generated on this website are estimates and are not tax invoices. Prices, stock and specifications are subject to change. Final pricing may depend on a site survey.</p>
<h2>Application assistance</h2><p>Smart Digital Services provides application assistance only. We are not a government authority, are not affiliated with any government department and do not guarantee eligibility, approval or any outcome. Applicants are responsible for the accuracy of information they provide.</p>
<h2>Limitation of liability</h2><p>To the extent permitted by law, SDS is not liable for indirect losses arising from use of this website or its content.</p>
<h2>Contact</h2><p>Questions about these terms can be sent through our Contact page.</p>`;

function seedDatabase() {
  const t = nowIso();
  if (!q.val('SELECT COUNT(*) FROM settings WHERE key = ?', 'legal')) {
    saveSettingGroup('legal', { privacy_html: DEFAULT_PRIVACY, terms_html: DEFAULT_TERMS });
  }
  if (!q.val('SELECT COUNT(*) FROM blog_categories')) {
    tx(() => {
      SEED_BLOG_CATEGORIES.forEach((c, i) => q.run('INSERT INTO blog_categories (name, slug, description, icon, sort_order, created_at, updated_at) VALUES (?,?,?,?,?,?,?)', c.name, c.slug, c.description, c.icon, i, t, t));
      const base = Date.now();
      SEED_POSTS.forEach((p, i) => {
        const catId = q.val('SELECT id FROM blog_categories WHERE slug = ?', p.cat);
        const pub = new Date(base - (SEED_POSTS.length - i) * 2.5 * 86400000).toISOString();
        const r = q.run(`INSERT INTO blog_posts (title, slug, excerpt, content, category_id, author, status, featured, seo_title, meta_description, published_at, created_at, updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.title, slugify(p.title), p.excerpt, p.content, catId, 'SDS Editorial Team', 'published',
          p.featured || 0, p.title + ' | SDS Blog', p.excerpt.slice(0, 158), pub, pub, pub);
        setPostTags(Number(r.lastInsertRowid), p.tags);
      });
    });
  }
  if (!q.val('SELECT COUNT(*) FROM courses')) {
    const c = SEED_COURSE;
    q.run(`INSERT INTO courses (name, slug, tagline, description, objectives, syllabus, fee, fee_period, duration, schedule, requirements, enrollment_open, active, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,1,1,?,?)`, c.name, c.slug, c.tagline, c.description, c.objectives, c.syllabus, c.fee, c.fee_period, c.duration, c.schedule, c.requirements, t, t);
  }
  if (!q.val('SELECT COUNT(*) FROM services')) {
    tx(() => SEED_SERVICES.forEach(([grp, title, icon, summary, link], i) =>
      q.run('INSERT INTO services (grp, title, slug, icon, summary, link, sort_order, active, created_at, updated_at) VALUES (?,?,?,?,?,?,?,1,?,?)',
        grp, title, slugify(title), icon, summary, link || null, i, t, t)));
  }
  if (!q.val('SELECT COUNT(*) FROM product_categories')) {
    tx(() => {
      SEED_PRODUCT_CATEGORIES.forEach(([name, slug, icon], i) => q.run('INSERT INTO product_categories (name, slug, icon, sort_order, created_at, updated_at) VALUES (?,?,?,?,?,?)', name, slug, icon, i, t, t));
      SEED_PRODUCTS.forEach(([name, cat, price, unit, inst, feat, short, specs], i) => {
        const catId = q.val('SELECT id FROM product_categories WHERE slug = ?', cat);
        q.run(`INSERT INTO products (name, slug, sku, category_id, short_description, description, specs, price, unit, stock_status, stock_qty, installable, featured, active, sort_order, created_at, updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)`, name, slugify(name), `SDS-${String(i + 1).padStart(3, '0')}`, catId, short,
          `${short} Demo product — price, description and image can be edited from the admin dashboard.`, specs, price, unit, 'in_stock', 20, inst, feat, i, t, t);
      });
    });
  }
  if (!q.val('SELECT COUNT(*) FROM team_members')) {
    tx(() => SEED_TEAM.forEach(([name, position, bio], i) => q.run('INSERT INTO team_members (name, position, bio, sort_order, active, created_at, updated_at) VALUES (?,?,?,?,1,?,?)', name, position, bio, i, t, t)));
  }
}

function setPostTags(postId, tags) {
  const list = (Array.isArray(tags) ? tags : String(tags || '').split(',')).map((x) => cleanText(x, 40)).filter(Boolean);
  q.run('DELETE FROM blog_post_tags WHERE post_id = ?', postId);
  for (const name of [...new Set(list)].slice(0, 15)) {
    const slug = slugify(name);
    let tagId = q.val('SELECT id FROM blog_tags WHERE slug = ?', slug);
    if (!tagId) tagId = Number(q.run('INSERT INTO blog_tags (name, slug, created_at, updated_at) VALUES (?,?,?,?)', name, slug, nowIso(), nowIso()).lastInsertRowid);
    q.run('INSERT OR IGNORE INTO blog_post_tags (post_id, tag_id) VALUES (?,?)', postId, tagId);
  }
}
const postTags = (postId) => q.all('SELECT t.* FROM blog_tags t JOIN blog_post_tags pt ON pt.tag_id = t.id WHERE pt.post_id = ? ORDER BY t.name', postId);

loadSettings();
seedDatabase();
loadSettings();

/* ========================= 7. SECURITY MIDDLEWARE ========================= */
const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY && process.env.TRUST_PROXY !== '0') {
  const tp = process.env.TRUST_PROXY;
  app.set('trust proxy', /^\d+$/.test(tp) ? parseInt(tp, 10) : tp === 'true' ? true : tp);
} else if (ON_VERCEL) app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'], connectSrc: ["'self'"],
      frameAncestors: ["'self'"], formAction: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"],
      upgradeInsecureRequests: IS_PROD ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: IS_PROD ? { maxAge: 15552000 } : false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) { try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch { /* ignore */ } }
  });
  return out;
}
// Double-submit CSRF token: random value in an httpOnly cookie, echoed by pages in a <meta> tag.
app.use((req, res, next) => {
  req.cookies = parseCookies(req.headers.cookie);
  let token = req.cookies.sds_csrf;
  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    token = randomToken(32);
    res.cookie('sds_csrf', token, { httpOnly: true, sameSite: 'lax', secure: req.secure, path: '/' });
  }
  req.csrfToken = token;
  next();
});
function csrfCheck(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  if (origin) {
    let host = '';
    try { host = new URL(origin).host; } catch { /* invalid */ }
    if (host !== req.get('host')) return res.status(403).json({ ok: false, error: 'Cross-site request blocked.' });
  }
  const sent = req.get('x-csrf-token') || (req.body && req.body._csrf);
  if (!safeEqual(sent, req.csrfToken)) return res.status(403).json({ ok: false, error: 'Your security token has expired. Please refresh the page and try again.' });
  next();
}

const rlStore = new Map();
function rateLimit({ name, windowMs, max, keyFn }) {
  return (req, res, next) => {
    const key = `${name}:${keyFn ? keyFn(req) : clientIp(req)}`;
    const now = Date.now();
    let e = rlStore.get(key);
    if (!e || e.reset < now) { e = { count: 0, reset: now + windowMs }; rlStore.set(key, e); }
    e.count++;
    if (e.count > max) {
      res.set('Retry-After', String(Math.ceil((e.reset - now) / 1000)));
      return res.status(429).json({ ok: false, error: 'Too many attempts. Please wait a few minutes and try again.' });
    }
    next();
  };
}
setInterval(() => {
  const n = Date.now();
  for (const [k, v] of rlStore) if (v.reset < n) rlStore.delete(k);
  q.run('DELETE FROM sessions WHERE expires_at < ? OR last_seen < ?', n, n - SESSION_IDLE_MS);
}, 60 * 1000).unref();
const formLimiter = rateLimit({ name: 'form', windowMs: 10 * 60 * 1000, max: 12 });

/* Admin sessions (random token in cookie, SHA-256 of token stored in DB) */
function createSession(req, res, admin) {
  const token = randomToken(32), n = Date.now();
  q.run('INSERT INTO sessions (id, admin_id, created_at, last_seen, expires_at, ip, user_agent) VALUES (?,?,?,?,?,?,?)',
    sha256(token), admin.id, n, n, n + SESSION_MAX_MS, clientIp(req), (req.get('user-agent') || '').slice(0, 200));
  res.cookie('sds_admin', token, { httpOnly: true, sameSite: 'strict', secure: req.secure, path: '/', maxAge: SESSION_MAX_MS });
}
function loadSession(req) {
  const tok = req.cookies.sds_admin;
  if (!tok || !/^[a-f0-9]{64}$/.test(tok)) return null;
  const s = q.get('SELECT s.*, a.name, a.email, a.role, a.active FROM sessions s JOIN admin_users a ON a.id = s.admin_id WHERE s.id = ?', sha256(tok));
  if (!s) return null;
  const n = Date.now();
  if (s.expires_at < n || s.last_seen + SESSION_IDLE_MS < n || !s.active) { q.run('DELETE FROM sessions WHERE id = ?', s.id); return null; }
  if (n - s.last_seen > 30000) q.run('UPDATE sessions SET last_seen = ? WHERE id = ?', n, s.id);
  return { id: s.admin_id, name: s.name, email: s.email, role: s.role, sessionId: s.id };
}
function requireAdmin(req, res, next) {
  const a = loadSession(req);
  res.set('Cache-Control', 'no-store');
  if (!a) {
    if (req.originalUrl.startsWith('/admin/api/')) return res.status(401).json({ ok: false, error: 'Your session has expired. Please log in again.' });
    return res.redirect('/admin/login?next=' + encodeURIComponent(req.originalUrl));
  }
  req.admin = a;
  next();
}

/* Uploads: memory → magic-byte validation → random filename on disk */
const memUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_DOC_BYTES, files: 5, fields: 80, fieldSize: 200 * 1024 } });
function sniffFile(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { ext: 'jpg', mime: 'image/jpeg' };
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { ext: 'png', mime: 'image/png' };
  if (buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'WEBP') return { ext: 'webp', mime: 'image/webp' };
  const g = buf.subarray(0, 6).toString('latin1');
  if (g === 'GIF87a' || g === 'GIF89a') return { ext: 'gif', mime: 'image/gif' };
  if (buf.subarray(0, 5).toString('latin1') === '%PDF-') return { ext: 'pdf', mime: 'application/pdf' };
  if (buf[0] === 0 && buf[1] === 0 && buf[2] === 1 && buf[3] === 0) return { ext: 'ico', mime: 'image/x-icon' };
  return null;
}
const IMAGE_TYPES = ['jpg', 'png', 'webp', 'gif'];
function storeFile(file, { allowed = IMAGE_TYPES, dir = 'images', maxBytes = MAX_IMAGE_BYTES } = {}) {
  if (!file) return null;
  if (file.size > maxBytes) throw new HttpError(413, `"${cleanText(file.originalname, 80)}" is too large. Maximum size is ${Math.round(maxBytes / 1048576)} MB.`);
  const t = sniffFile(file.buffer);
  if (!t || !allowed.includes(t.ext)) throw new HttpError(415, `"${cleanText(file.originalname, 80)}" is not an allowed file type. Allowed: ${allowed.join(', ').toUpperCase()}.`);
  const name = `${Date.now().toString(36)}-${randomToken(8)}.${t.ext}`;
  fs.writeFileSync(path.join(DIRS[dir], name), file.buffer, { mode: 0o640 });
  return { file: name, url: dir === 'private' ? null : `/uploads/${dir}/${name}`, mime: t.mime, size: file.size, original: cleanText(file.originalname, 120) };
}
function deleteUploadByUrl(url) {
  const m = /^\/uploads\/(images|documents)\/([a-z0-9-]+\.[a-z]{3,4})$/.exec(String(url || ''));
  if (m) { try { fs.unlinkSync(path.join(DIRS[m[1]], m[2])); return true; } catch { return false; } }
  return false;
}

/* Optional email notifications — the site keeps working when SMTP is not configured */
async function sendMail({ subject, text, to, replyTo }) {
  const s = S().smtp;
  if (!s.enabled || !s.host) return false;
  try {
    const transport = nodemailer.createTransport({
      host: s.host, port: parseInt(s.port, 10) || 587, secure: !!s.secure,
      auth: s.user ? { user: s.user, pass: decrypt(s.pass) } : undefined,
      connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000,
    });
    await transport.sendMail({ from: s.from || s.user, to: to || s.notify_to || S().contact.email, subject, text, replyTo });
    return true;
  } catch (e) { console.warn('[mail] sending failed:', e.message); return false; }
}
function notifyAdmin(subject, fields, replyTo) {
  const text = Object.entries(fields).map(([k, v]) => `${k}: ${v ?? ''}`).join('\n') + '\n\nOpen the admin dashboard to manage this request.';
  sendMail({ subject: `[SDS] ${subject}`, text, replyTo }).catch(() => {});
}

/* ===================== 8. PUBLIC LAYOUT, ICONS & CSS ===================== */
const ICONS = {
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>', check: '<path d="M20 6 9 17l-5-5"/>',
  cctv: '<path d="M3.5 6.5 16 10l-1.8 4.6L2 11z"/><path d="m14.2 14.6 1.2 3.4H19"/><path d="M19 14.5v7"/><circle cx="7" cy="9.6" r=".7"/>',
  camera: '<path d="M3 7h11a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H3z"/><path d="m16 10 5-3v10l-5-3"/>',
  monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
  phone: '<rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M11 18h2"/>',
  call: '<path d="M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1 1 .4 1.9.7 2.8a2 2 0 0 1-.5 2.1L8 9.9a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.8.7a2 2 0 0 1 1.7 2z"/>',
  book: '<path d="M4 19.5V5a2 2 0 0 1 2-2h14v16H6.5A2.5 2.5 0 0 0 4 21.5z"/><path d="M8 7h8M8 11h6"/>',
  award: '<circle cx="12" cy="9" r="6"/><path d="m8.5 14-1.5 8 5-3 5 3-1.5-8"/>',
  home: '<path d="M3 11 12 3l9 8"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
  users: '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 14 0"/><path d="M16 4a4 4 0 0 1 0 8M22 21a7 7 0 0 0-4-6.3"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  pin: '<path d="M12 22s7-6.2 7-12a7 7 0 0 0-14 0c0 5.8 7 12 7 12z"/><circle cx="12" cy="10" r="2.5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  wrench: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L3 17.8V21h3.2l6.3-6.3a4 4 0 0 0 5.2-5.4l-2.5 2.5-2.5-.5-.5-2.5z"/>',
  wifi: '<path d="M2 8.5a15 15 0 0 1 20 0M5 12a10 10 0 0 1 14 0M8.5 15.5a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/>',
  drive: '<rect x="2" y="13" width="20" height="8" rx="2"/><path d="M5 13 8 4h8l3 9"/><path d="M6 17h.01M10 17h.01"/>',
  cpu: '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  server: '<rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01M11 7h6M11 17h6"/>',
  file: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  cart: '<circle cx="9" cy="20" r="1.5"/><circle cx="18" cy="20" r="1.5"/><path d="M2 3h3l2.7 12.4a2 2 0 0 0 2 1.6h7.6a2 2 0 0 0 2-1.5L21 8H6"/>',
  menu: '<path d="M3 6h18M3 12h18M3 18h18"/>', x: '<path d="M18 6 6 18M6 6l12 12"/>',
  star: '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2L12 17.3 6.4 20.2l1.1-6.2L3 9.6l6.2-.9z"/>',
  chat: '<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  settings: '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
  tag: '<path d="M3 12V3h9l9 9-9 9z"/><circle cx="7.5" cy="7.5" r="1.5"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-5-5L5 21"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>', minus: '<path d="M5 12h14"/>',
  trash: '<path d="M3 6h18M8 6V4h8v2M6 6l1 15h10l1-15"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  print: '<path d="M6 9V2h12v7"/><rect x="2" y="9" width="20" height="9" rx="2"/><path d="M6 14h12v8H6z"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5h13L22 12v7a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-7z"/>',
  quote: '<path d="M3 21c3 0 7-1 7-8V5H3v8h4c0 4-2 5-4 5zM14 21c3 0 7-1 7-8V5h-7v8h4c0 4-2 5-4 5z"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>', user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  dashboard: '<rect x="3" y="3" width="8" height="10" rx="1.5"/><rect x="13" y="3" width="8" height="6" rx="1.5"/><rect x="13" y="11" width="8" height="10" rx="1.5"/><rect x="3" y="15" width="8" height="6" rx="1.5"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>', external: '<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
};
const icon = (name, cls = '') => `<svg class="ico ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICONS[name] || ICONS.monitor}</svg>`;
const ICON_NAMES = Object.keys(ICONS);

const NAV = [
  ['Home', '/'], ['About', '/about'], ['Services', '/services'], ['Blog', '/blog'], ['Computer Course', '/course'],
  ['CCTV', '/cctv', [['CCTV Services', '/cctv', 'cctv'], ['Product Catalogue', '/cctv/products', 'cart'], ['Request a Site Visit', '/cctv#request', 'calendar'], ['CCTV Guides', '/blog/category/cctv-cameras', 'book']]],
  ['Apna Ghar Apni Chat', '/apna-ghar-apni-chat'], ['Contact', '/contact'],
];

function brand() {
  const g = S().general;
  const mark = g.logo
    ? `<img src="${esc(g.logo)}" alt="" class="brand-logo" width="42" height="42">`
    : `<span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 40 40"><rect width="40" height="40" rx="11" fill="url(#bm)"/><defs><linearGradient id="bm" x1="0" y1="0" x2="40" y2="40"><stop offset="0" stop-color="#1d4ed8"/><stop offset="1" stop-color="#0b1b33"/></linearGradient></defs><path d="M26.5 13.2c-1.4-1.6-3.7-2.6-6.4-2.6-4 0-6.7 2.1-6.7 5.1 0 3.2 2.8 4.3 6.3 5.1 3 .7 4.2 1.3 4.2 2.7 0 1.5-1.6 2.5-3.9 2.5-2.5 0-4.4-1-5.7-2.7" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"/><circle cx="29.5" cy="27.5" r="3" fill="#22d3ee"/></svg></span>`;
  return `<a href="/" class="brand" aria-label="${esc(g.site_name)} — home">${mark}<span class="brand-text"><strong>${esc(g.site_name)}</strong><small>${esc(g.short_name)} · ${esc(g.service_area)}</small></span></a>`;
}

function socialLinks(cls = 'social') {
  const s = S().social;
  const labels = { facebook: 'Facebook', instagram: 'Instagram', youtube: 'YouTube', tiktok: 'TikTok', linkedin: 'LinkedIn', x: 'X' };
  const items = Object.entries(labels).filter(([k]) => /^https?:\/\//.test(s[k] || ''));
  if (!items.length) return '';
  return `<ul class="${cls}">${items.map(([k, l]) => `<li><a href="${esc(s[k])}" target="_blank" rel="noopener noreferrer">${l}</a></li>`).join('')}</ul>`;
}
const waLink = (text) => { const n = String(S().contact.whatsapp || '').replace(/\D/g, ''); return n ? `https://wa.me/${n}${text ? '?text=' + encodeURIComponent(text) : ''}` : ''; };
const telLink = () => 'tel:' + String(S().contact.phone || '').replace(/[^\d+]/g, '');

function layout(req, { title, description, body, path: pagePath = req.path, ogImage, ogType = 'website', jsonLd = [], bodyClass = '', noindex = false }) {
  const st = S(), g = st.general, seo = st.seo, c = st.contact;
  const fullTitle = title ? `${title} | ${g.site_name}` : seo.meta_title;
  const desc = truncate(description || seo.meta_description, 170);
  const base = baseUrl(req);
  const canonical = base + pagePath;
  const og = ogImage || seo.og_image;
  const ogAbs = og ? (og.startsWith('http') ? og : base + og) : '';
  const banner = HOME.banner;
  const navHtml = NAV.map(([label, href, sub]) => {
    const active = href === '/' ? req.path === '/' : req.path.startsWith(href);
    if (!sub) return `<li><a href="${href}" class="${active ? 'active' : ''}"${active ? ' aria-current="page"' : ''}>${esc(label)}</a></li>`;
    return `<li class="has-sub"><a href="${href}" class="${active ? 'active' : ''}" aria-haspopup="true">${esc(label)} ${icon('chevron', 'chev')}</a>
      <ul class="sub">${sub.map(([l, h, ic]) => `<li><a href="${h}">${icon(ic)}<span>${esc(l)}</span></a></li>`).join('')}</ul></li>`;
  }).join('');
  const org = {
    '@context': 'https://schema.org', '@type': 'LocalBusiness', name: g.site_name, alternateName: g.short_name, url: base + '/',
    description: seo.meta_description, telephone: c.phone, email: c.email, areaServed: g.service_area, currenciesAccepted: 'PKR',
    address: { '@type': 'PostalAddress', streetAddress: c.address, addressRegion: 'Punjab', addressCountry: 'PK' },
    ...(g.logo ? { logo: base + g.logo } : {}),
  };
  const ld = [org, ...jsonLd].map((o) => `<script type="application/ld+json">${JSON.stringify(o).replace(/</g, '\\u003c')}</script>`).join('');
  const wa = waLink('Hello SDS, I would like some information.');
  const year = new Date().getFullYear();
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(fullTitle)}</title>
<meta name="description" content="${esc(desc)}">
${seo.keywords && pagePath === '/' ? `<meta name="keywords" content="${esc(seo.keywords)}">` : ''}
${noindex ? '<meta name="robots" content="noindex, nofollow">' : '<meta name="robots" content="index, follow">'}
<link rel="canonical" href="${esc(canonical)}">
<meta property="og:site_name" content="${esc(g.site_name)}">
<meta property="og:title" content="${esc(title || seo.meta_title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:type" content="${ogType}">
<meta property="og:url" content="${esc(canonical)}">
${ogAbs ? `<meta property="og:image" content="${esc(ogAbs)}"><meta name="twitter:image" content="${esc(ogAbs)}">` : ''}
<meta name="twitter:card" content="${ogAbs ? 'summary_large_image' : 'summary'}">
<meta name="theme-color" content="#0b1b33">
${seo.google_verification ? `<meta name="google-site-verification" content="${esc(seo.google_verification)}">` : ''}
<meta name="csrf-token" content="${req.csrfToken}">
<link rel="icon" href="${esc(g.favicon || '/favicon.svg')}">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap">
<link rel="stylesheet" href="/assets/site.css?v=${ASSET_VERSION}">
${ld}
</head>
<body class="${bodyClass}">
<a class="skip" href="#main">Skip to content</a>
${banner.enabled && banner.text ? `<div class="topbar"><div class="container"><p>${esc(banner.text)}${banner.link ? ` <a href="${esc(banner.link)}">${esc(banner.link_text || 'Learn more')} ${icon('arrow')}</a>` : ''}</p></div></div>` : ''}
<header class="site-header" id="top">
  <div class="container header-inner">
    ${brand()}
    <nav class="main-nav" id="mainNav" aria-label="Main navigation"><ul>${navHtml}</ul>
      <div class="nav-cta-mobile"><a class="btn btn-primary btn-block" href="/cctv/products">Get a CCTV Quote</a></div>
    </nav>
    <div class="header-actions">
      <a href="/cctv/products#quote" class="cart-link" aria-label="Quotation cart">${icon('cart')}<span class="cart-count" data-cart-count hidden>0</span></a>
      <a href="/cctv/products" class="btn btn-primary btn-sm hide-sm">Get a Quote</a>
      <button class="nav-toggle" type="button" aria-controls="mainNav" aria-expanded="false" aria-label="Open menu">${icon('menu', 'i-open')}${icon('x', 'i-close')}</button>
    </div>
  </div>
</header>
<main id="main">${body}</main>
<footer class="site-footer">
  <div class="container footer-grid">
    <div class="footer-about">${brand()}<p>${esc(st.footer.about)}</p>${socialLinks('social')}</div>
    <div><h3>Explore</h3><ul><li><a href="/about">About SDS</a></li><li><a href="/services">Services</a></li><li><a href="/blog">Smart Digital Blog</a></li><li><a href="/course">Basic Computer Course</a></li><li><a href="/verify">Verify a Certificate</a></li></ul></div>
    <div><h3>CCTV</h3><ul><li><a href="/cctv">Installation &amp; Maintenance</a></li><li><a href="/cctv/products">Product Catalogue</a></li><li><a href="/cctv#request">Request a Site Visit</a></li><li><a href="/blog/category/cctv-cameras">CCTV Guides</a></li><li><a href="/apna-ghar-apni-chat">Application Assistance</a></li></ul></div>
    <div><h3>Contact</h3><ul class="footer-contact">
      <li>${icon('call')}<a href="${telLink()}">${esc(c.phone)}</a></li>
      <li>${icon('mail')}<a href="mailto:${esc(c.email)}">${esc(c.email)}</a></li>
      ${wa ? `<li>${icon('chat')}<a href="${esc(wa)}" target="_blank" rel="noopener">WhatsApp us</a></li>` : ''}
      <li>${icon('pin')}<span>${esc(c.address)}</span></li>
      <li>${icon('clock')}<span>${esc(c.hours)}</span></li></ul></div>
  </div>
  <div class="container footer-bottom">
    <p>${esc(String(st.footer.copyright || '').replace('{year}', year))} ${st.footer.note ? `<span class="muted">${esc(st.footer.note)}</span>` : ''}</p>
    <p><a href="/privacy-policy">Privacy Policy</a> · <a href="/terms">Terms &amp; Conditions</a> · <a href="/sitemap.xml">Sitemap</a></p>
  </div>
</footer>
${wa ? `<a class="wa-float" href="${esc(wa)}" target="_blank" rel="noopener" aria-label="Chat on WhatsApp">${icon('chat')}<span>WhatsApp</span></a>` : ''}
<div class="toast-wrap" id="toasts" aria-live="polite"></div>
<script src="/assets/site.js?v=${ASSET_VERSION}" defer></script>
</body>
</html>`;
}

function pageHero({ eyebrow, title, text, crumbs = [], extra = '' }) {
  const bc = crumbs.length ? `<nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a>${crumbs.map(([l, h]) => ` <span>/</span> ${h ? `<a href="${h}">${esc(l)}</a>` : `<span aria-current="page">${esc(l)}</span>`}`).join('')}</nav>` : '';
  return `<section class="page-hero"><div class="container">${bc}${eyebrow ? `<p class="eyebrow light">${esc(eyebrow)}</p>` : ''}<h1>${esc(title)}</h1>${text ? `<p class="lead">${esc(text)}</p>` : ''}${extra}</div></section>`;
}
const sectionHead = (h, { center = false, light = false } = {}) => `<div class="section-head${center ? ' center' : ''}">${h.eyebrow ? `<p class="eyebrow${light ? ' light' : ''}">${esc(h.eyebrow)}</p>` : ''}<h2>${esc(h.title)}</h2>${h.subtitle || h.text ? `<p class="section-sub">${esc(h.subtitle || h.text)}</p>` : ''}</div>`;

const SITE_CSS = `
:root{--navy-950:#060f1d;--navy-900:#0b1b33;--navy-800:#112a4d;--navy-700:#1a3a66;--blue-700:#1d4ed8;--blue-600:#2563eb;--blue-500:#3b82f6;--blue-100:#dbe7ff;--blue-50:#eef4ff;--cyan:#22d3ee;--ink:#0f172a;--body:#3f4b5e;--muted:#64748b;--line:#e3e8f0;--soft:#f5f7fb;--white:#fff;--ok:#047857;--ok-bg:#ecfdf5;--err:#b91c1c;--err-bg:#fef2f2;--warn:#92400e;--warn-bg:#fffbeb;--radius:14px;--shadow-sm:0 1px 2px rgba(15,23,42,.05),0 1px 3px rgba(15,23,42,.06);--shadow:0 10px 30px -12px rgba(15,23,42,.18);--shadow-lg:0 24px 60px -20px rgba(11,27,51,.35);--font:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;--display:'Plus Jakarta Sans','Inter',system-ui,sans-serif}
*,*::before,*::after{box-sizing:border-box}
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%;overflow-x:hidden}
body{margin:0;font-family:var(--font);font-size:16px;line-height:1.65;color:var(--body);background:var(--white);-webkit-font-smoothing:antialiased;overflow-x:hidden}
img{max-width:100%;height:auto;display:block}
a{color:var(--blue-600);text-decoration:none}
a:hover{color:var(--blue-700)}
h1,h2,h3,h4{font-family:var(--display);color:var(--ink);line-height:1.2;margin:0 0 .6em;letter-spacing:-.02em}
h1{font-size:clamp(2.1rem,4.6vw,3.6rem);font-weight:800}
h2{font-size:clamp(1.7rem,3vw,2.5rem);font-weight:800}
h3{font-size:1.2rem;font-weight:700}
p{margin:0 0 1em}
:focus-visible{outline:3px solid var(--blue-500);outline-offset:2px;border-radius:6px}
.ico{width:1.25em;height:1.25em;flex:none}
.container{width:100%;max-width:1220px;margin:0 auto;padding:0 20px}
.skip{position:absolute;left:-999px;top:8px;background:var(--ink);color:#fff;padding:8px 14px;border-radius:8px;z-index:200}
.skip:focus{left:8px}
.muted{color:var(--muted)}
.topbar{background:var(--blue-700);color:#fff;font-size:.9rem;text-align:center}
.topbar p{margin:0;padding:8px 0}.topbar a{color:#fff;font-weight:600;display:inline-flex;align-items:center;gap:4px;text-decoration:underline;text-underline-offset:3px}
/* Header */
.site-header{position:sticky;top:0;z-index:100;border-bottom:1px solid transparent;transition:border-color .2s,box-shadow .2s}
.site-header::before{content:'';position:absolute;inset:0;z-index:-1;background:rgba(255,255,255,.92);backdrop-filter:saturate(180%) blur(12px);-webkit-backdrop-filter:saturate(180%) blur(12px)}
.site-header.scrolled{border-bottom-color:var(--line);box-shadow:0 6px 24px -18px rgba(15,23,42,.4)}
.header-inner{display:flex;align-items:center;gap:20px;height:74px}
.brand{display:flex;align-items:center;gap:11px;color:var(--ink);flex:none}
.brand:hover{color:var(--ink)}
.brand-mark svg,.brand-logo{width:42px;height:42px;border-radius:11px;object-fit:contain}
.brand-text{display:flex;flex-direction:column;line-height:1.15}
.brand-text strong{font-family:var(--display);font-size:1.02rem;font-weight:800;letter-spacing:-.01em}
.brand-text small{font-size:.72rem;color:var(--muted);font-weight:500;letter-spacing:.02em}
.main-nav{margin-left:auto}
.main-nav>ul{display:flex;align-items:center;gap:2px;list-style:none;margin:0;padding:0}
.main-nav a{display:flex;align-items:center;gap:4px;padding:9px 11px;border-radius:9px;color:#334155;font-weight:500;font-size:.93rem;white-space:nowrap;transition:color .15s,background .15s}
.main-nav a:hover,.main-nav a.active{color:var(--blue-700);background:var(--blue-50)}
.chev{width:14px;height:14px;transition:transform .2s}
.has-sub{position:relative}
.sub{position:absolute;top:calc(100% + 8px);left:0;min-width:250px;list-style:none;margin:0;padding:8px;background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow-lg);opacity:0;visibility:hidden;transform:translateY(6px);transition:all .18s}
.sub::before{content:'';position:absolute;top:-10px;left:0;right:0;height:10px}
.has-sub:hover .sub,.has-sub:focus-within .sub{opacity:1;visibility:visible;transform:none}
.has-sub:hover .chev{transform:rotate(180deg)}
.sub a{padding:10px 12px;gap:10px}.sub .ico{color:var(--blue-600)}
.header-actions{display:flex;align-items:center;gap:10px}
.cart-link{position:relative;display:grid;place-items:center;width:42px;height:42px;border-radius:11px;border:1px solid var(--line);color:var(--ink)}
.cart-link:hover{border-color:var(--blue-500);color:var(--blue-600)}
.cart-count{position:absolute;top:-6px;right:-6px;min-width:20px;height:20px;padding:0 5px;border-radius:10px;background:var(--blue-600);color:#fff;font-size:.72rem;font-weight:700;display:grid;place-items:center}
.cart-count[hidden]{display:none}
.nav-toggle{display:none;width:42px;height:42px;border-radius:11px;border:1px solid var(--line);background:#fff;color:var(--ink);cursor:pointer;place-items:center}
.nav-toggle .i-close{display:none}
.nav-cta-mobile{display:none}
/* Buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;white-space:nowrap;padding:13px 22px;border-radius:11px;font-weight:600;font-size:.96rem;line-height:1.2;border:1px solid transparent;cursor:pointer;transition:transform .15s,box-shadow .2s,background .2s,color .2s,border-color .2s;font-family:inherit;text-align:center}
.btn:hover{transform:translateY(-1px)}
.btn:active{transform:none}
.btn .ico{width:18px;height:18px}
.btn-primary{background:var(--blue-600);color:#fff;box-shadow:0 8px 20px -8px rgba(37,99,235,.6)}
.btn-primary:hover{background:var(--blue-700);color:#fff}
.btn-dark{background:var(--navy-900);color:#fff}.btn-dark:hover{background:var(--navy-800);color:#fff}
.btn-outline{background:#fff;color:var(--ink);border-color:var(--line)}.btn-outline:hover{border-color:var(--blue-500);color:var(--blue-700)}
.btn-ghost-light{background:rgba(255,255,255,.08);color:#fff;border-color:rgba(255,255,255,.22)}.btn-ghost-light:hover{background:rgba(255,255,255,.16);color:#fff}
.btn-light{background:#fff;color:var(--navy-900)}.btn-light:hover{color:var(--blue-700)}
.btn-sm{padding:9px 15px;font-size:.88rem;border-radius:9px}
.btn-block{width:100%}
.btn[disabled]{opacity:.6;cursor:not-allowed;transform:none}
.link-arrow{display:inline-flex;align-items:center;gap:6px;font-weight:600}
.link-arrow .ico{width:16px;height:16px;transition:transform .2s}
.link-arrow:hover .ico{transform:translateX(3px)}
/* Sections */
.section{padding:96px 0}
.section.tight{padding:72px 0}
.section.soft{background:var(--soft)}
.section.dark{background:var(--navy-900);color:#c7d2e3}
.section.dark h2,.section.dark h3{color:#fff}
.section-head{max-width:720px;margin-bottom:48px}
.section-head.center{margin-left:auto;margin-right:auto;text-align:center}
.section-head h2{margin-bottom:14px}
.section-sub{font-size:1.07rem;color:var(--muted);margin:0}
.section.dark .section-sub{color:#9fb0c9}
.eyebrow{display:inline-flex;align-items:center;gap:10px;font-size:.78rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--blue-600);margin:0 0 14px}
.eyebrow::before{content:'';width:22px;height:2px;background:currentColor;border-radius:2px}
.section-head.center .eyebrow::after{content:'';width:22px;height:2px;background:currentColor;border-radius:2px}
.eyebrow.light{color:var(--cyan)}
.head-row{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:44px;flex-wrap:wrap}
.head-row .section-head{margin-bottom:0}
/* Hero */
.hero{position:relative;background:var(--navy-950);color:#c5d0e2;overflow:hidden;padding:88px 0 96px}
.hero::before{content:'';position:absolute;inset:0;background-image:linear-gradient(rgba(148,163,184,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(148,163,184,.07) 1px,transparent 1px);background-size:56px 56px;mask-image:radial-gradient(ellipse 80% 70% at 70% 40%,#000 30%,transparent 75%);-webkit-mask-image:radial-gradient(ellipse 80% 70% at 70% 40%,#000 30%,transparent 75%)}
.hero::after{content:'';position:absolute;width:720px;height:720px;right:-200px;top:-260px;background:radial-gradient(circle,rgba(37,99,235,.35),transparent 65%);pointer-events:none}
.hero .container{position:relative;z-index:1}
.hero-grid{display:grid;grid-template-columns:1.05fr .95fr;gap:56px;align-items:center}
.hero h1{color:#fff;margin-bottom:22px}
.hero h1 em{font-style:normal;color:transparent;background:linear-gradient(90deg,#60a5fa,var(--cyan));-webkit-background-clip:text;background-clip:text}
.hero .lead{font-size:1.15rem;color:#b3c0d6;max-width:560px;margin-bottom:32px}
.hero-actions{display:flex;flex-wrap:wrap;gap:12px}
.hero-stats{display:flex;gap:36px;margin-top:48px;padding-top:28px;border-top:1px solid rgba(148,163,184,.18);flex-wrap:wrap}
.hero-stats strong{display:block;font-family:var(--display);font-size:1.6rem;color:#fff;font-weight:800;letter-spacing:-.02em}
.hero-stats span{font-size:.86rem;color:#91a2bd}
.hero-visual{position:relative}
.hero-img{border-radius:20px;box-shadow:var(--shadow-lg);border:1px solid rgba(148,163,184,.2);width:100%;aspect-ratio:5/4;object-fit:cover}
.device{position:relative;background:linear-gradient(180deg,#0f2443,#0b1b33);border:1px solid rgba(148,163,184,.22);border-radius:20px;padding:14px;box-shadow:var(--shadow-lg)}
.device-bar{display:flex;align-items:center;gap:6px;padding:4px 6px 12px}
.device-bar i{width:9px;height:9px;border-radius:50%;background:#334a6d}
.device-bar span{margin-left:auto;font-size:.72rem;color:#8ea2c2;font-weight:600;letter-spacing:.06em;display:flex;align-items:center;gap:6px}
.rec{width:8px;height:8px;border-radius:50%;background:#ef4444;box-shadow:0 0 0 0 rgba(239,68,68,.6);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(239,68,68,.55)}70%{box-shadow:0 0 0 8px rgba(239,68,68,0)}100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}}
.feeds{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.feed{position:relative;aspect-ratio:16/10;border-radius:10px;overflow:hidden;background:#0a1730}
.feed::before{content:'';position:absolute;inset:0;background:linear-gradient(160deg,rgba(59,130,246,.25),transparent 50%),repeating-linear-gradient(0deg,rgba(255,255,255,.025) 0 2px,transparent 2px 4px)}
.feed .shape{position:absolute;bottom:0;background:#132c52;border-radius:6px 6px 0 0}
.feed b{position:absolute;left:8px;top:7px;font-size:.62rem;color:#cbd5e1;font-weight:600;letter-spacing:.05em;background:rgba(6,15,29,.55);padding:2px 6px;border-radius:4px}
.feed .ts{position:absolute;right:8px;bottom:6px;font-size:.6rem;color:#9fb3d1;font-family:ui-monospace,Consolas,monospace}
.feed .scan{position:absolute;left:0;right:0;height:30%;background:linear-gradient(180deg,transparent,rgba(34,211,238,.10),transparent);animation:scan 4.5s linear infinite}
@keyframes scan{from{top:-30%}to{top:100%}}
.float-card{position:absolute;background:#fff;color:var(--ink);border-radius:14px;padding:14px 16px;box-shadow:var(--shadow-lg);display:flex;align-items:center;gap:12px;font-size:.86rem;line-height:1.35;animation:float 6s ease-in-out infinite}
.float-card .ic{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;background:var(--blue-50);color:var(--blue-600)}
.float-card strong{display:block;font-size:.92rem}
.float-card small{color:var(--muted)}
.fc-1{left:-34px;bottom:-26px}.fc-2{right:-20px;top:-22px;animation-delay:-3s}
.progress{height:6px;background:var(--blue-100);border-radius:6px;margin-top:6px;overflow:hidden;width:130px}.progress i{display:block;height:100%;width:72%;background:var(--blue-600);border-radius:6px}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
/* Page hero */
.page-hero{position:relative;background:var(--navy-950);color:#b9c6da;padding:72px 0 64px;overflow:hidden}
.page-hero::before{content:'';position:absolute;inset:0;background-image:linear-gradient(rgba(148,163,184,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(148,163,184,.06) 1px,transparent 1px);background-size:48px 48px;mask-image:linear-gradient(90deg,transparent,#000 60%);-webkit-mask-image:linear-gradient(90deg,transparent,#000 60%)}
.page-hero::after{content:'';position:absolute;right:-160px;top:-200px;width:520px;height:520px;background:radial-gradient(circle,rgba(37,99,235,.3),transparent 65%)}
.page-hero .container{position:relative;z-index:1}
.page-hero h1{color:#fff;font-size:clamp(2rem,4vw,3rem);max-width:820px}
.page-hero .lead{font-size:1.1rem;max-width:720px;margin:0}
.crumbs{font-size:.85rem;margin-bottom:18px;color:#8195b3}.crumbs a{color:#b9c6da}.crumbs a:hover{color:#fff}.crumbs span{margin:0 4px}
/* Grids & cards */
.grid{display:grid;gap:24px}
.g-2{grid-template-columns:repeat(2,1fr)}.g-3{grid-template-columns:repeat(3,1fr)}.g-4{grid-template-columns:repeat(4,1fr)}
.card{background:#fff;border:1px solid var(--line);border-radius:var(--radius);padding:28px;box-shadow:var(--shadow-sm);transition:transform .25s,box-shadow .25s,border-color .25s}
.card-hover:hover{transform:translateY(-4px);box-shadow:var(--shadow);border-color:#cfd9ea}
.ic-box{width:52px;height:52px;border-radius:13px;display:grid;place-items:center;background:var(--blue-50);color:var(--blue-600);margin-bottom:20px}
.ic-box .ico{width:26px;height:26px}
.svc-card{display:flex;flex-direction:column;position:relative;overflow:hidden}
.svc-card h3{margin-bottom:10px}
.svc-card p{color:var(--muted);flex:1;margin-bottom:18px}
.svc-card::after{content:'';position:absolute;left:0;top:0;height:3px;width:0;background:linear-gradient(90deg,var(--blue-600),var(--cyan));transition:width .35s}
.svc-card:hover::after{width:100%}
.svc-num{position:absolute;right:22px;top:20px;font-family:var(--display);font-weight:800;font-size:.85rem;color:#c3cfe2}
/* Split */
.split{display:grid;grid-template-columns:1fr 1fr;gap:64px;align-items:center}
.split.rev>:first-child{order:2}
.checklist{list-style:none;padding:0;margin:0 0 28px;display:grid;gap:12px}
.checklist li{display:flex;gap:12px;align-items:flex-start}
.checklist .ico{color:var(--blue-600);width:22px;height:22px;padding:3px;background:var(--blue-50);border-radius:50%;margin-top:1px}
.checklist.cols{grid-template-columns:1fr 1fr}
.section.dark .checklist .ico{background:rgba(34,211,238,.12);color:var(--cyan)}
.visual-panel{position:relative;border-radius:20px;background:linear-gradient(145deg,var(--navy-900),var(--navy-700));padding:36px;color:#c7d2e3;overflow:hidden;min-height:340px}
.visual-panel::before{content:'';position:absolute;inset:0;background-image:radial-gradient(rgba(148,163,184,.18) 1px,transparent 1px);background-size:20px 20px;opacity:.6}
.visual-panel>*{position:relative}
.visual-panel img{border-radius:14px}
.vp-stat{display:flex;align-items:center;gap:14px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:14px;padding:16px 18px;margin-bottom:12px}
.vp-stat .ic-box{margin:0;background:rgba(59,130,246,.18);color:#93c5fd;width:46px;height:46px}
.vp-stat strong{color:#fff;display:block;font-family:var(--display)}
.vp-stat small{color:#9fb0c9}
/* Blog cards */
.post-card{display:flex;flex-direction:column;padding:0;overflow:hidden}
.post-card .thumb{aspect-ratio:1200/630;overflow:hidden;background:var(--navy-900)}
.post-card .thumb img{width:100%;height:100%;object-fit:cover;transition:transform .5s}
.post-card:hover .thumb img{transform:scale(1.04)}
.post-card .body{padding:22px 24px 24px;display:flex;flex-direction:column;flex:1}
.post-card h3{font-size:1.12rem;margin-bottom:10px}
.post-card h3 a{color:var(--ink)}.post-card h3 a:hover{color:var(--blue-700)}
.post-card p{color:var(--muted);font-size:.95rem;flex:1}
.meta{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;font-size:.82rem;color:var(--muted)}
.meta .ico{width:14px;height:14px}.meta span{display:inline-flex;align-items:center;gap:5px}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:.76rem;font-weight:600;padding:5px 11px;border-radius:999px;background:var(--blue-50);color:var(--blue-700);white-space:nowrap}
.chip.dark{background:rgba(255,255,255,.1);color:#dbeafe}
.post-feature{display:grid;grid-template-columns:1.2fr 1fr;padding:0;overflow:hidden}
.post-feature .thumb{aspect-ratio:auto;min-height:100%}
.post-feature .body{padding:36px}
.post-feature h3{font-size:1.5rem}
.blog-layout{display:grid;grid-template-columns:1fr 320px;gap:48px;align-items:start}
.sidebar{display:grid;gap:22px;position:sticky;top:96px}
.sidebar .card{padding:22px}
.sidebar h3{font-size:1rem;margin-bottom:14px}
.cat-list{list-style:none;margin:0;padding:0;display:grid;gap:4px}
.cat-list a{display:flex;justify-content:space-between;align-items:center;padding:9px 12px;border-radius:9px;color:var(--body);font-size:.93rem}
.cat-list a:hover,.cat-list a.active{background:var(--blue-50);color:var(--blue-700)}
.cat-list em{font-style:normal;font-size:.78rem;background:var(--soft);padding:1px 8px;border-radius:10px;color:var(--muted)}
.tag-cloud{display:flex;flex-wrap:wrap;gap:8px}
.tag-cloud a{font-size:.8rem;padding:5px 11px;border-radius:999px;border:1px solid var(--line);color:var(--body)}
.tag-cloud a:hover{border-color:var(--blue-500);color:var(--blue-700)}
.search-box{display:flex;gap:8px}
.search-box input{flex:1}
.cat-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:32px}
.cat-tabs a,.cat-tabs button{padding:9px 16px;border-radius:999px;border:1px solid var(--line);background:#fff;color:var(--body);font-size:.9rem;font-weight:500;cursor:pointer;font-family:inherit}
.cat-tabs a.active,.cat-tabs button.active,.cat-tabs a:hover,.cat-tabs button:hover{background:var(--navy-900);border-color:var(--navy-900);color:#fff}
/* Article */
.article-head{max-width:860px}
.article-head .meta{color:#9fb0c9;margin-top:18px}
.article-cover{margin-top:-40px;position:relative;z-index:2;border-radius:18px;overflow:hidden;box-shadow:var(--shadow-lg);aspect-ratio:1200/630;background:var(--navy-900)}
.article-cover img{width:100%;height:100%;object-fit:cover}
.prose{font-size:1.06rem;line-height:1.8;color:#334155;max-width:760px}
.prose h2{font-size:1.55rem;margin:1.8em 0 .6em}
.prose h3{font-size:1.2rem;margin:1.5em 0 .5em}
.prose p.lead{font-size:1.18rem;color:var(--ink)}
.prose ul,.prose ol{padding-left:1.3em}.prose li{margin-bottom:.4em}
.prose img{border-radius:12px;margin:1.5em 0}
.prose blockquote{margin:1.5em 0;padding:16px 22px;border-left:4px solid var(--blue-600);background:var(--blue-50);border-radius:0 12px 12px 0;color:var(--ink)}
.prose table{width:100%;border-collapse:collapse;margin:1.5em 0;font-size:.95rem;display:block;overflow-x:auto}
.prose th,.prose td{border:1px solid var(--line);padding:10px 14px;text-align:left}
.prose th{background:var(--soft);color:var(--ink)}
.prose code{background:var(--soft);padding:2px 6px;border-radius:5px;font-size:.92em}
.prose pre{background:var(--navy-900);color:#e2e8f0;padding:18px;border-radius:12px;overflow-x:auto}
.prose .tip,.prose .note,.prose .warning{padding:16px 20px;border-radius:12px;border:1px solid}
.prose .tip{background:var(--ok-bg);border-color:#a7f3d0;color:#065f46}
.prose .note{background:var(--blue-50);border-color:var(--blue-100);color:#1e3a8a}
.prose .warning{background:var(--warn-bg);border-color:#fde68a;color:var(--warn)}
.article-tags{display:flex;flex-wrap:wrap;gap:8px;margin:36px 0;padding-top:24px;border-top:1px solid var(--line)}
.share{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:.9rem}
.comments{margin-top:48px}
.comment{padding:18px 0;border-bottom:1px solid var(--line)}
.comment strong{color:var(--ink)}
/* Course */
.syllabus{list-style:none;padding:0;margin:0;display:grid;gap:12px;counter-reset:mod}
.syllabus li{counter-increment:mod;display:grid;grid-template-columns:48px 1fr;gap:16px;align-items:start;background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px 18px;transition:border-color .2s,box-shadow .2s}
.syllabus li:hover{border-color:#c7d6f0;box-shadow:var(--shadow-sm)}
.syllabus li::before{content:counter(mod,decimal-leading-zero);font-family:var(--display);font-weight:800;color:var(--blue-600);background:var(--blue-50);border-radius:10px;height:44px;display:grid;place-items:center}
.syllabus strong{color:var(--ink);display:block}
.syllabus span{font-size:.92rem;color:var(--muted)}
.fee-card{background:var(--navy-900);color:#c7d2e3;border-radius:18px;padding:32px;position:relative;overflow:hidden}
.fee-card::after{content:'';position:absolute;right:-80px;top:-80px;width:240px;height:240px;background:radial-gradient(circle,rgba(34,211,238,.25),transparent 70%)}
.fee-card .price{font-family:var(--display);font-size:3rem;font-weight:800;color:#fff;letter-spacing:-.03em;line-height:1}
.fee-card .price small{font-size:1rem;color:#9fb0c9;font-weight:600}
.fee-card ul{list-style:none;padding:0;margin:22px 0;display:grid;gap:10px}
.fee-card li{display:flex;gap:10px;align-items:flex-start;font-size:.95rem}
.fee-card li .ico{color:var(--cyan);margin-top:3px;width:18px;height:18px}
.course-band{display:grid;grid-template-columns:1.1fr .9fr;gap:48px;align-items:center}
.mini-syllabus{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:24px 0 30px}
.mini-syllabus span{display:flex;gap:8px;align-items:center;font-size:.93rem;color:var(--ink);background:#fff;border:1px solid var(--line);padding:10px 12px;border-radius:10px}
.mini-syllabus b{font-family:var(--display);color:var(--blue-600);font-size:.8rem}
/* CCTV */
.cctv-band{position:relative;overflow:hidden}
.cctv-band::before{content:'';position:absolute;left:-200px;bottom:-300px;width:600px;height:600px;background:radial-gradient(circle,rgba(37,99,235,.25),transparent 65%)}
.cctv-band .container{position:relative}
.svc-list{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.svc-item{display:flex;gap:14px;align-items:flex-start;padding:18px;border-radius:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);transition:background .2s,border-color .2s}
.svc-item:hover{background:rgba(255,255,255,.07);border-color:rgba(96,165,250,.35)}
.svc-item .ic-box{width:44px;height:44px;margin:0;background:rgba(59,130,246,.16);color:#93c5fd;flex:none}
.svc-item h3{font-size:1rem;margin:0 0 4px;color:#fff}
.svc-item p{font-size:.88rem;margin:0;color:#9fb0c9}
.svc-list.light .svc-item{background:#fff;border-color:var(--line)}
.svc-list.light .svc-item:hover{border-color:#c7d6f0;box-shadow:var(--shadow-sm)}
.svc-list.light .svc-item h3{color:var(--ink)}.svc-list.light .svc-item p{color:var(--muted)}
.svc-list.light .ic-box{background:var(--blue-50);color:var(--blue-600)}
.coverage{display:flex;gap:14px;align-items:center;padding:18px 22px;border-radius:14px;background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.2);color:#cdeff7;margin-top:32px;font-size:.95rem}
.coverage .ico{color:var(--cyan);width:24px;height:24px}
/* Products */
.product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:22px}
.product-card{display:flex;flex-direction:column;padding:0;overflow:hidden}
.product-card .pimg{aspect-ratio:4/3;background:var(--soft);display:grid;place-items:center;overflow:hidden;position:relative}
.product-card .pimg img{width:100%;height:100%;object-fit:cover}
.product-card .pbody{padding:18px 20px 20px;display:flex;flex-direction:column;flex:1}
.product-card h3{font-size:1rem;margin-bottom:6px}
.product-card p{font-size:.88rem;color:var(--muted);flex:1;margin-bottom:14px}
.price-row{display:flex;align-items:center;justify-content:space-between;gap:10px}
.price{font-family:var(--display);font-weight:800;color:var(--ink);font-size:1.15rem}
.price small{font-size:.75rem;color:var(--muted);font-weight:500}
.stock{position:absolute;left:12px;top:12px;font-size:.72rem;font-weight:700;padding:4px 9px;border-radius:999px;background:#fff;box-shadow:var(--shadow-sm)}
.stock.in_stock{color:var(--ok)}.stock.low_stock{color:var(--warn)}.stock.out_of_stock{color:var(--err)}.stock.on_order{color:var(--blue-700)}
.specs{list-style:none;padding:0;margin:0 0 14px;font-size:.8rem;color:var(--muted);display:grid;gap:3px}
.specs li::before{content:'• ';color:var(--blue-500)}
.add-btn.added{background:var(--ok);box-shadow:none}
.shop-layout{display:grid;grid-template-columns:1fr 400px;gap:36px;align-items:start}
.quote-panel{position:sticky;top:92px;padding:0;overflow-x:hidden;overflow-y:auto;max-height:calc(100vh - 110px);overscroll-behavior:contain}
.quote-panel .qp-head{position:sticky;top:0;z-index:2}
.quote-panel .qp-head{padding:20px 22px;background:var(--navy-900);color:#fff;display:flex;align-items:center;justify-content:space-between}
.quote-panel .qp-head h2{font-size:1.1rem;color:#fff;margin:0;display:flex;gap:10px;align-items:center}
.qp-body{padding:18px 22px 22px}
.cart-items{list-style:none;margin:0 0 14px;padding:0;max-height:330px;overflow-y:auto}
.cart-items li{display:grid;grid-template-columns:1fr auto;gap:6px 10px;padding:12px 0;border-bottom:1px dashed var(--line);font-size:.9rem}
.cart-items .nm{color:var(--ink);font-weight:600;line-height:1.35}
.cart-items .lt{font-weight:700;color:var(--ink);text-align:right}
.qty{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:9px;overflow:hidden}
.qty button{width:30px;height:30px;border:0;background:var(--soft);cursor:pointer;display:grid;place-items:center;color:var(--ink)}
.qty button:hover{background:var(--blue-50);color:var(--blue-700)}
.qty button .ico{width:14px;height:14px}
.qty input{width:44px;height:30px;border:0;text-align:center;font-weight:600;font-family:inherit;-moz-appearance:textfield}
.qty input::-webkit-inner-spin-button{-webkit-appearance:none}
.rm{background:none;border:0;color:var(--muted);cursor:pointer;font-size:.8rem;padding:0;text-decoration:underline}
.rm:hover{color:var(--err)}
.cart-empty{text-align:center;padding:24px 8px;color:var(--muted);font-size:.92rem}
.cart-empty .ico{width:36px;height:36px;margin:0 auto 10px;color:#b6c3d8}
.totals{display:grid;gap:8px;font-size:.92rem;padding:12px 0;border-top:1px solid var(--line)}
.totals div{display:flex;justify-content:space-between}
.totals .grand{font-size:1.15rem;font-weight:800;color:var(--ink);font-family:var(--display);padding-top:10px;border-top:1px solid var(--line)}
.opt{display:flex;align-items:flex-start;gap:10px;font-size:.9rem;padding:8px 0;cursor:pointer}
.opt input{margin-top:4px;accent-color:var(--blue-600);width:16px;height:16px}
/* Forms */
.form-card{padding:34px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.form-grid .full{grid-column:1/-1}
.field label{display:block;font-weight:600;font-size:.88rem;color:var(--ink);margin-bottom:7px}
.field label .req{color:var(--err)}
.field .hint{font-size:.8rem;color:var(--muted);margin-top:5px}
.input,input[type=text],input[type=email],input[type=tel],input[type=number],input[type=date],input[type=search],input[type=password],select,textarea{width:100%;padding:12px 14px;border:1px solid #d5dde9;border-radius:10px;font:inherit;font-size:.95rem;color:var(--ink);background:#fff;transition:border-color .15s,box-shadow .15s}
textarea{min-height:120px;resize:vertical}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--blue-500);box-shadow:0 0 0 4px rgba(59,130,246,.15)}
.field.invalid input,.field.invalid select,.field.invalid textarea{border-color:var(--err)}
.field .err{color:var(--err);font-size:.8rem;margin-top:5px}
.consent{display:flex;gap:12px;align-items:flex-start;font-size:.9rem;padding:14px 16px;background:var(--soft);border-radius:10px;border:1px solid var(--line)}
.consent input{margin-top:5px;width:18px;height:18px;accent-color:var(--blue-600);flex:none}
.form-actions{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-top:6px}
.form-note{font-size:.82rem;color:var(--muted);display:flex;align-items:center;gap:6px}
.form-note .ico{width:15px;height:15px}
.alert{padding:16px 18px;border-radius:12px;border:1px solid;font-size:.94rem;margin-bottom:18px;display:flex;gap:12px;align-items:flex-start}
.alert .ico{flex:none;margin-top:2px}
.alert-ok{background:var(--ok-bg);border-color:#a7f3d0;color:#065f46}
.alert-err{background:var(--err-bg);border-color:#fecaca;color:var(--err)}
.alert-warn{background:var(--warn-bg);border-color:#fde68a;color:var(--warn)}
.alert-info{background:var(--blue-50);border-color:var(--blue-100);color:#1e3a8a}
.hp{position:absolute!important;left:-9999px!important;width:1px;height:1px;overflow:hidden}
/* Scheme */
.notice-box{border:1px solid #fde68a;background:var(--warn-bg);color:var(--warn);border-radius:14px;padding:20px 22px;display:flex;gap:14px}
.notice-box .ico{width:26px;height:26px;flex:none}
.notice-box strong{color:#78350f}
.steps{list-style:none;padding:0;margin:0;display:grid;gap:0;counter-reset:st}
.steps li{counter-increment:st;position:relative;padding:0 0 26px 62px}
.steps li::before{content:counter(st);position:absolute;left:0;top:0;width:42px;height:42px;border-radius:50%;background:var(--blue-600);color:#fff;font-weight:800;font-family:var(--display);display:grid;place-items:center;box-shadow:0 0 0 6px var(--blue-50)}
.steps li::after{content:'';position:absolute;left:20px;top:48px;bottom:4px;width:2px;background:var(--blue-100)}
.steps li:last-child::after{display:none}
.steps strong{display:block;color:var(--ink);font-family:var(--display);margin-bottom:2px;padding-top:8px}
.steps span{color:var(--muted);font-size:.95rem}
.section.dark .steps strong{color:#fff}.section.dark .steps span{color:#9fb0c9}.section.dark .steps li::before{box-shadow:0 0 0 6px rgba(37,99,235,.2)}.section.dark .steps li::after{background:rgba(59,130,246,.3)}
/* Team */
.team-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:24px}
.team-card{padding:0;overflow:hidden;text-align:left}
.team-photo{position:relative;aspect-ratio:4/4.4;background:linear-gradient(160deg,var(--navy-800),var(--navy-950));overflow:hidden}
.team-photo img{width:100%;height:100%;object-fit:cover;transition:transform .5s}
.team-card:hover .team-photo img{transform:scale(1.04)}
.avatar{width:100%;height:100%;display:grid;place-items:center;font-family:var(--display);font-size:3.2rem;font-weight:800;color:rgba(255,255,255,.9);letter-spacing:-.02em;background:radial-gradient(circle at 30% 20%,rgba(59,130,246,.45),transparent 60%),linear-gradient(160deg,var(--navy-800),var(--navy-950))}
.team-social{position:absolute;left:12px;right:12px;bottom:12px;display:flex;gap:6px;flex-wrap:wrap;opacity:0;transform:translateY(8px);transition:all .25s}
.team-card:hover .team-social,.team-card:focus-within .team-social{opacity:1;transform:none}
.team-social a{font-size:.74rem;font-weight:600;padding:5px 10px;border-radius:999px;background:rgba(255,255,255,.95);color:var(--navy-900)}
.team-info{padding:20px 22px 24px}
.team-info h3{font-size:1.08rem;margin-bottom:4px}
.team-info .role{color:var(--blue-600);font-weight:600;font-size:.86rem;margin-bottom:10px;display:block}
.team-info p{font-size:.9rem;color:var(--muted);margin:0}
/* Certificate preview */
.cert-mini{background:#fff;border-radius:16px;padding:12px;box-shadow:var(--shadow-lg);transform:rotate(-1.5deg)}
.cert-mini .inner{border:2px solid var(--blue-700);border-radius:10px;padding:30px 26px;text-align:center;position:relative;background:radial-gradient(circle at 50% 0,var(--blue-50),#fff 60%)}
.cert-mini .inner::before{content:'';position:absolute;inset:6px;border:1px solid #c9d7f2;border-radius:7px}
.cert-mini small{display:block;font-size:.62rem;letter-spacing:.2em;text-transform:uppercase;color:var(--muted)}
.cert-mini .ct{font-family:var(--display);font-size:1.25rem;font-weight:800;color:var(--navy-900);margin:8px 0 4px}
.cert-mini .nm{font-family:Georgia,serif;font-style:italic;font-size:1.5rem;color:var(--blue-700);margin:10px 0;border-bottom:1px solid var(--line);display:inline-block;padding:0 20px 4px}
.cert-mini .row{display:flex;justify-content:space-between;margin-top:20px;font-size:.68rem;color:var(--muted)}
.cert-mini .seal{width:46px;height:46px;border-radius:50%;background:var(--blue-700);color:#fff;display:grid;place-items:center;margin:0 auto}
.verify-form{display:flex;gap:10px;max-width:520px;margin-top:22px}
.verify-form input{flex:1}
/* Why */
.why-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border:1px solid var(--line);border-radius:18px;overflow:hidden;background:#fff}
.why-item{padding:32px 30px;border-right:1px solid var(--line);border-bottom:1px solid var(--line);transition:background .25s}
.why-item:nth-child(3n){border-right:0}
.why-item:nth-last-child(-n+3){border-bottom:0}
.why-item:hover{background:var(--soft)}
.why-item .n{font-family:var(--display);font-weight:800;font-size:.9rem;color:var(--blue-600);display:block;margin-bottom:14px}
.why-item h3{font-size:1.08rem;margin-bottom:8px}
.why-item p{color:var(--muted);font-size:.94rem;margin:0}
/* Testimonials */
.testi{display:flex;flex-direction:column}
.testi .ico.q{width:32px;height:32px;color:var(--blue-100);margin-bottom:12px}
.testi blockquote{margin:0 0 20px;color:var(--ink);font-size:1rem;flex:1}
.testi .who{display:flex;align-items:center;gap:12px}
.testi .who img,.testi .who .av{width:44px;height:44px;border-radius:50%;object-fit:cover;background:var(--navy-800);color:#fff;display:grid;place-items:center;font-weight:700}
.testi .who strong{display:block;color:var(--ink);font-size:.95rem}
.testi .who small{color:var(--muted)}
.stars{display:flex;gap:2px;color:#f59e0b;margin-bottom:12px}.stars .ico{width:16px;height:16px;fill:currentColor}
.demo-label{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--warn);background:var(--warn-bg);padding:3px 8px;border-radius:6px;align-self:flex-start;margin-bottom:12px}
/* Contact */
.contact-grid{display:grid;grid-template-columns:.85fr 1.15fr;gap:40px;align-items:start}
.info-list{list-style:none;padding:0;margin:0 0 26px;display:grid;gap:14px}
.info-list li{display:flex;gap:14px;align-items:flex-start;padding:16px 18px;background:#fff;border:1px solid var(--line);border-radius:14px}
.info-list .ic-box{margin:0;width:44px;height:44px;flex:none}
.info-list strong{display:block;color:var(--ink);font-size:.9rem}
.info-list a,.info-list span{color:var(--body);font-size:.95rem;word-break:break-word}
/* CTA */
.cta-band{background:linear-gradient(120deg,var(--blue-700),var(--navy-900));border-radius:22px;padding:52px 56px;display:flex;align-items:center;justify-content:space-between;gap:32px;color:#dbe7ff;position:relative;overflow:hidden}
.cta-band::after{content:'';position:absolute;right:-60px;top:-120px;width:340px;height:340px;border-radius:50%;border:60px solid rgba(255,255,255,.05)}
.cta-band h2{color:#fff;font-size:clamp(1.5rem,2.6vw,2rem);margin-bottom:8px}
.cta-band p{margin:0}
.cta-band .btn{position:relative;z-index:1;flex:none}
/* Pagination */
.pagination{display:flex;gap:6px;justify-content:center;margin-top:48px;flex-wrap:wrap}
.pagination a,.pagination span{min-width:42px;height:42px;padding:0 12px;border-radius:10px;border:1px solid var(--line);display:grid;place-items:center;color:var(--body);font-weight:600;font-size:.92rem}
.pagination a:hover{border-color:var(--blue-500);color:var(--blue-700)}
.pagination .cur{background:var(--navy-900);border-color:var(--navy-900);color:#fff}
.empty{text-align:center;padding:64px 20px;color:var(--muted)}
.empty .ico{width:48px;height:48px;margin:0 auto 16px;color:#b6c3d8}
/* Verify */
.verify-result{border-radius:18px;padding:32px;border:1px solid;margin-top:28px}
.verify-result.valid{background:var(--ok-bg);border-color:#a7f3d0}
.verify-result.invalid{background:var(--err-bg);border-color:#fecaca}
.verify-result dl{display:grid;grid-template-columns:180px 1fr;gap:10px 16px;margin:20px 0 0}
.verify-result dt{color:var(--muted);font-size:.9rem}.verify-result dd{margin:0;color:var(--ink);font-weight:600}
/* Footer */
.site-footer{background:var(--navy-950);color:#94a3b8;padding:72px 0 0;font-size:.94rem}
.footer-grid{display:grid;grid-template-columns:1.5fr 1fr 1fr 1.2fr;gap:40px;padding-bottom:48px}
.site-footer .brand{color:#fff;margin-bottom:18px}.site-footer .brand-text small{color:#7d8ea8}
.site-footer h3{color:#fff;font-size:.95rem;margin-bottom:18px;letter-spacing:0}
.site-footer ul{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.site-footer a{color:#a9b6c9}.site-footer a:hover{color:#fff}
.footer-about p{max-width:360px}
.footer-contact li{display:flex;gap:10px;align-items:flex-start;min-width:0}.footer-contact a,.footer-contact span{word-break:break-word;overflow-wrap:anywhere}
@media (max-width:1400px) and (min-width:1181px){.header-actions .hide-sm{display:none}.main-nav a{padding:9px 9px}}
.footer-contact .ico{color:var(--cyan);width:18px;height:18px;margin-top:3px}
.social{display:flex!important;flex-wrap:wrap;gap:8px!important;margin-top:6px!important}
.social a{display:inline-block;padding:6px 12px;border:1px solid rgba(148,163,184,.25);border-radius:999px;font-size:.8rem}
.social a:hover{border-color:var(--cyan)}
.footer-bottom{border-top:1px solid rgba(148,163,184,.15);padding:22px 20px;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;font-size:.85rem}
.footer-bottom p{margin:0}.footer-bottom .muted{display:block;color:#6b7c96;font-size:.8rem;margin-top:4px}
.wa-float{position:fixed;right:20px;bottom:20px;z-index:90;display:flex;align-items:center;gap:8px;background:#15803d;color:#fff;padding:12px 18px;border-radius:999px;font-weight:600;font-size:.92rem;box-shadow:0 12px 30px -10px rgba(21,128,61,.6);transition:transform .2s}
.wa-float:hover{color:#fff;transform:translateY(-2px)}
/* Toasts */
.toast-wrap{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:300;display:grid;gap:8px;width:min(420px,calc(100% - 32px))}
.toast{background:var(--navy-900);color:#fff;padding:14px 18px;border-radius:12px;box-shadow:var(--shadow-lg);font-size:.92rem;animation:tin .25s ease}
.toast.err{background:var(--err)}
@keyframes tin{from{opacity:0;transform:translateY(10px)}}
/* Reveal */
.reveal{opacity:0;transform:translateY(22px);transition:opacity .7s ease,transform .7s cubic-bezier(.2,.7,.2,1)}
.reveal.in{opacity:1;transform:none}
.reveal.d1{transition-delay:.08s}.reveal.d2{transition-delay:.16s}.reveal.d3{transition-delay:.24s}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important;scroll-behavior:auto!important}.reveal{opacity:1;transform:none}}
/* Responsive */
@media (max-width:1180px){
  .nav-toggle{display:grid}
  .main-nav{position:fixed;top:74px;left:0;right:0;bottom:0;z-index:99;background:#fff;padding:16px 20px 32px;overflow-y:auto;transform:translateX(100%);visibility:hidden;transition:transform .3s ease,visibility 0s linear .3s;margin:0;border-top:1px solid var(--line)}
  .menu-open .main-nav{transform:none;visibility:visible;transition:transform .3s ease}
  .menu-open .nav-toggle .i-open{display:none}.menu-open .nav-toggle .i-close{display:block}
  .menu-open{overflow:hidden}
  .main-nav>ul{flex-direction:column;align-items:stretch;gap:2px}
  .main-nav a{padding:13px 14px;font-size:1rem}
  .sub{position:static;opacity:1;visibility:visible;transform:none;box-shadow:none;border:0;padding:0 0 0 14px;min-width:0}
  .chev{display:none}
  .nav-cta-mobile{display:block;margin-top:18px}.nav-cta-mobile .btn,.nav-cta-mobile .btn:hover{color:#fff;background:var(--blue-600);justify-content:center}
  .header-actions{margin-left:auto}
}
@media (max-width:1024px){
  .hero-grid,.split,.course-band,.contact-grid,.blog-layout,.shop-layout{grid-template-columns:1fr}
  .split.rev>:first-child{order:0}
  .hero-visual{max-width:560px}
  .g-4,.team-grid{grid-template-columns:repeat(2,1fr)}
  .g-3,.svc-list{grid-template-columns:repeat(2,1fr)}
  .why-grid{grid-template-columns:repeat(2,1fr)}
  .why-item:nth-child(3n){border-right:1px solid var(--line)}.why-item:nth-child(2n){border-right:0}
  .why-item:nth-last-child(-n+3){border-bottom:1px solid var(--line)}.why-item:nth-last-child(-n+2){border-bottom:0}
  .footer-grid{grid-template-columns:1fr 1fr}
  .post-feature{grid-template-columns:1fr}
  .sidebar,.quote-panel{position:static}
  .cta-band{flex-direction:column;align-items:flex-start;padding:40px 32px}
}
@media (max-width:640px){
  body{font-size:15.5px}
  .section{padding:68px 0}
  .hero{padding:56px 0 72px}
  .hide-sm{display:none}
  .brand-text small{display:none}
  .g-2,.g-3,.g-4,.svc-list,.team-grid,.why-grid,.form-grid,.footer-grid,.checklist.cols,.mini-syllabus{grid-template-columns:1fr}
  .why-item{border-right:0!important;border-bottom:1px solid var(--line)!important}.why-item:last-child{border-bottom:0!important}
  .float-card{display:none}
  .hero-stats{gap:24px}
  .card,.form-card{padding:22px}
  .post-feature .body{padding:24px}
  .verify-result dl{grid-template-columns:1fr}
  .verify-form,.search-box{flex-direction:column}
  .wa-float span{display:none}.wa-float{padding:14px}
  .head-row{align-items:flex-start}
}
@media print{.site-header,.site-footer,.wa-float,.topbar,.no-print{display:none!important}body{background:#fff}}
`;

/* ============================== 9. PUBLIC PAGES ============================== */
const getCourse = () => q.get('SELECT * FROM courses WHERE active = 1 ORDER BY id LIMIT 1') || q.get('SELECT * FROM courses ORDER BY id LIMIT 1');
const getServices = (grp) => q.all('SELECT * FROM services WHERE grp = ? AND active = 1 ORDER BY sort_order, id', grp);
const coverUrl = (p) => p.featured_image || `/media/cover/${encodeURIComponent(p.slug)}.svg`;
const productImg = (p) => p.image || `/media/product/${p.id}.svg`;
const STOCK_LABELS = { in_stock: 'In stock', low_stock: 'Low stock', out_of_stock: 'Out of stock', on_order: 'On order' };
const initials = (n) => String(n || '?').split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('');

function postCard(p, { reveal = '' } = {}) {
  return `<article class="card card-hover post-card reveal ${reveal}">
    <a class="thumb" href="/blog/${esc(p.slug)}" tabindex="-1" aria-hidden="true"><img src="${esc(coverUrl(p))}" alt="" loading="lazy" width="1200" height="630"></a>
    <div class="body">
      <div class="meta" style="margin-bottom:12px">${p.category_name ? `<a class="chip" href="/blog/category/${esc(p.category_slug)}">${esc(p.category_name)}</a>` : ''}<span>${icon('clock')}${readMinutes(p.content)} min read</span></div>
      <h3><a href="/blog/${esc(p.slug)}">${esc(p.title)}</a></h3>
      <p>${esc(truncate(p.excerpt || stripTags(p.content), 150))}</p>
      <div class="meta"><span>${icon('calendar')}${fmtDate(p.published_at)}</span><span>${icon('user')}${esc(p.author || '')}</span></div>
    </div></article>`;
}
function productCard(p) {
  const out = p.stock_status === 'out_of_stock';
  const data = esc(JSON.stringify({ id: p.id, name: p.name, price: p.price, installable: !!p.installable, unit: p.unit }));
  return `<article class="card card-hover product-card reveal" data-cat="${esc(p.category_slug || '')}">
    <div class="pimg"><img src="${esc(productImg(p))}" alt="${esc(p.name)}" loading="lazy" width="400" height="300"><span class="stock ${esc(p.stock_status)}">${STOCK_LABELS[p.stock_status] || ''}</span></div>
    <div class="pbody">
      <h3>${esc(p.name)}</h3>
      <p>${esc(p.short_description || '')}</p>
      ${p.specs ? `<ul class="specs">${lines(p.specs).slice(0, 3).map((l) => `<li>${esc(l)}</li>`).join('')}</ul>` : ''}
      <div class="price-row"><span class="price">${money(p.price)} <small>/ ${esc(p.unit || 'piece')}</small></span>
        <button type="button" class="btn btn-primary btn-sm add-btn" data-add='${data}' ${out ? 'disabled' : ''}>${out ? 'Unavailable' : `${icon('plus')} Add`}</button></div>
    </div></article>`;
}
function teamCard(m, i) {
  const links = [['facebook', 'Facebook'], ['linkedin', 'LinkedIn'], ['instagram', 'Instagram'], ['x', 'X']].filter(([k]) => /^https?:\/\//.test(m[k] || ''));
  if (m.email) links.push(['email', 'Email']);
  return `<article class="card card-hover team-card reveal d${i % 4}">
    <div class="team-photo">${m.photo ? `<img src="${esc(m.photo)}" alt="${esc(m.name)}" loading="lazy" width="400" height="440">` : `<div class="avatar" aria-hidden="true">${esc(initials(/^team member/i.test(m.name) ? m.position : m.name))}</div>`}
    ${links.length ? `<div class="team-social">${links.map(([k, l]) => `<a href="${k === 'email' ? 'mailto:' + esc(m.email) : esc(m[k])}" ${k === 'email' ? '' : 'target="_blank" rel="noopener noreferrer"'}>${l}</a>`).join('')}</div>` : ''}</div>
    <div class="team-info"><h3>${esc(m.name)}</h3><span class="role">${esc(m.position)}</span><p>${esc(m.bio || '')}</p></div></article>`;
}
function field({ name, label, type = 'text', required = false, full = false, options, placeholder = '', hint = '', attrs = '', value = '' }) {
  const id = `f_${name}_${crypto.randomBytes(2).toString('hex')}`;
  const req = required ? ' required' : '';
  let input;
  if (type === 'textarea') input = `<textarea id="${id}" name="${name}" placeholder="${esc(placeholder)}"${req} ${attrs}>${esc(value)}</textarea>`;
  else if (type === 'select') input = `<select id="${id}" name="${name}"${req} ${attrs}><option value="">${esc(placeholder || 'Select…')}</option>${options.map((o) => { const [v, l] = Array.isArray(o) ? o : [o, o]; return `<option value="${esc(v)}"${String(value) === String(v) ? ' selected' : ''}>${esc(l)}</option>`; }).join('')}</select>`;
  else input = `<input id="${id}" type="${type}" name="${name}" placeholder="${esc(placeholder)}" value="${esc(value)}"${req} ${attrs}>`;
  return `<div class="field${full ? ' full' : ''}"><label for="${id}">${esc(label)}${required ? ' <span class="req">*</span>' : ''}</label>${input}${hint ? `<p class="hint">${esc(hint)}</p>` : ''}</div>`;
}
const honeypot = () => '<div class="hp" aria-hidden="true"><label>Leave this field empty<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>';
const PK_CITIES = ['Lahore', 'Faisalabad', 'Rawalpindi', 'Gujranwala', 'Multan', 'Sialkot', 'Bahawalpur', 'Sargodha', 'Sahiwal', 'Sheikhupura', 'Jhang', 'Rahim Yar Khan', 'Gujrat', 'Kasur', 'Okara', 'Dera Ghazi Khan', 'Chiniot', 'Kamoke', 'Hafizabad', 'Sadiqabad', 'Khanewal', 'Muzaffargarh', 'Jhelum', 'Vehari', 'Attock', 'Other'];

function contactForm(subjectDefault = '') {
  return `<form class="card form-card ajax-form" data-endpoint="/api/contact" novalidate>
    <div class="form-status" role="status"></div>
    <div class="form-grid">
      ${field({ name: 'name', label: 'Full name', required: true, placeholder: 'Your name', attrs: 'autocomplete="name" maxlength="100"' })}
      ${field({ name: 'email', label: 'Email', type: 'email', required: true, placeholder: 'you@example.com', attrs: 'autocomplete="email" maxlength="190"' })}
      ${field({ name: 'phone', label: 'Phone', type: 'tel', placeholder: '03XX XXXXXXX', attrs: 'autocomplete="tel" maxlength="20"' })}
      ${field({ name: 'subject', label: 'Subject', placeholder: 'How can we help?', value: subjectDefault, attrs: 'maxlength="150"' })}
      ${field({ name: 'message', label: 'Message', type: 'textarea', required: true, full: true, placeholder: 'Write your message…', attrs: 'maxlength="4000"' })}
    </div>${honeypot()}
    <div class="form-actions" style="margin-top:20px"><button class="btn btn-primary" type="submit">${icon('mail')} Send message</button><span class="form-note">${icon('lock')} Your details are kept private.</span></div>
  </form>`;
}

function renderPagination(page, pages, makeUrl) {
  if (pages <= 1) return '';
  const out = [];
  if (page > 1) out.push(`<a href="${makeUrl(page - 1)}" aria-label="Previous page">‹</a>`);
  for (let i = 1; i <= pages; i++) {
    if (i === 1 || i === pages || Math.abs(i - page) <= 1) out.push(i === page ? `<span class="cur" aria-current="page">${i}</span>` : `<a href="${makeUrl(i)}">${i}</a>`);
    else if (out[out.length - 1] !== '<span>…</span>') out.push('<span>…</span>');
  }
  if (page < pages) out.push(`<a href="${makeUrl(page + 1)}" aria-label="Next page">›</a>`);
  return `<nav class="pagination" aria-label="Pagination">${out.join('')}</nav>`;
}

function queryPosts({ search = '', categoryId = null, tagSlug = '', page = 1, perPage = 9, featuredFirst = false }) {
  const where = ["p.status = 'published'", '(p.published_at IS NULL OR p.published_at <= ?)'];
  const params = [nowIso()];
  if (categoryId) { where.push('p.category_id = ?'); params.push(categoryId); }
  if (tagSlug) { where.push('p.id IN (SELECT pt.post_id FROM blog_post_tags pt JOIN blog_tags t ON t.id = pt.tag_id WHERE t.slug = ?)'); params.push(tagSlug); }
  if (search) { const l = `%${search}%`; where.push('(p.title LIKE ? OR p.excerpt LIKE ? OR p.content LIKE ?)'); params.push(l, l, l); }
  const w = where.join(' AND ');
  const total = q.val(`SELECT COUNT(*) FROM blog_posts p WHERE ${w}`, ...params);
  const rows = q.all(`SELECT p.id, p.title, p.slug, p.excerpt, p.featured_image, p.published_at, p.author, p.content, p.featured,
      c.name AS category_name, c.slug AS category_slug FROM blog_posts p LEFT JOIN blog_categories c ON c.id = p.category_id
      WHERE ${w} ORDER BY ${featuredFirst ? 'p.featured DESC, ' : ''}p.published_at DESC LIMIT ? OFFSET ?`, ...params, perPage, (page - 1) * perPage);
  return { rows, total, pages: Math.max(1, Math.ceil(total / perPage)) };
}

function testimonialsHtml(limit = 6) {
  const rows = q.all('SELECT * FROM testimonials WHERE active = 1 ORDER BY sort_order, id LIMIT ?', limit);
  if (!rows.length) return '';
  return rows.map((t, i) => `<figure class="card testi reveal d${i % 3}">
    ${t.is_demo ? '<span class="demo-label">Demo content</span>' : ''}
    <div class="stars" aria-label="${t.rating} out of 5">${Array.from({ length: Math.max(0, Math.min(5, t.rating || 0)) }, () => icon('star')).join('')}</div>
    <blockquote>“${esc(t.content)}”</blockquote>
    <figcaption class="who">${t.photo ? `<img src="${esc(t.photo)}" alt="" loading="lazy" width="44" height="44">` : `<span class="av">${esc(initials(t.name))}</span>`}<span><strong>${esc(t.name)}</strong><small>${esc([t.role, t.city].filter(Boolean).join(' · '))}</small></span></figcaption></figure>`).join('');
}

function heroVisual(h) {
  if (h.image) return `<div class="hero-visual reveal d2"><img class="hero-img" src="${esc(h.image)}" alt="" width="640" height="512" fetchpriority="high"></div>`;
  const feeds = [['CAM 01 · GATE', [[8, 40, 30], [44, 55, 22]]], ['CAM 02 · SHOP', [[10, 30, 45], [60, 25, 35]]], ['CAM 03 · PARKING', [[5, 60, 25], [70, 22, 40]]], ['CAM 04 · OFFICE', [[15, 35, 50], [58, 30, 30]]]];
  return `<div class="hero-visual reveal d2" aria-hidden="true">
    <div class="device"><div class="device-bar"><i></i><i></i><i></i><span><span class="rec"></span> LIVE · 4 CAMERAS</span></div>
      <div class="feeds">${feeds.map(([l, shapes], i) => `<div class="feed"><div class="scan" style="animation-delay:-${i * 1.1}s"></div>${shapes.map(([x, w, hgt]) => `<span class="shape" style="left:${x}%;width:${w}%;height:${hgt}%"></span>`).join('')}<b>${l}</b><span class="ts">REC 24/7</span></div>`).join('')}</div>
    </div>
    <div class="float-card fc-1"><span class="ic">${icon('award')}</span><span><strong>Basic Computer Course</strong><small>Module 9 of 13 · Internet Basics</small><span class="progress"><i></i></span></span></div>
    <div class="float-card fc-2"><span class="ic">${icon('shield')}</span><span><strong>System protected</strong><small>Mobile viewing active</small></span></div>
  </div>`;
}

function homePage(req) {
  const H = HOME, st = S();
  const course = getCourse();
  const services = getServices('main');
  const cctv = getServices('cctv');
  const { rows: posts } = queryPosts({ perPage: 3, featuredFirst: true });
  const products = q.all(`SELECT p.*, c.slug AS category_slug FROM products p LEFT JOIN product_categories c ON c.id = p.category_id WHERE p.active = 1 ORDER BY p.featured DESC, p.sort_order LIMIT 4`);
  const team = q.all('SELECT * FROM team_members WHERE active = 1 ORDER BY sort_order, id LIMIT 8');
  const testi = H.testimonials.enabled ? testimonialsHtml() : '';
  const syl = pairs(course?.syllabus).slice(0, 8);
  const titleHtml = esc(H.hero.title).replace(/(homes, students &amp; businesses|technology)/i, '<em>$1</em>');
  const out = [];
  out.push(`<section class="hero"><div class="container hero-grid">
    <div class="reveal"><p class="eyebrow light">${esc(H.hero.eyebrow)}</p><h1>${titleHtml}</h1><p class="lead">${esc(H.hero.subtitle)}</p>
      <div class="hero-actions">${H.hero.primary_text ? `<a class="btn btn-primary" href="${esc(H.hero.primary_link)}">${esc(H.hero.primary_text)} ${icon('arrow')}</a>` : ''}${H.hero.secondary_text ? `<a class="btn btn-ghost-light" href="${esc(H.hero.secondary_link)}">${icon('cart')} ${esc(H.hero.secondary_text)}</a>` : ''}</div>
      <div class="hero-stats">${[1, 2, 3].filter((i) => H.hero[`stat${i}_value`]).map((i) => `<div><strong>${esc(H.hero[`stat${i}_value`])}</strong><span>${esc(H.hero[`stat${i}_label`])}</span></div>`).join('')}</div>
    </div>${heroVisual(H.hero)}</div></section>`);
  if (H.intro.enabled) out.push(`<section class="section"><div class="container split">
    <div class="reveal">${H.intro.image ? `<img src="${esc(H.intro.image)}" alt="" loading="lazy" style="border-radius:20px;box-shadow:var(--shadow-lg)">` : `<div class="visual-panel">
      <div class="vp-stat"><span class="ic-box">${icon('book')}</span><span><strong>IT Education</strong><small>Basic Computer Course · ${money(course?.fee || 300)}/${esc(course?.fee_period || 'month')}</small></span></div>
      <div class="vp-stat"><span class="ic-box">${icon('cctv')}</span><span><strong>CCTV Security</strong><small>Installation, repair &amp; maintenance</small></span></div>
      <div class="vp-stat"><span class="ic-box">${icon('file')}</span><span><strong>Technology Blog</strong><small>Mobile, Windows &amp; CCTV guides</small></span></div>
      <div class="vp-stat"><span class="ic-box">${icon('users')}</span><span><strong>Application Assistance</strong><small>Guided, private and secure</small></span></div></div>`}</div>
    <div class="reveal d1">${sectionHead({ eyebrow: H.intro.eyebrow, title: H.intro.title })}<p>${esc(H.intro.text)}</p><ul class="checklist">${lines(H.intro.points).map((p) => `<li>${icon('check')}<span>${esc(p)}</span></li>`).join('')}</ul><a class="link-arrow" href="/about">More about SDS ${icon('arrow')}</a></div>
  </div></section>`);
  if (H.services.enabled && services.length) out.push(`<section class="section soft"><div class="container">${sectionHead(H.services, { center: true })}
    <div class="grid g-3">${services.map((s, i) => `<article class="card card-hover svc-card reveal d${i % 3}"><span class="svc-num">0${i + 1}</span><span class="ic-box">${icon(s.icon)}</span><h3>${esc(s.title)}</h3><p>${esc(s.summary)}</p>${s.link ? `<a class="link-arrow" href="${esc(s.link)}">Learn more ${icon('arrow')}</a>` : ''}</article>`).join('')}</div></div></section>`);
  if (H.blog.enabled && posts.length) out.push(`<section class="section"><div class="container"><div class="head-row">${sectionHead(H.blog)}<a class="btn btn-outline" href="/blog">View all articles ${icon('arrow')}</a></div>
    <div class="grid g-3">${posts.map((p, i) => postCard(p, { reveal: `d${i}` })).join('')}</div>
    <div class="cat-tabs" style="margin:32px 0 0;justify-content:center">${q.all('SELECT name, slug FROM blog_categories ORDER BY sort_order').map((c) => `<a href="/blog/category/${esc(c.slug)}">${esc(c.name)}</a>`).join('')}</div></div></section>`);
  if (H.course.enabled && course) out.push(`<section class="section soft"><div class="container course-band">
    <div class="reveal">${sectionHead(H.course)}<div class="mini-syllabus">${syl.map((m, i) => `<span><b>${String(i + 1).padStart(2, '0')}</b>${esc(m.title)}</span>`).join('')}</div>
      <div class="hero-actions"><a class="btn btn-primary" href="/course">${esc(H.course.button_text || 'View course')} ${icon('arrow')}</a><a class="btn btn-outline" href="/course#enrol">Enrol now</a></div></div>
    <div class="reveal d1"><div class="fee-card"><p class="eyebrow light">Monthly fee</p><div class="price">${money(course.fee)} <small>/ ${esc(course.fee_period)}</small></div>
      <ul><li>${icon('check')}${esc(course.duration || '')}</li><li>${icon('check')}${pairs(course.syllabus).length} practical modules</li><li>${icon('check')}Verifiable SDS certificate</li><li>${icon('check')}${esc(truncate(course.schedule || '', 80))}</li></ul>
      <a class="btn btn-light btn-block" href="/course#enrol">${course.enrollment_open ? 'Reserve your seat' : 'Enrolment currently closed'}</a></div></div>
  </div></section>`);
  if (H.cctv.enabled) out.push(`<section class="section dark cctv-band"><div class="container">
    <div class="head-row">${sectionHead(H.cctv, { light: true })}<a class="btn btn-primary" href="/cctv#request">${esc(H.cctv.button_text || 'Request a visit')} ${icon('arrow')}</a></div>
    <div class="svc-list">${cctv.slice(0, 9).map((s, i) => `<div class="svc-item reveal d${i % 3}"><span class="ic-box">${icon(s.icon)}</span><div><h3>${esc(s.title)}</h3><p>${esc(s.summary)}</p></div></div>`).join('')}</div>
    <div class="coverage">${icon('pin')}<span>Services available across <strong>${esc(st.general.service_area)}</strong>, subject to availability and scheduling. <a href="/cctv" style="color:#fff;text-decoration:underline">See all ${cctv.length} CCTV services</a></span></div>
  </div></section>`);
  if (H.products.enabled && products.length) out.push(`<section class="section"><div class="container"><div class="head-row">${sectionHead(H.products)}<a class="btn btn-outline" href="/cctv/products">Open catalogue ${icon('arrow')}</a></div>
    <div class="product-grid">${products.map(productCard).join('')}</div></div></section>`);
  if (H.scheme.enabled) out.push(`<section class="section soft"><div class="container split rev">
    <div class="reveal d1"><div class="card" style="padding:34px"><ol class="steps">
      <li><strong>Submit your details</strong><span>Fill in the secure assistance form on our website.</span></li>
      <li><strong>We contact you</strong><span>Our team reviews your information and calls you to confirm details.</span></li>
      <li><strong>Application prepared</strong><span>We help prepare and submit your application manually, with your consent.</span></li>
      <li><strong>Follow-up support</strong><span>We keep you informed about the status of our assistance.</span></li></ol></div></div>
    <div class="reveal">${sectionHead(H.scheme)}<div class="notice-box" style="margin-bottom:24px">${icon('shield')}<div><strong>Assistance only.</strong> SDS is not a government authority and does not guarantee eligibility or approval.</div></div>
      <a class="btn btn-primary" href="/apna-ghar-apni-chat">${esc(H.scheme.button_text || 'Request assistance')} ${icon('arrow')}</a></div>
  </div></section>`);
  if (H.team.enabled && team.length) out.push(`<section class="section"><div class="container">${sectionHead(H.team, { center: true })}<div class="team-grid">${team.map(teamCard).join('')}</div></div></section>`);
  if (H.certificate.enabled) out.push(`<section class="section soft"><div class="container split">
    <div class="reveal">${sectionHead(H.certificate)}<ul class="checklist"><li>${icon('check')}Unique certificate ID on every certificate</li><li>${icon('check')}Print-ready, professional A4 design</li><li>${icon('check')}Instant public verification online</li></ul>
      <form class="verify-form" action="/verify" method="get" role="search"><input type="text" name="id" placeholder="Enter certificate ID, e.g. SDS-BCC-2026-ABC123" aria-label="Certificate ID" maxlength="40" required><button class="btn btn-dark" type="submit">${icon('search')} Verify</button></form></div>
    <div class="reveal d1"><div class="cert-mini" aria-hidden="true"><div class="inner"><small>Smart Digital Services</small><div class="ct">${esc(st.certificate.title)}</div><small>${esc(st.certificate.subtitle)}</small><div class="nm">Student Name</div><small>${esc(st.certificate.body)} ${esc(course?.name || 'Basic Computer Course')}</small>
      <div class="row"><span>ID: SDS-BCC-0000-XXXXXX</span><span class="seal">${icon('award')}</span><span>Authorised Signatory</span></div></div></div></div>
  </div></section>`);
  if (H.why.enabled) out.push(`<section class="section"><div class="container">${sectionHead(H.why, { center: true })}<div class="why-grid">${pairs(H.why.items).map((w, i) => `<div class="why-item reveal d${i % 3}"><span class="n">${String(i + 1).padStart(2, '0')}</span><h3>${esc(w.title)}</h3><p>${esc(w.text)}</p></div>`).join('')}</div></div></section>`);
  if (testi) out.push(`<section class="section soft"><div class="container">${sectionHead(H.testimonials, { center: true })}<div class="grid g-3">${testi}</div></div></section>`);
  if (H.contact.enabled) out.push(`<section class="section ${testi ? '' : 'soft'}" id="contact"><div class="container contact-grid">
    <div class="reveal">${sectionHead(H.contact)}${contactInfoList()}</div><div class="reveal d1">${contactForm()}</div></div></section>`);
  if (H.cta.enabled) out.push(ctaBand(H.cta));
  return layout(req, { title: '', description: st.seo.meta_description, body: out.join(''), path: '/' });
}
function ctaBand(c = HOME.cta) {
  return `<section class="section tight"><div class="container"><div class="cta-band reveal"><div><h2>${esc(c.title)}</h2><p>${esc(c.text)}</p></div><a class="btn btn-light" href="${esc(c.button_link || '/contact')}">${esc(c.button_text || 'Contact us')} ${icon('arrow')}</a></div></div></section>`;
}
function contactInfoList() {
  const c = S().contact, wa = waLink();
  return `<ul class="info-list">
    <li><span class="ic-box">${icon('call')}</span><div><strong>Phone</strong><a href="${telLink()}">${esc(c.phone)}</a></div></li>
    <li><span class="ic-box">${icon('mail')}</span><div><strong>Email support</strong><a href="mailto:${esc(c.email)}">${esc(c.email)}</a>${c.support_note ? `<br><small class="muted">${esc(c.support_note)}</small>` : ''}</div></li>
    ${wa ? `<li><span class="ic-box">${icon('chat')}</span><div><strong>WhatsApp</strong><a href="${esc(wa)}" target="_blank" rel="noopener">Chat with us on WhatsApp</a></div></li>` : ''}
    <li><span class="ic-box">${icon('pin')}</span><div><strong>Address</strong><span>${esc(c.address)}</span>${/^https?:\/\//.test(c.map_link || '') ? `<br><a href="${esc(c.map_link)}" target="_blank" rel="noopener">Open in maps</a>` : ''}</div></li>
    <li><span class="ic-box">${icon('clock')}</span><div><strong>Working hours</strong><span>${esc(c.hours)}</span></div></li></ul>`;
}

function aboutPage(req) {
  const H = HOME;
  const team = q.all('SELECT * FROM team_members WHERE active = 1 ORDER BY sort_order, id');
  const body = `${pageHero({ eyebrow: 'About us', title: 'Technology made practical, safe and affordable', text: H.intro.text, crumbs: [['About']] })}
  <section class="section"><div class="container split"><div class="reveal">${sectionHead({ eyebrow: 'Our mission', title: 'Helping Punjab get more from technology' })}
    <p>We started Smart Digital Services to close a simple gap: many people need reliable technology help but do not know whom to trust. We focus on clear advice, fair prices and work we are proud to put our name on.</p>
    <ul class="checklist">${lines(H.intro.points).map((p) => `<li>${icon('check')}<span>${esc(p)}</span></li>`).join('')}</ul></div>
    <div class="grid g-2 reveal d1">${[['book', 'Education', 'Affordable, hands-on computer training with verifiable certificates.'], ['cctv', 'Security', 'CCTV systems designed around your property and budget.'], ['file', 'Knowledge', 'Free, original guides that solve real technology problems.'], ['users', 'Assistance', 'Private, careful help with online applications.']].map(([ic, t, d]) => `<div class="card"><span class="ic-box">${icon(ic)}</span><h3>${t}</h3><p class="muted" style="margin:0">${d}</p></div>`).join('')}</div>
  </div></section>
  ${team.length ? `<section class="section soft"><div class="container">${sectionHead(H.team, { center: true })}<div class="team-grid">${team.map(teamCard).join('')}</div></div></section>` : ''}
  <section class="section"><div class="container">${sectionHead(H.why, { center: true })}<div class="why-grid">${pairs(H.why.items).map((w, i) => `<div class="why-item reveal"><span class="n">${String(i + 1).padStart(2, '0')}</span><h3>${esc(w.title)}</h3><p>${esc(w.text)}</p></div>`).join('')}</div></div></section>
  ${ctaBand()}`;
  return layout(req, { title: 'About Smart Digital Services', description: H.intro.text, body });
}

function servicesPage(req) {
  const main = getServices('main'), cctv = getServices('cctv');
  const body = `${pageHero({ eyebrow: 'Services', title: 'Everything SDS can do for you', text: HOME.services.subtitle, crumbs: [['Services']] })}
  <section class="section"><div class="container"><div class="grid g-3">${main.map((s, i) => `<article class="card card-hover svc-card reveal d${i % 3}"><span class="svc-num">0${i + 1}</span><span class="ic-box">${icon(s.icon)}</span><h3>${esc(s.title)}</h3><p>${esc(s.summary)}</p>${s.description ? `<div class="muted" style="font-size:.93rem;margin-bottom:16px">${nl2br(s.description)}</div>` : ''}${s.link ? `<a class="link-arrow" href="${esc(s.link)}">Learn more ${icon('arrow')}</a>` : ''}</article>`).join('')}</div></div></section>
  <section class="section soft"><div class="container">${sectionHead({ eyebrow: 'CCTV services', title: 'Complete CCTV support from survey to maintenance', subtitle: `Available across ${S().general.service_area}, subject to availability and scheduling.` })}
    <div class="svc-list light">${cctv.map((s) => `<div class="svc-item reveal"><span class="ic-box">${icon(s.icon)}</span><div><h3>${esc(s.title)}</h3><p>${esc(s.summary)}</p></div></div>`).join('')}</div>
    <div style="margin-top:32px" class="hero-actions"><a class="btn btn-primary" href="/cctv#request">Request a site visit ${icon('arrow')}</a><a class="btn btn-outline" href="/cctv/products">Browse products</a></div></div></section>
  ${ctaBand()}`;
  return layout(req, { title: 'Services — Computer Course, CCTV, IT Support', description: 'Smart Digital Services: Basic Computer Course, CCTV installation and maintenance across Punjab, CCTV product quotations, computer and mobile support and online application assistance.', body });
}

function blogSidebar(activeCat) {
  const cats = q.all(`SELECT c.*, (SELECT COUNT(*) FROM blog_posts p WHERE p.category_id = c.id AND p.status = 'published') AS n FROM blog_categories c ORDER BY c.sort_order, c.name`);
  const tags = q.all(`SELECT t.name, t.slug, COUNT(*) AS n FROM blog_tags t JOIN blog_post_tags pt ON pt.tag_id = t.id JOIN blog_posts p ON p.id = pt.post_id AND p.status = 'published' GROUP BY t.id ORDER BY n DESC, t.name LIMIT 24`);
  return `<aside class="sidebar">
    <div class="card"><h3>Search articles</h3><form class="search-box" action="/blog" method="get" role="search"><input type="search" name="q" placeholder="e.g. WhatsApp, DVR, Windows" aria-label="Search articles" maxlength="80"><button class="btn btn-dark btn-sm" type="submit" aria-label="Search">${icon('search')}</button></form></div>
    <div class="card"><h3>Categories</h3><ul class="cat-list"><li><a href="/blog" class="${!activeCat ? 'active' : ''}">All articles</a></li>${cats.map((c) => `<li><a href="/blog/category/${esc(c.slug)}" class="${activeCat === c.id ? 'active' : ''}">${esc(c.name)} <em>${c.n}</em></a></li>`).join('')}</ul></div>
    ${tags.length ? `<div class="card"><h3>Popular tags</h3><div class="tag-cloud">${tags.map((t) => `<a href="/blog?tag=${esc(t.slug)}">${esc(t.name)}</a>`).join('')}</div></div>` : ''}
    <div class="card" style="background:var(--navy-900);border-color:var(--navy-900);color:#c7d2e3"><h3 style="color:#fff">Need hands-on help?</h3><p style="font-size:.92rem">Our technicians can fix phones, computers and CCTV systems for you.</p><a class="btn btn-light btn-sm" href="/contact">Contact support</a></div>
  </aside>`;
}

function blogIndex(req, res, category) {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const search = cleanText(req.query.q, 80);
  const tagSlug = slugify(req.query.tag || '') === 'item' ? '' : slugify(req.query.tag || '');
  const perPage = Math.min(30, Math.max(3, parseInt(S().blog.posts_per_page, 10) || 9));
  const { rows, total, pages } = queryPosts({ search, categoryId: category?.id, tagSlug, page, perPage });
  const tag = tagSlug ? q.get('SELECT * FROM blog_tags WHERE slug = ?', tagSlug) : null;
  const base = category ? `/blog/category/${category.slug}` : '/blog';
  const qs = (p) => { const u = new URLSearchParams(); if (search) u.set('q', search); if (tagSlug) u.set('tag', tagSlug); if (p > 1) u.set('page', p); const s = u.toString(); return base + (s ? '?' + s : ''); };
  const heading = category ? category.name : tag ? `Articles tagged “${tag.name}”` : search ? `Search results for “${search}”` : 'Smart Digital Blog';
  const intro = category ? category.description : HOME.blog.subtitle;
  let list;
  if (!rows.length) list = `<div class="empty">${icon('search')}<h3>No articles found</h3><p>Try a different search term or browse all categories.</p><a class="btn btn-outline" href="/blog">View all articles</a></div>`;
  else if (page === 1 && !search && !tagSlug && rows.length > 2) {
    const [first, ...rest] = rows;
    list = `<article class="card card-hover post-card post-feature reveal" style="margin-bottom:24px"><a class="thumb" href="/blog/${esc(first.slug)}" tabindex="-1" aria-hidden="true"><img src="${esc(coverUrl(first))}" alt="" width="1200" height="630"></a><div class="body"><div class="meta" style="margin-bottom:14px">${first.category_name ? `<span class="chip">${esc(first.category_name)}</span>` : ''}<span>${icon('clock')}${readMinutes(first.content)} min read</span></div><h3><a href="/blog/${esc(first.slug)}">${esc(first.title)}</a></h3><p>${esc(truncate(first.excerpt, 220))}</p><div class="meta"><span>${icon('calendar')}${fmtDate(first.published_at)}</span></div><a class="link-arrow" style="margin-top:18px" href="/blog/${esc(first.slug)}">Read article ${icon('arrow')}</a></div></article>
      <div class="grid g-2">${rest.map((p) => postCard(p)).join('')}</div>`;
  } else list = `<div class="grid g-2">${rows.map((p) => postCard(p)).join('')}</div>`;
  const body = `${pageHero({ eyebrow: category ? 'Blog category' : 'Smart Digital Blog', title: heading, text: intro, crumbs: category ? [['Blog', '/blog'], [category.name]] : [['Blog']] })}
  <section class="section"><div class="container blog-layout"><div><p class="muted" style="margin-bottom:22px">${total} article${total === 1 ? '' : 's'}</p>${list}${renderPagination(page, pages, qs)}</div>${blogSidebar(category?.id)}</div></section>`;
  return layout(req, { title: category ? `${category.name} — Blog` : 'Smart Digital Blog — Mobile, Windows & CCTV Guides', description: intro, body, noindex: !!search, path: req.path + (page > 1 ? `?page=${page}` : '') });
}

function blogPost(req, res, post) {
  q.run('UPDATE blog_posts SET views = views + 1 WHERE id = ?', post.id);
  const cat = post.category_id ? q.get('SELECT * FROM blog_categories WHERE id = ?', post.category_id) : null;
  const tags = postTags(post.id);
  let related = q.all(`SELECT p.*, c.name AS category_name, c.slug AS category_slug FROM blog_posts p LEFT JOIN blog_categories c ON c.id = p.category_id
    WHERE p.status = 'published' AND p.id != ? AND p.category_id IS ? ORDER BY p.published_at DESC LIMIT 3`, post.id, post.category_id);
  if (related.length < 3) related = related.concat(q.all(`SELECT p.*, c.name AS category_name, c.slug AS category_slug FROM blog_posts p LEFT JOIN blog_categories c ON c.id = p.category_id WHERE p.status = 'published' AND p.id != ? AND p.id NOT IN (${related.map((r) => r.id).join(',') || 0}) ORDER BY p.published_at DESC LIMIT ?`, post.id, 3 - related.length));
  const commentsOn = S().blog.comments_enabled && post.allow_comments;
  const comments = commentsOn ? q.all("SELECT name, comment, created_at FROM blog_comments WHERE post_id = ? AND status = 'approved' ORDER BY created_at", post.id) : [];
  const url = baseUrl(req) + '/blog/' + post.slug;
  const body = `<section class="page-hero"><div class="container article-head">
      <nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a> <span>/</span> <a href="/blog">Blog</a>${cat ? ` <span>/</span> <a href="/blog/category/${esc(cat.slug)}">${esc(cat.name)}</a>` : ''}</nav>
      ${cat ? `<a class="chip dark" href="/blog/category/${esc(cat.slug)}">${esc(cat.name)}</a>` : ''}
      <h1 style="margin-top:16px">${esc(post.title)}</h1>
      <div class="meta"><span>${icon('user')}${esc(post.author || '')}</span><span>${icon('calendar')}${fmtDate(post.published_at)}</span><span>${icon('clock')}${readMinutes(post.content)} min read</span><span>${icon('eye')}${post.views + 1} views</span></div>
    </div></section>
  <section class="section" style="padding-top:0"><div class="container">
    <div class="article-cover"><img src="${esc(coverUrl(post))}" alt="${esc(post.title)}" width="1200" height="630"></div>
    <div class="blog-layout" style="margin-top:56px"><article>
      <div class="prose">${post.content}</div>
      ${tags.length ? `<div class="article-tags">${icon('tag')} ${tags.map((t) => `<a class="chip" href="/blog?tag=${esc(t.slug)}">${esc(t.name)}</a>`).join('')}</div>` : '<div class="article-tags"></div>'}
      <div class="share"><strong>Share:</strong> <a class="btn btn-outline btn-sm" href="https://wa.me/?text=${encodeURIComponent(post.title + ' ' + url)}" target="_blank" rel="noopener">WhatsApp</a><a class="btn btn-outline btn-sm" href="https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(url)}" target="_blank" rel="noopener">Facebook</a><button class="btn btn-outline btn-sm" type="button" data-copy="${esc(url)}">${icon('link')} Copy link</button></div>
      ${commentsOn ? `<div class="comments"><h2 style="font-size:1.4rem">Comments (${comments.length})</h2>
        ${comments.map((c) => `<div class="comment"><strong>${esc(c.name)}</strong> <span class="muted" style="font-size:.85rem">· ${fmtDate(c.created_at)}</span><p style="margin:.4em 0 0">${nl2br(c.comment)}</p></div>`).join('') || '<p class="muted">No comments yet. Be the first to share your thoughts.</p>'}
        <form class="card form-card ajax-form" data-endpoint="/api/comments" data-reset="1" style="margin-top:24px" novalidate><h3>Leave a comment</h3><p class="muted" style="font-size:.9rem">Comments are reviewed before they appear. Your email is never published.</p>
          <div class="form-status" role="status"></div><input type="hidden" name="post_id" value="${post.id}">
          <div class="form-grid">${field({ name: 'name', label: 'Name', required: true, attrs: 'maxlength="80"' })}${field({ name: 'email', label: 'Email (private)', type: 'email', attrs: 'maxlength="190"' })}${field({ name: 'comment', label: 'Comment', type: 'textarea', required: true, full: true, attrs: 'maxlength="2000"' })}</div>${honeypot()}
          <div class="form-actions" style="margin-top:18px"><button class="btn btn-primary" type="submit">Submit comment</button></div></form></div>` : ''}
    </article>${blogSidebar(post.category_id)}</div>
    ${related.length ? `<div style="margin-top:80px">${sectionHead({ eyebrow: 'Keep reading', title: 'Related articles' })}<div class="grid g-3">${related.map((p, i) => postCard(p, { reveal: `d${i}` })).join('')}</div></div>` : ''}
  </div></section>`;
  const ld = { '@context': 'https://schema.org', '@type': 'BlogPosting', headline: post.title, description: post.meta_description || post.excerpt, datePublished: post.published_at, dateModified: post.updated_at || post.published_at, author: { '@type': 'Organization', name: post.author || S().general.site_name }, publisher: { '@type': 'Organization', name: S().general.site_name }, mainEntityOfPage: url, image: baseUrl(req) + coverUrl(post), keywords: tags.map((t) => t.name).join(', ') };
  return layout(req, { title: post.seo_title ? post.seo_title.replace(/\s*\|\s*SDS Blog$/, '') : post.title, description: post.meta_description || post.excerpt, body, ogType: 'article', ogImage: coverUrl(post), jsonLd: [ld] });
}

function coursePage(req) {
  const c = getCourse();
  if (!c) return null;
  const syl = pairs(c.syllabus);
  const body = `${pageHero({ eyebrow: 'IT Education', title: c.name, text: c.tagline, crumbs: [['Computer Course']], extra: `<div class="hero-actions" style="margin-top:28px"><a class="btn btn-primary" href="#enrol">Enrol now ${icon('arrow')}</a><a class="btn btn-ghost-light" href="#syllabus">View syllabus</a></div>` })}
  <section class="section"><div class="container split" style="align-items:start">
    <div class="reveal">${sectionHead({ eyebrow: 'Course introduction', title: 'Build real computer confidence' })}<p>${nl2br(c.description)}</p>
      <h3 style="margin-top:32px">Learning objectives</h3><ul class="checklist">${lines(c.objectives).map((o) => `<li>${icon('check')}<span>${esc(o)}</span></li>`).join('')}</ul></div>
    <div class="reveal d1"><div class="fee-card"><p class="eyebrow light">Course fee</p><div class="price">${money(c.fee)} <small>/ ${esc(c.fee_period)}</small></div>
      <ul><li>${icon('clock')}<span><strong style="color:#fff">Duration:</strong> ${esc(c.duration)}</span></li><li>${icon('calendar')}<span><strong style="color:#fff">Schedule:</strong> ${esc(c.schedule)}</span></li><li>${icon('user')}<span><strong style="color:#fff">Requirements:</strong> ${esc(c.requirements)}</span></li><li>${icon('award')}<span>Verifiable SDS certificate on successful completion</span></li></ul>
      <a class="btn btn-light btn-block" href="#enrol">${c.enrollment_open ? 'Reserve your seat' : 'Join the waiting list'}</a></div></div>
  </div></section>
  <section class="section soft" id="syllabus"><div class="container">${sectionHead({ eyebrow: 'Course syllabus', title: `${syl.length} practical modules`, subtitle: 'Each module combines a short explanation with guided practice on a real computer.' }, { center: true })}
    <ol class="syllabus grid g-2">${syl.map((m) => `<li class="reveal"><div><strong>${esc(m.title)}</strong><span>${esc(m.text)}</span></div></li>`).join('')}</ol></div></section>
  <section class="section" id="enrol"><div class="container split" style="align-items:start">
    <div class="reveal">${sectionHead({ eyebrow: 'Registration', title: 'Enrol in the Basic Computer Course', subtitle: 'Fill in the form and our team will call you to confirm your batch and timing.' })}
      <ol class="steps"><li><strong>Submit the form</strong><span>It takes less than two minutes.</span></li><li><strong>Confirmation call</strong><span>We confirm your batch, timing and fee.</span></li><li><strong>Start learning</strong><span>Attend classes and practise with our trainers.</span></li><li><strong>Get certified</strong><span>Receive a verifiable SDS certificate on completion.</span></li></ol></div>
    <div class="reveal d1">${c.enrollment_open ? `<form class="card form-card ajax-form" data-endpoint="/api/enroll" novalidate>
      <div class="form-status" role="status"></div><input type="hidden" name="course_id" value="${c.id}">
      <div class="form-grid">
        ${field({ name: 'full_name', label: 'Student full name', required: true, attrs: 'maxlength="100" autocomplete="name"' })}
        ${field({ name: 'father_name', label: "Father's name", required: true, attrs: 'maxlength="100"' })}
        ${field({ name: 'phone', label: 'Mobile number', type: 'tel', required: true, placeholder: '03XX XXXXXXX', attrs: 'maxlength="20" autocomplete="tel"' })}
        ${field({ name: 'email', label: 'Email (optional)', type: 'email', attrs: 'maxlength="190"' })}
        ${field({ name: 'gender', label: 'Gender', type: 'select', options: ['Male', 'Female', 'Prefer not to say'] })}
        ${field({ name: 'education', label: 'Education', type: 'select', options: ['Primary', 'Middle', 'Matric', 'Intermediate', 'Graduate', 'Other'] })}
        ${field({ name: 'city', label: 'City', type: 'select', required: true, options: PK_CITIES })}
        ${field({ name: 'preferred_timing', label: 'Preferred timing', type: 'select', options: ['Morning', 'Afternoon', 'Evening'] })}
        ${field({ name: 'address', label: 'Address', full: true, attrs: 'maxlength="250"' })}
        ${field({ name: 'message', label: 'Anything we should know? (optional)', type: 'textarea', full: true, attrs: 'maxlength="1000"' })}
      </div>${honeypot()}
      <div class="form-actions" style="margin-top:20px"><button class="btn btn-primary" type="submit">Submit enrolment</button><span class="form-note">${icon('lock')} Fee: ${money(c.fee)} per ${esc(c.fee_period)}</span></div></form>`
    : `<div class="alert alert-info">${icon('clock')}<div><strong>Enrolment is currently closed.</strong> Please send us a message and we will contact you when the next batch opens.</div></div>${contactForm('Basic Computer Course — next batch')}`}</div>
  </div></section>
  <section class="section soft"><div class="container split"><div>${sectionHead(HOME.certificate)}<a class="btn btn-outline" href="/verify">Verify a certificate ${icon('arrow')}</a></div><div class="cert-mini" aria-hidden="true"><div class="inner"><small>Smart Digital Services</small><div class="ct">${esc(S().certificate.title)}</div><div class="nm">Your Name</div><small>${esc(c.name)}</small></div></div></div></section>`;
  const ld = { '@context': 'https://schema.org', '@type': 'Course', name: c.name, description: c.tagline || stripTags(c.description).slice(0, 200), provider: { '@type': 'Organization', name: S().general.site_name, sameAs: baseUrl(req) }, offers: { '@type': 'Offer', price: c.fee, priceCurrency: S().currency.code, category: 'Monthly fee' }, hasCourseInstance: { '@type': 'CourseInstance', courseMode: 'onsite', courseWorkload: c.duration } };
  return layout(req, { title: `${c.name} — ${money(c.fee)} per ${c.fee_period}`, description: `${c.tagline} ${stripTags(c.description)}`.slice(0, 165), body, jsonLd: [ld] });
}

function cctvPage(req) {
  const cctv = getServices('cctv');
  const { rows: guides } = queryPosts({ categoryId: q.val("SELECT id FROM blog_categories WHERE slug = 'cctv-cameras'"), perPage: 3 });
  const body = `${pageHero({ eyebrow: 'CCTV Security Solutions', title: HOME.cctv.title, text: HOME.cctv.text, crumbs: [['CCTV']], extra: `<div class="hero-actions" style="margin-top:28px"><a class="btn btn-primary" href="#request">Request a site visit ${icon('arrow')}</a><a class="btn btn-ghost-light" href="/cctv/products">${icon('cart')} Product catalogue</a></div>` })}
  <section class="section"><div class="container">${sectionHead({ eyebrow: 'Our CCTV services', title: 'Installation, configuration, repair and maintenance', subtitle: 'Whether you need a brand-new system or want an old one fixed, our technicians handle it end to end.' })}
    <div class="svc-list light">${cctv.map((s, i) => `<div class="svc-item reveal d${i % 3}"><span class="ic-box">${icon(s.icon)}</span><div><h3>${esc(s.title)}</h3><p>${esc(s.summary)}</p></div></div>`).join('')}</div>
    <div class="alert alert-info" style="margin-top:32px">${icon('pin')}<div>CCTV services are available across <strong>${esc(S().general.service_area)}</strong>, subject to availability and scheduling. Travel charges may apply for distant locations.</div></div></div></section>
  <section class="section dark"><div class="container split"><div>${sectionHead({ eyebrow: 'How it works', title: 'A clear process from survey to support' }, { light: true })}
    <ol class="steps"><li><strong>Consultation &amp; site survey</strong><span>We assess coverage, lighting, cabling routes and your budget.</span></li><li><strong>Transparent quotation</strong><span>You receive an itemised quotation in PKR — no hidden charges.</span></li><li><strong>Professional installation</strong><span>Neat cabling, secure mounting and careful configuration.</span></li><li><strong>Mobile viewing &amp; training</strong><span>We set up the app on your phone and show you how to play back footage.</span></li><li><strong>Maintenance &amp; support</strong><span>Health checks, cleaning, repairs and upgrades whenever you need them.</span></li></ol></div>
    <div class="visual-panel"><div class="vp-stat"><span class="ic-box">${icon('cctv')}</span><span><strong>HD &amp; IP cameras</strong><small>2MP to 8MP, dome, bullet &amp; PTZ</small></span></div><div class="vp-stat"><span class="ic-box">${icon('server')}</span><span><strong>DVR &amp; NVR systems</strong><small>4 to 32 channels</small></span></div><div class="vp-stat"><span class="ic-box">${icon('phone')}</span><span><strong>Remote viewing</strong><small>Android &amp; iPhone apps configured</small></span></div><div class="vp-stat"><span class="ic-box">${icon('wrench')}</span><span><strong>Repair &amp; maintenance</strong><small>For existing systems of most brands</small></span></div></div>
  </div></section>
  <section class="section soft" id="request"><div class="container split" style="align-items:start">
    <div>${sectionHead({ eyebrow: 'Service request', title: 'Book a CCTV visit or repair', subtitle: 'Tell us what you need and we will call you to confirm a convenient time.' })}${contactInfoList()}</div>
    <form class="card form-card ajax-form" data-endpoint="/api/cctv-request" novalidate><div class="form-status" role="status"></div>
      <div class="form-grid">
        ${field({ name: 'name', label: 'Customer name', required: true, attrs: 'maxlength="100" autocomplete="name"' })}
        ${field({ name: 'phone', label: 'Phone number', type: 'tel', required: true, placeholder: '03XX XXXXXXX', attrs: 'maxlength="20" autocomplete="tel"' })}
        ${field({ name: 'city', label: 'City', type: 'select', required: true, options: PK_CITIES })}
        ${field({ name: 'service_type', label: 'Service type', type: 'select', required: true, options: cctv.map((s) => s.title).concat(['Other']) })}
        ${field({ name: 'address', label: 'Address', required: true, full: true, attrs: 'maxlength="250" autocomplete="street-address"' })}
        ${field({ name: 'cameras', label: 'Number of cameras', type: 'number', attrs: 'min="0" max="500"' })}
        ${field({ name: 'preferred_date', label: 'Preferred visit date', type: 'date', attrs: `min="${today()}"` })}
        ${field({ name: 'details', label: 'Additional details', type: 'textarea', full: true, placeholder: 'Property type, existing equipment, problems you are facing…', attrs: 'maxlength="2000"' })}
      </div>${honeypot()}
      <div class="form-actions" style="margin-top:20px"><button class="btn btn-primary" type="submit">${icon('calendar')} Submit request</button><span class="form-note">${icon('lock')} We only use your details to arrange the visit.</span></div></form>
  </div></section>
  ${guides.length ? `<section class="section"><div class="container"><div class="head-row">${sectionHead({ eyebrow: 'CCTV knowledge base', title: 'Helpful CCTV guides' })}<a class="btn btn-outline" href="/blog/category/cctv-cameras">All CCTV articles</a></div><div class="grid g-3">${guides.map((p) => postCard(p)).join('')}</div></div></section>` : ''}`;
  return layout(req, { title: 'CCTV Installation, Repair & Maintenance in Punjab', description: `Professional CCTV installation, DVR/NVR setup, IP cameras, remote mobile viewing, repair and maintenance across ${S().general.service_area}. Request a site visit online.`, body });
}

function chargesConfig() {
  const c = S().charges;
  return { installation_base: +c.installation_base || 0, installation_per_camera: +c.installation_per_camera || 0, delivery_charge: +c.delivery_charge || 0,
    free_delivery_above: +c.free_delivery_above || 0, discount_percent: +c.discount_percent || 0, discount_threshold: +c.discount_threshold || 0 };
}
function computeTotals(items, { include_installation, include_delivery }, cfg = chargesConfig()) {
  const subtotal = items.reduce((s, i) => s + i.unit_price * i.quantity, 0);
  const cams = items.reduce((s, i) => s + (i.installable ? i.quantity : 0), 0);
  const installation = include_installation && items.length ? cfg.installation_base + cfg.installation_per_camera * cams : 0;
  const delivery = include_delivery && items.length ? (cfg.free_delivery_above > 0 && subtotal >= cfg.free_delivery_above ? 0 : cfg.delivery_charge) : 0;
  const discount = cfg.discount_percent > 0 && subtotal >= cfg.discount_threshold ? Math.round(subtotal * cfg.discount_percent / 100) : 0;
  return { subtotal, installation, delivery, discount, total: Math.max(0, subtotal + installation + delivery - discount) };
}

function productsPage(req) {
  const cats = q.all('SELECT c.*, (SELECT COUNT(*) FROM products p WHERE p.category_id = c.id AND p.active = 1) AS n FROM product_categories c ORDER BY c.sort_order, c.name');
  const products = q.all('SELECT p.*, c.slug AS category_slug FROM products p LEFT JOIN product_categories c ON c.id = p.category_id WHERE p.active = 1 ORDER BY c.sort_order, p.sort_order, p.name');
  const cfg = chargesConfig(), cur = S().currency;
  const productData = JSON.stringify(products.map((p) => ({ id: p.id, name: p.name, price: p.price, installable: !!p.installable, unit: p.unit, out: p.stock_status === 'out_of_stock' }))).replace(/</g, '\\u003c');
  const body = `${pageHero({ eyebrow: 'CCTV Product Catalogue', title: HOME.products.title, text: HOME.products.subtitle, crumbs: [['CCTV', '/cctv'], ['Products']] })}
  <section class="section"><div class="container shop-layout">
    <div><div class="cat-tabs" role="tablist" aria-label="Filter products">${[['all', 'All products', products.length], ...cats.filter((c) => c.n).map((c) => [c.slug, c.name, c.n])].map(([s, n, k], i) => `<button type="button" data-filter="${esc(s)}" class="${i === 0 ? 'active' : ''}">${esc(n)} <span class="muted">(${k})</span></button>`).join('')}</div>
      ${products.length ? `<div class="product-grid" id="productGrid">${products.map(productCard).join('')}</div>` : `<div class="empty">${icon('cart')}<h3>No products yet</h3></div>`}
      <p class="muted" style="font-size:.85rem;margin-top:24px">Prices shown are in ${esc(cur.code)} and may change without notice. Product images are illustrative.</p></div>
    <aside class="card quote-panel" id="quote" data-cfg='${esc(JSON.stringify({ ...cfg, symbol: cur.symbol, position: cur.position }))}'>
      <script type="application/json" id="productData">${productData}</script>
      <div class="qp-head"><h2>${icon('file')} Your quotation</h2><span class="chip dark" data-cart-count-label>0 items</span></div>
      <div class="qp-body">
        <ul class="cart-items" id="cartItems"></ul>
        <div class="cart-empty" id="cartEmpty">${icon('cart')}<p>Your quotation is empty.<br>Add products from the catalogue.</p></div>
        <label class="opt"><input type="checkbox" id="optInstall" checked><span><strong>Include installation</strong><br><small class="muted">${money(cfg.installation_base)} base + ${money(cfg.installation_per_camera)} per camera</small></span></label>
        <label class="opt"><input type="checkbox" id="optDelivery"><span><strong>Include delivery</strong><br><small class="muted">${money(cfg.delivery_charge)}${cfg.free_delivery_above ? ` · free above ${money(cfg.free_delivery_above)}` : ''}</small></span></label>
        <div class="totals" id="totals"></div>
        <form class="ajax-form" id="quoteForm" data-endpoint="/api/quotation" data-quote="1" novalidate style="margin-top:12px">
          <div class="form-status" role="status"></div>
          <div class="form-grid" style="gap:12px">
            ${field({ name: 'customer_name', label: 'Your name', required: true, full: true, attrs: 'maxlength="100" autocomplete="name"' })}
            ${field({ name: 'phone', label: 'Phone', type: 'tel', required: true, attrs: 'maxlength="20" autocomplete="tel"' })}
            ${field({ name: 'city', label: 'City', type: 'select', required: true, options: PK_CITIES })}
            ${field({ name: 'address', label: 'Address', full: true, attrs: 'maxlength="250"' })}
            ${field({ name: 'email', label: 'Email (optional)', type: 'email', full: true, attrs: 'maxlength="190"' })}
            ${field({ name: 'customer_notes', label: 'Notes (optional)', type: 'textarea', full: true, attrs: 'maxlength="1000" style="min-height:80px"' })}
          </div>${honeypot()}
          <button class="btn btn-primary btn-block" type="submit" style="margin-top:16px">${icon('file')} Generate quotation</button>
          <p class="form-note" style="justify-content:center;margin-top:10px">No payment required · Printable PDF</p>
        </form>
      </div>
    </aside>
  </div></section>`;
  return layout(req, { title: 'CCTV Cameras, DVR, NVR & Accessories — Prices in PKR', description: 'Browse CCTV cameras, DVR and NVR recorders, hard drives, cables and accessories with prices in PKR. Add items and generate a printable quotation instantly.', body });
}

function schemePage(req) {
  const sc = S().scheme;
  const body = `${pageHero({ eyebrow: 'Application assistance', title: 'Apna Ghar Apni Chat — Application Assistance', text: 'Get help from Smart Digital Services in preparing your application information for the Apna Ghar Apni Chat housing scheme.', crumbs: [['Apna Ghar Apni Chat']] })}
  <section class="section"><div class="container">
    <div class="notice-box reveal" style="margin-bottom:48px">${icon('shield')}<div><strong>Important notice:</strong> ${esc(sc.notice)} Submitting this form does <strong>not</strong> guarantee approval or eligibility. We do not charge or collect any government fee on behalf of any authority.</div></div>
    <div class="split" style="align-items:start">
      <div class="reveal">${sectionHead({ eyebrow: 'About the scheme', title: 'What is Apna Ghar Apni Chat?' })}
        <p>Apna Ghar Apni Chat is a housing initiative announced by the Government of Punjab to help eligible families build a home. Eligibility rules, financing terms and the official application process are decided by the government and may change over time — please always confirm current details through official government channels.</p>
        <p>Many people find online applications confusing or do not have easy access to a computer. Smart Digital Services can help you organise the information required and submit the application <strong>manually, on your behalf and with your consent</strong>.</p>
        <h3 style="margin-top:28px">Information usually needed</h3>
        <ul class="checklist"><li>${icon('check')}Valid CNIC of the applicant</li><li>${icon('check')}Active mobile number registered in the applicant’s name</li><li>${icon('check')}Address and family information</li><li>${icon('check')}Details of the plot (if applicable) and any supporting documents</li></ul>
        <h3 style="margin-top:28px">How our assistance works</h3>
        <ol class="steps"><li><strong>You submit this form</strong><span>Your information is sent securely to SDS.</span></li><li><strong>We review and call you</strong><span>We confirm details and explain the next steps.</span></li><li><strong>Manual submission</strong><span>Our team prepares and submits your application manually. Nothing is submitted automatically.</span></li><li><strong>Status updates</strong><span>We keep you informed about our assistance.</span></li></ol>
      </div>
      <div class="reveal d1">${sc.form_enabled ? `<form class="card form-card ajax-form" data-endpoint="/api/scheme" data-multipart="1" enctype="multipart/form-data" novalidate>
        <h3 style="margin-bottom:6px">Assistance request form</h3><p class="muted" style="font-size:.9rem">Fields marked * are required.</p>
        <div class="form-status" role="status"></div>
        <div class="form-grid">
          ${field({ name: 'full_name', label: 'Applicant full name', required: true, attrs: 'maxlength="100" autocomplete="name"' })}
          ${field({ name: 'father_name', label: "Father's / husband's name", required: true, attrs: 'maxlength="100"' })}
          ${field({ name: 'cnic', label: 'CNIC number', required: true, placeholder: '12345-1234567-1', hint: 'Format: 12345-1234567-1', attrs: 'maxlength="15" inputmode="numeric" data-cnic autocomplete="off"' })}
          ${field({ name: 'gender', label: 'Gender', type: 'select', options: ['Male', 'Female', 'Transgender'] })}
          ${field({ name: 'mobile', label: 'Mobile number', type: 'tel', required: true, placeholder: '03XX XXXXXXX', attrs: 'maxlength="20" autocomplete="tel"' })}
          ${field({ name: 'alt_mobile', label: 'Alternate contact number', type: 'tel', attrs: 'maxlength="20"' })}
          ${field({ name: 'marital_status', label: 'Marital status', type: 'select', options: ['Single', 'Married', 'Widowed', 'Divorced'] })}
          ${field({ name: 'family_members', label: 'Family members', type: 'number', attrs: 'min="1" max="30"' })}
          ${field({ name: 'city', label: 'City', type: 'select', required: true, options: PK_CITIES })}
          ${field({ name: 'district', label: 'District / Tehsil', attrs: 'maxlength="80"' })}
          ${field({ name: 'address', label: 'Current address', required: true, full: true, attrs: 'maxlength="300" autocomplete="street-address"' })}
          ${field({ name: 'occupation', label: 'Occupation', attrs: 'maxlength="80"' })}
          ${field({ name: 'monthly_income', label: 'Monthly household income', type: 'select', options: ['Below Rs 30,000', 'Rs 30,000 – 50,000', 'Rs 50,000 – 80,000', 'Rs 80,000 – 120,000', 'Above Rs 120,000', 'Prefer not to say'] })}
          ${field({ name: 'owns_plot', label: 'Do you own a plot?', type: 'select', options: ['Yes', 'No', 'Not sure'] })}
          ${field({ name: 'plot_size', label: 'Plot size (if any)', placeholder: 'e.g. 5 marla', attrs: 'maxlength="40"' })}
          ${field({ name: 'plot_location', label: 'Plot location (if any)', full: true, attrs: 'maxlength="200"' })}
          ${field({ name: 'additional_info', label: 'Additional information', type: 'textarea', full: true, attrs: 'maxlength="2000"' })}
          ${sc.uploads_enabled ? `<div class="field full"><label for="docs">Supporting documents (optional)</label><input id="docs" type="file" name="documents" accept=".pdf,.jpg,.jpeg,.png,.webp" multiple><p class="hint">Up to 3 files · PDF, JPG, PNG or WEBP · max 5 MB each. Stored privately — only authorised SDS staff can access them.</p></div>` : ''}
          <div class="full"><label class="consent"><input type="checkbox" name="consent" value="yes" required><span>I confirm the information is correct and I <strong>consent</strong> to Smart Digital Services storing it securely and using it only to contact me and help prepare and submit my application manually. I understand SDS is <strong>not a government authority</strong> and that submitting this form does not guarantee approval or eligibility. I have read the <a href="/privacy-policy" target="_blank">Privacy Policy</a>.</span></label></div>
        </div>${honeypot()}
        <div class="form-actions" style="margin-top:20px"><button class="btn btn-primary" type="submit">${icon('lock')} Submit securely</button><span class="form-note">${icon('shield')} CNIC numbers are encrypted.</span></div>
      </form>` : `<div class="alert alert-info">${icon('clock')}<div>The online assistance form is temporarily unavailable. Please contact us by phone or WhatsApp.</div></div>${contactInfoList()}`}
      <div class="card" style="margin-top:20px;padding:22px"><h3 style="font-size:1rem">${icon('lock')} Privacy notice</h3><p class="muted" style="font-size:.9rem;margin:0">Your CNIC is encrypted before it is stored. Your information is accessible only to authorised SDS staff, is never sold or shared for marketing, and is used only for the assistance you request. You may ask us to delete your data at any time.</p></div></div>
    </div></div></section>`;
  return layout(req, { title: 'Apna Ghar Apni Chat — Application Assistance', description: 'Get private application assistance for the Apna Ghar Apni Chat housing scheme from Smart Digital Services. We are not a government body and do not guarantee approval.', body });
}

function contactPage(req) {
  const body = `${pageHero({ eyebrow: 'Contact & support', title: HOME.contact.title, text: HOME.contact.text, crumbs: [['Contact']] })}
  <section class="section"><div class="container contact-grid"><div>${contactInfoList()}${socialLinks('tag-cloud')}</div><div>${contactForm(cleanText(req.query.subject, 120))}</div></div></section>`;
  return layout(req, { title: 'Contact Smart Digital Services', description: `Contact Smart Digital Services by phone, WhatsApp or email. ${S().contact.address}.`, body });
}

function verifyPage(req) {
  const id = cleanText(req.query.id, 40).toUpperCase();
  let result = '';
  if (id) {
    const cert = q.get('SELECT * FROM certificates WHERE certificate_id = ?', id);
    const status = !cert ? 'not_found' : cert.status;
    q.run('INSERT INTO certificate_verifications (certificate_id, result, ip_hash, checked_at) VALUES (?,?,?,?)', id, status, ipHash(req), nowIso());
    if (cert && cert.status === 'valid') {
      result = `<div class="verify-result valid">${icon('shield', '')}<h2 style="font-size:1.4rem;color:var(--ok)">Valid certificate</h2><p style="margin:0">This certificate was issued by <strong>${esc(S().general.site_name)}</strong>.</p>
        <dl><dt>Certificate ID</dt><dd>${esc(cert.certificate_id)}</dd><dt>Student name</dt><dd>${esc(cert.student_name)}</dd>${cert.father_name ? `<dt>Father's name</dt><dd>${esc(cert.father_name)}</dd>` : ''}<dt>Course</dt><dd>${esc(cert.course_name)}</dd><dt>Completion date</dt><dd>${fmtDate(cert.completion_date)}</dd>${cert.grade ? `<dt>Grade</dt><dd>${esc(cert.grade)}</dd>` : ''}<dt>Issued on</dt><dd>${fmtDate(cert.issued_at)}</dd></dl>
        ${S().certificate.public_download ? `<a class="btn btn-dark" style="margin-top:22px" href="/certificate/${esc(cert.certificate_id)}" target="_blank">${icon('print')} View / print certificate</a>` : ''}</div>`;
    } else if (cert && cert.status === 'revoked') {
      result = `<div class="verify-result invalid"><h2 style="font-size:1.4rem;color:var(--err)">Certificate revoked</h2><p>Certificate <strong>${esc(id)}</strong> was issued by ${esc(S().general.site_name)} but has been <strong>revoked</strong> and is no longer valid.</p></div>`;
    } else {
      result = `<div class="verify-result invalid"><h2 style="font-size:1.4rem;color:var(--err)">No certificate found</h2><p>We could not find a certificate with ID <strong>${esc(id)}</strong>. Please check the ID and try again, or contact us for help.</p></div>`;
    }
  }
  const body = `${pageHero({ eyebrow: 'Certificate verification', title: 'Verify an SDS certificate', text: 'Enter the certificate ID printed on the certificate to confirm that it was genuinely issued by Smart Digital Services.', crumbs: [['Verify certificate']] })}
  <section class="section"><div class="container" style="max-width:820px"><form class="card form-card" action="/verify" method="get" role="search"><label for="cid" style="font-weight:600;color:var(--ink)">Certificate ID</label>
    <div class="verify-form" style="max-width:none;margin-top:10px"><input id="cid" type="text" name="id" value="${esc(id)}" placeholder="SDS-BCC-2026-ABC123" maxlength="40" required autocomplete="off"><button class="btn btn-primary" type="submit">${icon('search')} Verify</button></div></form>${result}</div></section>`;
  return layout(req, { title: id ? `Certificate verification — ${id}` : 'Verify a Certificate', description: 'Verify the authenticity of a Smart Digital Services course certificate using its unique certificate ID.', body, noindex: !!id });
}

function legalPage(req, kind) {
  const html = kind === 'privacy' ? S().legal.privacy_html || DEFAULT_PRIVACY : S().legal.terms_html || DEFAULT_TERMS;
  const title = kind === 'privacy' ? 'Privacy Policy' : 'Terms & Conditions';
  const body = `${pageHero({ title, crumbs: [[title]] })}<section class="section"><div class="container"><div class="prose" style="margin:0 auto">${html}</div></div></section>`;
  return layout(req, { title, description: `${title} of ${S().general.site_name}.`, body });
}

function notFoundPage(req) {
  const body = `<section class="section"><div class="container empty" style="padding:96px 20px">${icon('search')}<p class="eyebrow" style="justify-content:center">Error 404</p><h1 style="font-size:2.4rem">Page not found</h1><p>The page you are looking for may have moved or no longer exists.</p><div class="hero-actions" style="justify-content:center"><a class="btn btn-primary" href="/">Back to home</a><a class="btn btn-outline" href="/blog">Browse the blog</a></div></div></section>`;
  return layout(req, { title: 'Page not found', body, noindex: true });
}

app.get('/', (req, res) => res.send(homePage(req)));
app.get('/about', (req, res) => res.send(aboutPage(req)));
app.get('/services', (req, res) => res.send(servicesPage(req)));
app.get('/blog', (req, res) => res.send(blogIndex(req, res, null)));
app.get('/blog/category/:slug', (req, res, next) => {
  const cat = q.get('SELECT * FROM blog_categories WHERE slug = ?', req.params.slug);
  if (!cat) return next();
  res.send(blogIndex(req, res, cat));
});
app.get('/blog/:slug', (req, res, next) => {
  const post = q.get("SELECT * FROM blog_posts WHERE slug = ? AND status = 'published'", req.params.slug);
  if (!post) {
    if (loadSession(req)) { const draft = q.get('SELECT * FROM blog_posts WHERE slug = ?', req.params.slug); if (draft) return res.set('X-Robots-Tag', 'noindex').send(blogPost(req, res, draft)); }
    return next();
  }
  res.send(blogPost(req, res, post));
});
app.get('/course', (req, res, next) => { const html = coursePage(req); if (!html) return next(); res.send(html); });
app.get('/courses/:slug', (req, res) => res.redirect(301, '/course'));
app.get('/cctv', (req, res) => res.send(cctvPage(req)));
app.get('/cctv/products', (req, res) => res.send(productsPage(req)));
app.get('/apna-ghar-apni-chat', (req, res) => res.send(schemePage(req)));
app.get('/contact', (req, res) => res.send(contactPage(req)));
app.get('/verify', (req, res) => res.send(verifyPage(req)));
app.get('/privacy-policy', (req, res) => res.send(legalPage(req, 'privacy')));
app.get('/terms', (req, res) => res.send(legalPage(req, 'terms')));

/* ============================== 10. PUBLIC FORM APIs ============================== */
const api = express.Router();
api.use(csrfCheck);
const isBot = (b) => b && String(b.website || '').trim() !== '';
function checkErrors(errors) { if (Object.keys(errors).length) throw new HttpError(422, 'Please correct the highlighted fields.', errors); }

api.post('/contact', formLimiter, (req, res) => {
  const b = req.body || {};
  if (isBot(b)) return res.json({ ok: true, message: 'Thank you! Your message has been received.' });
  requireFields(b, { name: 'Name', email: 'Email', message: 'Message' });
  const e = {};
  if (!V.email(b.email)) e.email = 'Please enter a valid email address.';
  if (b.phone && !V.phone(b.phone)) e.phone = 'Please enter a valid phone number.';
  if (String(b.message).trim().length < 5) e.message = 'Please write a little more detail.';
  checkErrors(e);
  const ref = makeRef('MSG'), t = nowIso();
  const r = q.run('INSERT INTO contact_messages (ref, name, email, phone, subject, message, status, ip_hash, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
    ref, cleanText(b.name, 100), cleanText(b.email, 190).toLowerCase(), cleanText(b.phone, 20), cleanText(b.subject, 150) || 'General enquiry', cleanText(b.message, 4000), 'new', ipHash(req), t, t);
  logActivity(req, 'New contact message', 'contact', r.lastInsertRowid, `${cleanText(b.name, 100)} — ${cleanText(b.subject, 100)}`);
  notifyAdmin(`New contact message ${ref}`, { Name: b.name, Email: b.email, Phone: b.phone, Subject: b.subject, Message: cleanText(b.message, 4000) }, cleanText(b.email, 190));
  res.json({ ok: true, ref, message: `Thank you, ${cleanText(b.name, 60)}! Your message has been received (ref. ${ref}). We will get back to you soon.` });
});

api.post('/enroll', formLimiter, (req, res) => {
  const b = req.body || {};
  if (isBot(b)) return res.json({ ok: true, message: 'Thank you!' });
  requireFields(b, { full_name: 'Student name', father_name: "Father's name", phone: 'Mobile number', city: 'City' });
  const e = {};
  if (!V.phone(b.phone)) e.phone = 'Please enter a valid mobile number.';
  if (b.email && !V.email(b.email)) e.email = 'Please enter a valid email address.';
  checkErrors(e);
  const course = q.get('SELECT * FROM courses WHERE id = ?', parseInt(b.course_id, 10) || 0) || getCourse();
  if (!course) throw new HttpError(404, 'Course not found.');
  if (!course.enrollment_open) throw new HttpError(409, 'Enrolment for this course is currently closed.');
  const t = nowIso(), ref = makeRef('ENR');
  const id = tx(() => {
    const s = q.run('INSERT INTO students (full_name, father_name, gender, phone, email, city, address, education, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
      cleanText(b.full_name, 100), cleanText(b.father_name, 100), cleanText(b.gender, 30), cleanText(b.phone, 20), cleanText(b.email, 190).toLowerCase(), cleanText(b.city, 60), cleanText(b.address, 250), cleanText(b.education, 40), t, t);
    return q.run('INSERT INTO enrollments (ref, student_id, course_id, preferred_timing, status, fee_status, message, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
      ref, s.lastInsertRowid, course.id, cleanText(b.preferred_timing, 30), 'pending', 'unpaid', cleanText(b.message, 1000), t, t).lastInsertRowid;
  });
  logActivity(req, 'New course enrolment', 'enrollments', id, `${cleanText(b.full_name, 100)} — ${course.name}`);
  notifyAdmin(`New enrolment ${ref}`, { Student: b.full_name, Father: b.father_name, Phone: b.phone, City: b.city, Timing: b.preferred_timing, Course: course.name });
  res.json({ ok: true, ref, message: `Thank you! Your enrolment request (ref. ${ref}) has been received. Our team will call you to confirm your batch.` });
});

api.post('/cctv-request', formLimiter, (req, res) => {
  const b = req.body || {};
  if (isBot(b)) return res.json({ ok: true, message: 'Thank you!' });
  requireFields(b, { name: 'Customer name', phone: 'Phone number', city: 'City', address: 'Address', service_type: 'Service type' });
  const e = {};
  if (!V.phone(b.phone)) e.phone = 'Please enter a valid phone number.';
  if (b.preferred_date && !V.date(b.preferred_date)) e.preferred_date = 'Please choose a valid date.';
  const cams = b.cameras === '' || b.cameras == null ? null : parseInt(b.cameras, 10);
  if (cams !== null && (isNaN(cams) || cams < 0 || cams > 500)) e.cameras = 'Enter a number between 0 and 500.';
  checkErrors(e);
  const ref = makeRef('SR'), t = nowIso();
  const r = q.run('INSERT INTO service_requests (ref, name, phone, city, address, service_type, cameras, preferred_date, details, status, ip_hash, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
    ref, cleanText(b.name, 100), cleanText(b.phone, 20), cleanText(b.city, 60), cleanText(b.address, 250), cleanText(b.service_type, 80), cams, b.preferred_date || null, cleanText(b.details, 2000), 'new', ipHash(req), t, t);
  logActivity(req, 'New CCTV service request', 'service_requests', r.lastInsertRowid, `${cleanText(b.name, 100)} — ${cleanText(b.service_type, 80)}`);
  notifyAdmin(`New CCTV service request ${ref}`, { Name: b.name, Phone: b.phone, City: b.city, Address: b.address, Service: b.service_type, Cameras: cams, 'Preferred date': b.preferred_date, Details: cleanText(b.details, 2000) });
  res.json({ ok: true, ref, message: `Thank you! Your service request (ref. ${ref}) has been received. We will call you to confirm the visit.` });
});

api.post('/quotation', formLimiter, (req, res) => {
  const b = req.body || {};
  if (isBot(b)) return res.json({ ok: true, message: 'Thank you!' });
  requireFields(b, { customer_name: 'Name', phone: 'Phone', city: 'City' });
  const e = {};
  if (!V.phone(b.phone)) e.phone = 'Please enter a valid phone number.';
  if (b.email && !V.email(b.email)) e.email = 'Please enter a valid email address.';
  checkErrors(e);
  const raw = Array.isArray(b.items) ? b.items.slice(0, 60) : [];
  const items = [];
  for (const it of raw) {
    const qty = Math.min(999, Math.max(1, parseInt(it.qty, 10) || 0));
    const p = q.get("SELECT * FROM products WHERE id = ? AND active = 1 AND stock_status != 'out_of_stock'", parseInt(it.id, 10) || 0);
    if (p && !items.find((x) => x.product_id === p.id)) items.push({ product_id: p.id, product_name: p.name, sku: p.sku, unit_price: p.price, quantity: qty, installable: p.installable ? 1 : 0 });
  }
  if (!items.length) throw new HttpError(422, 'Please add at least one available product to your quotation.');
  const opts = { include_installation: !!b.include_installation, include_delivery: !!b.include_delivery };
  const tot = computeTotals(items, opts);
  const number = makeRef('SDS-Q'), token = randomToken(16), t = nowIso();
  const validity = Math.max(1, parseInt(S().charges.quotation_validity_days, 10) || 7);
  const validUntil = new Date(Date.now() + validity * 86400000).toISOString().slice(0, 10);
  const id = tx(() => {
    const qid = q.run(`INSERT INTO quotations (number, access_token, customer_name, phone, email, city, address, include_installation, include_delivery, subtotal, installation_charge, delivery_charge, discount, total, status, customer_notes, valid_until, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, number, token, cleanText(b.customer_name, 100), cleanText(b.phone, 20), cleanText(b.email, 190).toLowerCase(), cleanText(b.city, 60), cleanText(b.address, 250),
      opts.include_installation, opts.include_delivery, tot.subtotal, tot.installation, tot.delivery, tot.discount, tot.total, 'new', cleanText(b.customer_notes, 1000), validUntil, t, t).lastInsertRowid;
    for (const it of items) q.run('INSERT INTO quotation_items (quotation_id, product_id, product_name, sku, unit_price, quantity, line_total, installable) VALUES (?,?,?,?,?,?,?,?)', qid, it.product_id, it.product_name, it.sku, it.unit_price, it.quantity, it.unit_price * it.quantity, it.installable);
    return qid;
  });
  logActivity(req, 'New quotation generated', 'quotations', id, `${number} — ${cleanText(b.customer_name, 100)} — ${money(tot.total)}`);
  notifyAdmin(`New quotation ${number}`, { Customer: b.customer_name, Phone: b.phone, City: b.city, Items: items.map((i) => `${i.quantity} x ${i.product_name}`).join('; '), Total: money(tot.total) });
  res.json({ ok: true, ref: number, message: 'Your quotation is ready.', redirect: `/quotation/${number}?t=${token}` });
});

api.post('/scheme', formLimiter, (req, res, next) => {
  if (!S().scheme.form_enabled) return res.status(403).json({ ok: false, error: 'The assistance form is currently unavailable.' });
  memUpload.array('documents', 3)(req, res, (err) => {
    if (err) return next(err);
    try { handleSchemeSubmission(req, res); } catch (ex) { next(ex); }
  });
});
function handleSchemeSubmission(req, res) {
  {
    const b = req.body || {};
    if (isBot(b)) return res.json({ ok: true, message: 'Thank you!' });
    requireFields(b, { full_name: 'Applicant name', father_name: "Father's name", cnic: 'CNIC number', mobile: 'Mobile number', city: 'City', address: 'Address' });
    const e = {};
    if (!V.cnic(b.cnic)) e.cnic = 'Enter a valid 13-digit CNIC, e.g. 12345-1234567-1.';
    if (!V.phone(b.mobile)) e.mobile = 'Enter a valid mobile number.';
    if (b.alt_mobile && !V.phone(b.alt_mobile)) e.alt_mobile = 'Enter a valid number.';
    if (b.email && !V.email(b.email)) e.email = 'Enter a valid email address.';
    if (b.consent !== 'yes') e.consent = 'Consent is required to submit this form.';
    const fam = b.family_members ? parseInt(b.family_members, 10) : null;
    if (fam !== null && (isNaN(fam) || fam < 1 || fam > 30)) e.family_members = 'Enter a number between 1 and 30.';
    checkErrors(e);
    const docs = [];
    if (S().scheme.uploads_enabled) for (const f of req.files || []) docs.push(storeFile(f, { allowed: ['pdf', 'jpg', 'png', 'webp'], dir: 'private', maxBytes: MAX_DOC_BYTES }));
    const cnic = normCnic(b.cnic), ref = makeRef('AGAC'), t = nowIso();
    const dupe = q.val('SELECT COUNT(*) FROM scheme_submissions WHERE cnic_index = ?', blindIndex(cnic));
    const r = q.run(`INSERT INTO scheme_submissions (ref, full_name, father_name, cnic_enc, cnic_index, cnic_last4, gender, marital_status, mobile, alt_mobile, email, city, district, address, occupation, monthly_income, family_members, owns_plot, plot_size, plot_location, additional_info, documents, consent, consent_at, status, notes, ip_hash, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, ref, cleanText(b.full_name, 100), cleanText(b.father_name, 100), encrypt(cnic), blindIndex(cnic), cnic.replace(/\D/g, '').slice(-4),
      cleanText(b.gender, 20), cleanText(b.marital_status, 20), cleanText(b.mobile, 20), cleanText(b.alt_mobile, 20), cleanText(b.email, 190).toLowerCase(), cleanText(b.city, 60), cleanText(b.district, 80), cleanText(b.address, 300),
      cleanText(b.occupation, 80), cleanText(b.monthly_income, 40), fam, cleanText(b.owns_plot, 20), cleanText(b.plot_size, 40), cleanText(b.plot_location, 200), cleanText(b.additional_info, 2000),
      JSON.stringify(docs), 1, t, 'pending', dupe ? `System: ${dupe} earlier submission(s) found with the same CNIC.` : null, ipHash(req), t, t);
    logActivity(req, 'New scheme assistance submission', 'scheme', r.lastInsertRowid, `${ref} — ${cleanText(b.full_name, 100)}`);
    notifyAdmin(`New Apna Ghar Apni Chat assistance request ${ref}`, { Reference: ref, Name: b.full_name, City: b.city, Note: 'Personal details (CNIC etc.) are only visible in the admin dashboard.' });
    res.json({ ok: true, ref, message: `Thank you! Your request has been received securely (ref. ${ref}). Our team will contact you. Remember: SDS provides assistance only and cannot guarantee approval.` });
  }
}

api.post('/comments', formLimiter, (req, res) => {
  const b = req.body || {};
  if (isBot(b)) return res.json({ ok: true, message: 'Thank you!' });
  if (!S().blog.comments_enabled) throw new HttpError(403, 'Comments are disabled.');
  requireFields(b, { name: 'Name', comment: 'Comment' });
  if (b.email && !V.email(b.email)) throw new HttpError(422, 'Please correct the highlighted fields.', { email: 'Enter a valid email address.' });
  const post = q.get("SELECT id, title, allow_comments FROM blog_posts WHERE id = ? AND status = 'published'", parseInt(b.post_id, 10) || 0);
  if (!post || !post.allow_comments) throw new HttpError(404, 'Article not found.');
  const t = nowIso();
  const r = q.run('INSERT INTO blog_comments (post_id, name, email, comment, status, ip_hash, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)', post.id, cleanText(b.name, 80), cleanText(b.email, 190), cleanText(b.comment, 2000), 'pending', ipHash(req), t, t);
  logActivity(req, 'New blog comment (pending)', 'comments', r.lastInsertRowid, post.title);
  res.json({ ok: true, message: 'Thank you! Your comment has been submitted and will appear after review.' });
});
app.use('/api', api);

/* ================= 11. CERTIFICATES, QUOTATIONS & SVG MEDIA ================= */
function printShell(req, { title, body, css, landscape = false }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><meta name="robots" content="noindex, nofollow">
<meta name="csrf-token" content="${req.csrfToken}"><link rel="icon" href="${esc(S().general.favicon || '/favicon.svg')}">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@700;800&family=Playfair+Display:ital,wght@0,700;1,600&display=swap">
<style>@page{size:A4 ${landscape ? 'landscape' : 'portrait'};margin:${landscape ? '0' : '12mm'}}*{box-sizing:border-box}body{margin:0;background:#e9edf4;font-family:'Inter',system-ui,Arial,sans-serif;color:#0f172a;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.toolbar{position:sticky;top:0;z-index:5;display:flex;gap:10px;justify-content:center;flex-wrap:wrap;padding:14px;background:#0b1b33}.toolbar a,.toolbar button{font:600 14px Inter,sans-serif;padding:10px 16px;border-radius:9px;border:1px solid rgba(255,255,255,.25);background:rgba(255,255,255,.08);color:#fff;cursor:pointer;text-decoration:none}.toolbar .primary{background:#2563eb;border-color:#2563eb}
.sheet-wrap{padding:28px 12px;overflow-x:auto}@media print{.toolbar{display:none}.sheet-wrap{padding:0}body{background:#fff}}${css}</style></head><body>${body}<script src="/assets/site.js?v=${ASSET_VERSION}" defer></script></body></html>`;
}
function certLogo() {
  const c = S().certificate, g = S().general;
  const src = c.logo || g.logo;
  return src ? `<img src="${esc(src)}" alt="" style="height:64px;width:auto;object-fit:contain">` : `<svg viewBox="0 0 40 40" width="58" height="58"><rect width="40" height="40" rx="11" fill="${esc(c.accent || '#1d4ed8')}"/><path d="M26.5 13.2c-1.4-1.6-3.7-2.6-6.4-2.6-4 0-6.7 2.1-6.7 5.1 0 3.2 2.8 4.3 6.3 5.1 3 .7 4.2 1.3 4.2 2.7 0 1.5-1.6 2.5-3.9 2.5-2.5 0-4.4-1-5.7-2.7" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"/><circle cx="29.5" cy="27.5" r="3" fill="#22d3ee"/></svg>`;
}
function certificateHtml(req, cert) {
  const c = S().certificate, g = S().general;
  const accent = /^#[0-9a-f]{3,8}$/i.test(c.accent || '') ? c.accent : '#1d4ed8';
  const verifyUrl = `${baseUrl(req)}/verify?id=${encodeURIComponent(cert.certificate_id)}`;
  const css = `.cert{width:297mm;height:210mm;margin:0 auto;background:#fff;position:relative;overflow:hidden;box-shadow:0 20px 60px -20px rgba(11,27,51,.4)}
@media print{.cert{box-shadow:none;margin:0}}
.cert .bg{position:absolute;inset:0;background:${c.background_image ? `url('${esc(c.background_image)}') center/cover no-repeat` : `radial-gradient(circle at 50% 0%,#eef4ff,transparent 55%),repeating-radial-gradient(circle at 0 0,transparent 0 22px,rgba(29,78,216,.035) 22px 23px),repeating-radial-gradient(circle at 100% 100%,transparent 0 22px,rgba(29,78,216,.035) 22px 23px)`}}
.frame{position:absolute;inset:9mm;border:2.5px solid ${accent};border-radius:3mm}.frame::before{content:'';position:absolute;inset:2.2mm;border:1px solid ${accent}55;border-radius:2mm}
.corner{position:absolute;width:30mm;height:30mm;border-color:#0b1b33;border-style:solid}.c1{top:5mm;left:5mm;border-width:5px 0 0 5px}.c2{top:5mm;right:5mm;border-width:5px 5px 0 0}.c3{bottom:5mm;left:5mm;border-width:0 0 5px 5px}.c4{bottom:5mm;right:5mm;border-width:0 5px 5px 0}
.content{position:absolute;inset:16mm 24mm 31mm;display:flex;flex-direction:column;align-items:center;text-align:center}
.org{display:flex;align-items:center;gap:14px}.org strong{display:block;font:800 21px 'Plus Jakarta Sans',sans-serif;letter-spacing:.06em;color:#0b1b33;text-transform:uppercase;text-align:left}.org small{display:block;font-size:11px;letter-spacing:.18em;color:#64748b;text-transform:uppercase;text-align:left}
h1{font:700 44px 'Playfair Display',Georgia,serif;color:#0b1b33;margin:7mm 0 1mm;letter-spacing:.01em}
.ribbon{display:inline-block;background:${accent};color:#fff;font-size:11px;letter-spacing:.3em;text-transform:uppercase;padding:6px 22px;border-radius:30px;margin-bottom:7mm}
.pre{font-size:15px;color:#475569;margin:0}
.name{font:italic 600 44px 'Playfair Display',Georgia,serif;color:${accent};margin:4mm 0 2mm;padding:0 14mm 3mm;border-bottom:1.5px solid #cbd5e1;min-width:150mm}
.father{font-size:13px;color:#64748b;margin:0 0 4mm}
.body{font-size:15.5px;color:#334155;max-width:200mm;line-height:1.6;margin:0}.body strong{color:#0b1b33}
.foot{margin-top:auto;width:100%;display:grid;grid-template-columns:1fr auto 1fr;align-items:end;gap:10mm}
.sig{text-align:center;font-size:12.5px;color:#475569}.sig .line{border-top:1.5px solid #0b1b33;margin:0 auto 2mm;width:62mm}.sig strong{display:block;color:#0b1b33;font-size:14px}.sig img{height:16mm;width:auto;margin:0 auto 1mm;display:block}.sig .val{font:600 16px 'Plus Jakarta Sans',sans-serif;color:#0b1b33;margin-bottom:3mm;min-height:16mm;display:flex;align-items:flex-end;justify-content:center}
.seal{width:34mm;height:34mm}
.meta{position:absolute;left:22mm;right:22mm;bottom:15mm;display:grid;grid-template-columns:1fr 1.3fr 1fr;align-items:end;font-size:9.5px;line-height:1.45;color:#64748b;gap:6mm;padding-top:3mm;border-top:1px solid #e2e8f0}.meta span:nth-child(2){text-align:center}.meta span:nth-child(3){text-align:right;word-break:break-all}
.meta b{color:#0b1b33;font-family:ui-monospace,Consolas,monospace;letter-spacing:.05em}
.void{position:absolute;inset:0;display:grid;place-items:center;pointer-events:none}.void span{font:800 120px 'Plus Jakarta Sans',sans-serif;color:rgba(220,38,38,.18);transform:rotate(-18deg);border:10px solid rgba(220,38,38,.18);padding:0 40px;border-radius:20px}`;
  const seal = `<svg class="seal" viewBox="0 0 120 120" aria-hidden="true"><defs><path id="sc" d="M60 60m-44 0a44 44 0 1 1 88 0a44 44 0 1 1-88 0"/></defs><circle cx="60" cy="60" r="57" fill="${accent}"/><circle cx="60" cy="60" r="50" fill="none" stroke="#fff" stroke-opacity=".5" stroke-dasharray="2 3"/><text font-family="Inter,Arial" font-size="9.5" font-weight="700" fill="#fff" letter-spacing="2.4"><textPath href="#sc">SMART DIGITAL SERVICES • VERIFIED •</textPath></text><circle cx="60" cy="60" r="30" fill="#0b1b33"/><text x="60" y="58" text-anchor="middle" font-family="Plus Jakarta Sans,Arial" font-weight="800" font-size="18" fill="#fff">SDS</text><text x="60" y="73" text-anchor="middle" font-family="Inter,Arial" font-size="7" fill="#93c5fd" letter-spacing="1.5">CERTIFIED</text></svg>`;
  const body = `<div class="toolbar"><button type="button" class="primary" data-print>Print / Save as PDF</button><a href="/verify?id=${encodeURIComponent(cert.certificate_id)}">Verification page</a>${req.admin ? '<a href="/admin#/r/certificates">Back to admin</a>' : '<a href="/">Website</a>'}</div>
  <div class="sheet-wrap"><div class="cert"><div class="bg"></div><div class="frame"></div><span class="corner c1"></span><span class="corner c2"></span><span class="corner c3"></span><span class="corner c4"></span>
  <div class="content"><div class="org">${certLogo()}<div><strong>${esc(g.site_name)}</strong><small>IT Education &amp; Digital Services</small></div></div>
    <h1>${esc(c.title)}</h1><span class="ribbon">${esc(cert.course_name)}</span>
    <p class="pre">${esc(c.subtitle)}</p><div class="name">${esc(cert.student_name)}</div>${cert.father_name ? `<p class="father">Father’s name: ${esc(cert.father_name)}</p>` : ''}
    <p class="body">${esc(c.body)} <strong>${esc(cert.course_name)}</strong> conducted by <strong>${esc(g.site_name)}</strong>, completed on <strong>${fmtDate(cert.completion_date)}</strong>${cert.grade ? ` with grade <strong>${esc(cert.grade)}</strong>` : ''}.</p>
    <div class="foot"><div class="sig"><div class="val">${fmtDate(cert.completion_date)}</div><div class="line"></div><strong>Date of Completion</strong></div>${seal}
      <div class="sig">${c.signature_image ? `<img src="${esc(c.signature_image)}" alt="Signature">` : '<div class="val"></div>'}<div class="line"></div><strong>${esc(c.signatory_name)}</strong>${esc(c.signatory_title)}</div></div></div>
  <div class="meta"><span>Certificate ID: <b>${esc(cert.certificate_id)}</b> · Issued ${fmtDate(cert.issued_at)}</span><span>${esc(c.footer_text)}</span><span>Verify: ${esc(verifyUrl.replace(/^https?:\/\//, ''))}</span></div>
  ${cert.status !== 'valid' ? '<div class="void"><span>REVOKED</span></div>' : ''}</div></div>`;
  return printShell(req, { title: `Certificate ${cert.certificate_id} — ${cert.student_name}`, body, css, landscape: true });
}
app.get('/certificate/:id', (req, res, next) => {
  const cert = q.get('SELECT * FROM certificates WHERE certificate_id = ?', String(req.params.id).toUpperCase().slice(0, 40));
  const admin = loadSession(req);
  if (!cert) return next();
  if (!admin && (cert.status !== 'valid' || !S().certificate.public_download)) return res.redirect(`/verify?id=${encodeURIComponent(cert.certificate_id)}`);
  req.admin = admin;
  res.set('X-Robots-Tag', 'noindex').send(certificateHtml(req, cert));
});

const QUOTE_STATUS = ['new', 'contacted', 'sent', 'accepted', 'rejected', 'completed', 'cancelled'];
function quotationHtml(req, qt, items) {
  const g = S().general, c = S().contact, ch = S().charges;
  const css = `.doc{width:210mm;min-height:297mm;margin:0 auto;background:#fff;padding:16mm 15mm;box-shadow:0 20px 60px -20px rgba(11,27,51,.35);font-size:13px;color:#334155}
@media print{.doc{box-shadow:none;width:auto;min-height:0;padding:0}}
.head{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;padding-bottom:18px;border-bottom:3px solid #0b1b33}
.org{display:flex;gap:12px;align-items:center}.org strong{display:block;font:800 19px 'Plus Jakarta Sans',sans-serif;color:#0b1b33}.org small{color:#64748b;font-size:11.5px}
.qt{text-align:right}.qt h1{font:800 26px 'Plus Jakarta Sans',sans-serif;letter-spacing:.08em;color:#1d4ed8;margin:0 0 6px}.qt table{margin-left:auto;font-size:12.5px}.qt td{padding:1px 0 1px 12px}.qt td:first-child{color:#64748b}
.status{display:inline-block;margin-top:6px;font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;background:#eef4ff;color:#1d4ed8;padding:3px 9px;border-radius:6px}
.parties{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:20px 0}.box{background:#f5f7fb;border-radius:8px;padding:12px 14px}.box h3{margin:0 0 6px;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:#64748b}.box p{margin:2px 0}.box strong{color:#0f172a}
table.items{width:100%;border-collapse:collapse;margin-top:6px}.items th{background:#0b1b33;color:#fff;text-align:left;font-size:11.5px;letter-spacing:.04em;padding:9px 10px}.items td{padding:9px 10px;border-bottom:1px solid #e3e8f0;vertical-align:top}.items .r{text-align:right;white-space:nowrap}.items tr:nth-child(even) td{background:#fafbfd}.items small{color:#64748b}
.sum{display:flex;justify-content:flex-end;margin-top:14px}.sum table{width:80mm;border-collapse:collapse}.sum td{padding:6px 10px}.sum td:last-child{text-align:right;font-weight:600;color:#0f172a}.sum .grand td{background:#1d4ed8;color:#fff!important;font:800 15px 'Plus Jakarta Sans',sans-serif}
.terms{margin-top:22px;font-size:11.5px}.terms h3{font-size:12px;margin:0 0 6px;color:#0f172a}.terms ol{margin:0;padding-left:18px}.terms li{margin-bottom:2px}
.notes{margin-top:14px;font-size:12px;background:#fffbeb;border:1px solid #fde68a;color:#92400e;padding:10px 12px;border-radius:8px}
.foot{margin-top:26px;padding-top:12px;border-top:1px solid #e3e8f0;display:flex;justify-content:space-between;gap:12px;font-size:11px;color:#64748b;flex-wrap:wrap}`;
  const wa = waLink(`Hello SDS, I would like to confirm my quotation ${qt.number}.`);
  const body = `<div class="toolbar"><button type="button" class="primary" data-print>Print / Save as PDF</button>${wa ? `<a href="${esc(wa)}" target="_blank" rel="noopener">Confirm on WhatsApp</a>` : ''}<a href="/cctv/products">Back to catalogue</a>${req.admin ? `<a href="/admin#/quotations/${qt.id}">Open in admin</a>` : ''}</div>
  <div class="sheet-wrap"><div class="doc">
    <div class="head"><div class="org">${certLogo()}<div><strong>${esc(g.site_name)}</strong><small>${esc(g.tagline)}</small><br><small>${esc(c.address)}</small></div></div>
      <div class="qt"><h1>QUOTATION</h1><table><tr><td>Quotation no.</td><td><strong>${esc(qt.number)}</strong></td></tr><tr><td>Date</td><td>${fmtDate(qt.created_at)}</td></tr>${qt.valid_until ? `<tr><td>Valid until</td><td>${fmtDate(qt.valid_until)}</td></tr>` : ''}</table><span class="status">${esc(qt.status)}</span></div></div>
    <div class="parties"><div class="box"><h3>Quotation for</h3><p><strong>${esc(qt.customer_name)}</strong></p><p>${esc(qt.phone)}</p>${qt.email ? `<p>${esc(qt.email)}</p>` : ''}<p>${esc([qt.address, qt.city].filter(Boolean).join(', '))}</p></div>
      <div class="box"><h3>From</h3><p><strong>${esc(g.site_name)}</strong></p><p>${esc(c.phone)}</p><p>${esc(c.email)}</p><p>${esc(c.hours)}</p></div></div>
    <table class="items"><thead><tr><th style="width:34px">#</th><th>Item</th><th class="r">Qty</th><th class="r">Unit price</th><th class="r">Total</th></tr></thead>
      <tbody>${items.map((it, i) => `<tr><td>${i + 1}</td><td><strong style="color:#0f172a">${esc(it.product_name)}</strong>${it.sku ? `<br><small>SKU: ${esc(it.sku)}</small>` : ''}</td><td class="r">${it.quantity}</td><td class="r">${money(it.unit_price)}</td><td class="r">${money(it.line_total)}</td></tr>`).join('')}</tbody></table>
    <div class="sum"><table><tr><td>Subtotal</td><td>${money(qt.subtotal)}</td></tr>${qt.installation_charge ? `<tr><td>Installation charges</td><td>${money(qt.installation_charge)}</td></tr>` : ''}${qt.include_delivery || qt.delivery_charge ? `<tr><td>Delivery charges</td><td>${qt.delivery_charge ? money(qt.delivery_charge) : 'Free'}</td></tr>` : ''}${qt.discount ? `<tr><td>Discount</td><td>− ${money(qt.discount)}</td></tr>` : ''}<tr class="grand"><td>Total (${esc(S().currency.code)})</td><td>${money(qt.total)}</td></tr></table></div>
    ${qt.customer_notes ? `<div class="notes"><strong>Customer notes:</strong> ${nl2br(qt.customer_notes)}</div>` : ''}
    <div class="terms"><h3>Terms &amp; conditions</h3><ol>${lines(ch.terms).map((t) => `<li>${esc(t)}</li>`).join('')}</ol></div>
    <div class="foot"><span>${esc(g.site_name)} · ${esc(c.phone)} · ${esc(c.email)}</span><span>This is a computer-generated quotation and does not require a signature.</span></div>
  </div></div>`;
  return printShell(req, { title: `Quotation ${qt.number}`, body, css });
}
app.get('/quotation/:number', (req, res, next) => {
  const qt = q.get('SELECT * FROM quotations WHERE number = ?', String(req.params.number).slice(0, 40));
  if (!qt) return next();
  const admin = loadSession(req);
  if (!admin && !safeEqual(req.query.t, qt.access_token)) return res.status(403).send(layout(req, { title: 'Quotation unavailable', noindex: true, body: `<section class="section"><div class="container empty">${icon('lock')}<h1 style="font-size:2rem">This quotation link is not valid</h1><p>Please use the full link you received when the quotation was generated, or contact us.</p><a class="btn btn-primary" href="/contact">Contact SDS</a></div></section>` }));
  req.admin = admin;
  res.set('X-Robots-Tag', 'noindex').set('Cache-Control', 'private, no-store').send(quotationHtml(req, qt, q.all('SELECT * FROM quotation_items WHERE quotation_id = ? ORDER BY id', qt.id)));
});

/* Generated, original SVG artwork used when no image has been uploaded */
function wrapText(text, max, maxLines) {
  const words = String(text).split(/\s+/), out = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > max) { out.push(line.trim()); line = w; if (out.length === maxLines) break; } else line += ' ' + w;
  }
  if (out.length < maxLines && line.trim()) out.push(line.trim());
  if (out.length === maxLines && words.join(' ').length > out.join(' ').length) out[maxLines - 1] = out[maxLines - 1].replace(/\W*\s*\S*$/, '') + '…';
  return out;
}
const svgIcon = (name, x, y, size, color, sw = 1.6) => `<g transform="translate(${x} ${y}) scale(${size / 24})" fill="none" stroke="${color}" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ICONS.monitor}</g>`;
app.get('/media/cover/:slug.svg', (req, res, next) => {
  const p = q.get('SELECT p.title, p.id, c.name AS cat, c.icon FROM blog_posts p LEFT JOIN blog_categories c ON c.id = p.category_id WHERE p.slug = ?', req.params.slug);
  if (!p) return next();
  const pal = [['#0b1b33', '#1d4ed8', '#22d3ee'], ['#07162b', '#0e7490', '#67e8f9'], ['#0f1f3d', '#4338ca', '#a5b4fc']][(p.id || 0) % 3];
  const ttl = wrapText(p.title, 30, 3);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630" width="1200" height="630"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${pal[0]}"/><stop offset="1" stop-color="${pal[1]}"/></linearGradient><pattern id="p" width="48" height="48" patternUnits="userSpaceOnUse"><path d="M48 0H0V48" fill="none" stroke="#fff" stroke-opacity=".06"/></pattern></defs>
<rect width="1200" height="630" fill="url(#g)"/><rect width="1200" height="630" fill="url(#p)"/><circle cx="1010" cy="170" r="250" fill="#fff" fill-opacity=".04"/><circle cx="1010" cy="170" r="160" fill="none" stroke="${pal[2]}" stroke-opacity=".35" stroke-width="2"/>
${svgIcon(p.icon || 'file', 920, 80, 180, pal[2], 1.3)}
<rect x="80" y="90" rx="18" height="40" width="${Math.min(560, 26 + (p.cat || 'SDS Blog').length * 11.5)}" fill="#fff" fill-opacity=".12"/><text x="100" y="117" font-family="Inter,Segoe UI,Arial" font-size="19" font-weight="600" fill="#dbeafe">${escXml(p.cat || 'SDS Blog')}</text>
${ttl.map((l, i) => `<text x="80" y="${250 + i * 76}" font-family="Plus Jakarta Sans,Segoe UI,Arial" font-size="60" font-weight="800" fill="#fff">${escXml(l)}</text>`).join('')}
<text x="80" y="560" font-family="Inter,Segoe UI,Arial" font-size="22" font-weight="600" fill="#fff" fill-opacity=".75">Smart Digital Services · Blog</text><rect x="80" y="500" width="90" height="5" rx="2.5" fill="${pal[2]}"/></svg>`;
  res.type('image/svg+xml').set('Cache-Control', 'public, max-age=86400').send(svg);
});
app.get('/media/product/:id.svg', (req, res, next) => {
  const p = q.get('SELECT p.name, p.id, c.icon, c.name AS cat FROM products p LEFT JOIN product_categories c ON c.id = p.category_id WHERE p.id = ?', parseInt(req.params.id, 10) || 0);
  if (!p) return next();
  const nm = wrapText(p.name, 26, 2);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 300" width="400" height="300"><defs><radialGradient id="r" cx=".5" cy=".38" r=".6"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#e8eef8"/></radialGradient></defs><rect width="400" height="300" fill="url(#r)"/>
<circle cx="200" cy="118" r="70" fill="#eef4ff" stroke="#dbe7ff" stroke-width="2"/>${svgIcon(p.icon || 'cctv', 152, 70, 96, '#1d4ed8', 1.5)}
${nm.map((l, i) => `<text x="200" y="${228 + i * 22}" text-anchor="middle" font-family="Inter,Segoe UI,Arial" font-size="16" font-weight="600" fill="#0f172a">${escXml(l)}</text>`).join('')}
<text x="200" y="${232 + nm.length * 22}" text-anchor="middle" font-family="Inter,Segoe UI,Arial" font-size="12" fill="#64748b">${escXml(p.cat || '')}</text></svg>`;
  res.type('image/svg+xml').set('Cache-Control', 'public, max-age=86400').send(svg);
});
app.get('/favicon.svg', (req, res) => res.type('image/svg+xml').set('Cache-Control', 'public, max-age=604800').send(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><rect width="40" height="40" rx="10" fill="#1d4ed8"/><path d="M26.5 13.2c-1.4-1.6-3.7-2.6-6.4-2.6-4 0-6.7 2.1-6.7 5.1 0 3.2 2.8 4.3 6.3 5.1 3 .7 4.2 1.3 4.2 2.7 0 1.5-1.6 2.5-3.9 2.5-2.5 0-4.4-1-5.7-2.7" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round"/><circle cx="29.5" cy="27.5" r="3" fill="#22d3ee"/></svg>`));
app.get('/favicon.ico', (req, res) => res.redirect(301, S().general.favicon || '/favicon.svg'));

app.get('/robots.txt', (req, res) => res.type('text/plain').send(`User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/\nDisallow: /quotation/\nDisallow: /certificate/\n\nSitemap: ${baseUrl(req)}/sitemap.xml\n`));
app.get('/sitemap.xml', (req, res) => {
  const b = baseUrl(req);
  const urls = [['/', '1.0', 'weekly'], ['/about', '0.6', 'monthly'], ['/services', '0.8', 'monthly'], ['/blog', '0.9', 'daily'], ['/course', '0.9', 'monthly'], ['/cctv', '0.9', 'monthly'], ['/cctv/products', '0.8', 'weekly'], ['/apna-ghar-apni-chat', '0.7', 'monthly'], ['/contact', '0.6', 'yearly'], ['/verify', '0.4', 'yearly'], ['/privacy-policy', '0.2', 'yearly'], ['/terms', '0.2', 'yearly']].map(([u, p, f]) => ({ loc: b + u, priority: p, changefreq: f }));
  for (const c of q.all('SELECT slug FROM blog_categories')) urls.push({ loc: `${b}/blog/category/${c.slug}`, priority: '0.6', changefreq: 'weekly' });
  for (const p of q.all("SELECT slug, COALESCE(updated_at, published_at) AS m FROM blog_posts WHERE status = 'published' ORDER BY published_at DESC")) urls.push({ loc: `${b}/blog/${p.slug}`, lastmod: String(p.m || '').slice(0, 10), priority: '0.7', changefreq: 'monthly' });
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `<url><loc>${escXml(u.loc)}</loc>${u.lastmod ? `<lastmod>${u.lastmod}</lastmod>` : ''}<changefreq>${u.changefreq}</changefreq><priority>${u.priority}</priority></url>`).join('\n')}\n</urlset>`);
});

const staticOpts = { maxAge: '30d', index: false, dotfiles: 'deny', fallthrough: true, setHeaders: (res) => res.set('X-Content-Type-Options', 'nosniff') };
app.use('/uploads/images', express.static(DIRS.images, staticOpts));
app.use('/uploads/documents', express.static(DIRS.documents, { ...staticOpts, setHeaders: (res) => { res.set('X-Content-Type-Options', 'nosniff'); res.set('Content-Disposition', 'inline'); } }));

/* ===================== 12. ADMIN RESOURCES (GENERIC CRUD) ===================== */
const opt = (...vals) => vals.map((v) => (Array.isArray(v) ? v : [v, v.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())]));
const F = (name, label, type = 'text', extra = {}) => ({ name, label, type, ...extra });
const CREATED = F('created_at', 'Created', 'datetime', { readonly: true, list: true });
const maskCnic = (l4) => `*****-****${String(l4 || '').slice(0, 3)}-${String(l4 || '').slice(3) || '*'}`;

const RESOURCES = {
  posts: {
    label: 'Blog Posts', singular: 'Blog Post', group: 'Blog', icon: 'file', table: 'blog_posts', title: 'title',
    select: 't.*, (SELECT COUNT(*) FROM blog_comments bc WHERE bc.post_id = t.id) AS comment_count', sort: 'COALESCE(t.published_at, t.created_at) DESC',
    fields: [
      F('title', 'Title', 'text', { required: true, list: true, search: true, max: 200, full: true }),
      F('slug', 'URL slug', 'text', { help: 'Leave empty to generate from the title. Used in /blog/your-slug', max: 120 }),
      F('category_id', 'Category', 'select', { optionsFrom: { table: 'blog_categories', label: 'name' }, list: true, filter: true }),
      F('status', 'Status', 'select', { options: opt('draft', 'published'), list: true, filter: true, default: 'draft' }),
      F('author', 'Author', 'text', { max: 100 }),
      F('published_at', 'Publish date', 'datetime', { list: true, help: 'Set automatically when first published. Future dates schedule the post.' }),
      F('featured', 'Featured post', 'bool', { list: true, filter: true }),
      F('allow_comments', 'Allow comments', 'bool', { default: 1 }),
      F('featured_image', 'Featured image', 'image', { full: true, help: 'Recommended 1200 × 630 px. If empty, an original cover graphic is generated.' }),
      F('excerpt', 'Excerpt / summary', 'textarea', { max: 500, full: true }),
      F('content', 'Content', 'html', { full: true }),
      F('tags', 'Tags', 'tags', { virtual: true, full: true, help: 'Comma separated, e.g. Android, Battery, Tips' }),
      F('seo_title', 'SEO title', 'text', { max: 120, full: true, help: 'Shown in Google results. Aim for 50–60 characters.' }),
      F('meta_description', 'Meta description', 'textarea', { max: 300, full: true, help: 'Aim for 140–160 characters.' }),
      F('views', 'Views', 'number', { readonly: true, list: true }),
    ],
    beforeSave(d, old) {
      if ('title' in d || 'slug' in d) d.slug = uniqueSlug('blog_posts', d.slug || d.title || old?.title, old?.id);
      if (d.status === 'published' && !(d.published_at || old?.published_at)) d.published_at = nowIso();
      if (!d.author && !old) d.author = S().blog.default_author;
      if (!old && !d.seo_title && d.title) d.seo_title = d.title;
      if (!old && !d.meta_description && d.excerpt) d.meta_description = d.excerpt.slice(0, 160);
    },
    afterSave(id, d, virt) { if (virt.tags !== undefined) setPostTags(id, virt.tags); },
    afterLoad(r, mode) { if (mode === 'detail') r.tags = postTags(r.id).map((t) => t.name).join(', '); return r; },
    links: (r) => [{ label: r.status === 'published' ? 'View on website' : 'Preview draft', href: `/blog/${r.slug}`, icon: 'external' }],
  },
  blog_categories: {
    label: 'Categories', singular: 'Category', group: 'Blog', icon: 'layers', table: 'blog_categories', title: 'name', sort: 't.sort_order, t.name',
    select: "t.*, (SELECT COUNT(*) FROM blog_posts p WHERE p.category_id = t.id) AS post_count",
    fields: [F('name', 'Name', 'text', { required: true, list: true, search: true, max: 100 }), F('slug', 'URL slug', 'text', { help: 'Leave empty to generate automatically.' }),
      F('icon', 'Icon', 'icon', { list: true }), F('sort_order', 'Display order', 'number', { list: true, int: true }), F('description', 'Description', 'textarea', { max: 500, full: true }),
      F('post_count', 'Posts', 'number', { readonly: true, list: true, computed: true })],
    beforeSave(d, old) { if ('name' in d || 'slug' in d) d.slug = uniqueSlug('blog_categories', d.slug || d.name || old?.name, old?.id); },
  },
  blog_tags: {
    label: 'Tags', singular: 'Tag', group: 'Blog', icon: 'tag', table: 'blog_tags', title: 'name', sort: 't.name',
    select: 't.*, (SELECT COUNT(*) FROM blog_post_tags pt WHERE pt.tag_id = t.id) AS post_count',
    fields: [F('name', 'Name', 'text', { required: true, list: true, search: true, max: 40 }), F('slug', 'Slug', 'text', { list: true }), F('post_count', 'Posts', 'number', { readonly: true, list: true, computed: true })],
    beforeSave(d, old) { if ('name' in d || 'slug' in d) d.slug = uniqueSlug('blog_tags', d.slug || d.name || old?.name, old?.id); },
  },
  comments: {
    label: 'Comments', singular: 'Comment', group: 'Blog', icon: 'chat', table: 'blog_comments', title: 'name', canCreate: false, badge: "SELECT COUNT(*) FROM blog_comments WHERE status = 'pending'",
    from: 'blog_comments t LEFT JOIN blog_posts p ON p.id = t.post_id', select: 't.*, p.title AS post_title, p.slug AS post_slug', searchCols: ['t.name', 't.email', 't.comment', 'p.title'],
    fields: [F('post_title', 'Article', 'text', { readonly: true, list: true, computed: true }), F('name', 'Name', 'text', { list: true, max: 80 }), F('email', 'Email', 'email', { readonly: true }),
      F('comment', 'Comment', 'textarea', { list: true, max: 2000, full: true }), F('status', 'Status', 'select', { options: opt('pending', 'approved', 'spam'), list: true, filter: true }), CREATED],
    links: (r) => (r.post_slug ? [{ label: 'View article', href: `/blog/${r.post_slug}`, icon: 'external' }] : []),
  },
  courses: {
    label: 'Courses', singular: 'Course', group: 'Course', icon: 'book', table: 'courses', title: 'name', sort: 't.id',
    fields: [F('name', 'Course name', 'text', { required: true, list: true, search: true, max: 120 }), F('slug', 'Slug', 'text'),
      F('fee', 'Fee (PKR)', 'money', { required: true, list: true }), F('fee_period', 'Fee period', 'select', { options: opt('month', 'week', 'course'), list: true }),
      F('duration', 'Duration', 'text', { list: true, max: 100 }), F('enrollment_open', 'Enrolment open', 'bool', { list: true }), F('active', 'Active', 'bool', { list: true }),
      F('tagline', 'Tagline', 'text', { full: true, max: 200 }), F('schedule', 'Schedule', 'text', { full: true, max: 300 }), F('requirements', 'Requirements', 'text', { full: true, max: 300 }),
      F('description', 'Course description', 'textarea', { full: true, max: 5000 }), F('objectives', 'Learning objectives', 'lines', { full: true, help: 'One objective per line.' }),
      F('syllabus', 'Syllabus', 'lines', { full: true, help: 'One module per line in the format:  Module title | short description' }), F('image', 'Course image', 'image')],
    beforeSave(d, old) { if ('name' in d || 'slug' in d) d.slug = uniqueSlug('courses', d.slug || d.name || old?.name, old?.id); },
    links: () => [{ label: 'View course page', href: '/course', icon: 'external' }],
  },
  enrollments: {
    label: 'Enrollments', singular: 'Enrollment', group: 'Course', icon: 'list', table: 'enrollments', title: 'ref', badge: "SELECT COUNT(*) FROM enrollments WHERE status = 'pending'", exportable: true,
    from: 'enrollments t JOIN students s ON s.id = t.student_id JOIN courses c ON c.id = t.course_id',
    select: "t.*, s.full_name AS student_name, s.father_name AS student_father, s.phone AS student_phone, s.city AS student_city, c.name AS course_name, (SELECT certificate_id FROM certificates x WHERE x.enrollment_id = t.id AND x.status = 'valid' LIMIT 1) AS certificate_id",
    searchCols: ['t.ref', 's.full_name', 's.phone', 's.father_name', 's.city'],
    fields: [F('ref', 'Reference', 'text', { readonly: true, list: true }), F('student_name', 'Student', 'text', { readonly: true, list: true, computed: true }),
      F('student_phone', 'Phone', 'text', { readonly: true, list: true, computed: true }), F('student_city', 'City', 'text', { readonly: true, computed: true }),
      F('student_id', 'Student record', 'select', { required: true, optionsFrom: { table: 'students', label: "full_name || ' — ' || COALESCE(phone, '')" } }),
      F('course_id', 'Course', 'select', { required: true, optionsFrom: { table: 'courses', label: 'name' } }),
      F('status', 'Enrollment status', 'select', { options: opt('pending', 'active', 'completed', 'cancelled'), list: true, filter: true, default: 'pending' }),
      F('fee_status', 'Fee status', 'select', { options: opt('unpaid', 'partial', 'paid', 'waived'), list: true, filter: true, default: 'unpaid' }),
      F('months_paid', 'Months paid', 'number', { int: true }), F('preferred_timing', 'Preferred timing', 'text'),
      F('start_date', 'Start date', 'date'), F('completion_date', 'Completion date', 'date', { help: 'Set when the course is completed.' }),
      F('certificate_eligible', 'Certificate eligible', 'bool', { list: true, filter: true, help: 'Completed enrollments are automatically eligible.' }),
      F('certificate_id', 'Certificate', 'text', { readonly: true, list: true, computed: true }),
      F('message', 'Student message', 'textarea', { readonly: true, full: true }), F('notes', 'Internal notes', 'textarea', { full: true, max: 5000 }), CREATED],
    beforeSave(d, old) {
      if (!old) d.ref = makeRef('ENR');
      if (d.status === 'completed') { if (!d.completion_date && !old?.completion_date) d.completion_date = today(); if (d.certificate_eligible === undefined) d.certificate_eligible = 1; }
      if (d.status === 'active' && !d.start_date && !old?.start_date) d.start_date = today();
    },
  },
  students: {
    label: 'Students', singular: 'Student', group: 'Course', icon: 'users', table: 'students', title: 'full_name', exportable: true,
    select: 't.*, (SELECT COUNT(*) FROM enrollments e WHERE e.student_id = t.id) AS enrollment_count',
    fields: [F('full_name', 'Full name', 'text', { required: true, list: true, search: true, max: 100 }), F('father_name', "Father's name", 'text', { list: true, search: true, max: 100 }),
      F('phone', 'Phone', 'tel', { required: true, list: true, search: true, max: 20 }), F('email', 'Email', 'email', { search: true }), F('gender', 'Gender', 'select', { options: opt('Male', 'Female', 'Prefer not to say') }),
      F('education', 'Education', 'text'), F('city', 'City', 'text', { list: true, search: true }), F('address', 'Address', 'text', { full: true, max: 250 }),
      F('notes', 'Notes', 'textarea', { full: true }), F('enrollment_count', 'Enrollments', 'number', { readonly: true, list: true, computed: true }), CREATED],
  },
  certificates: {
    label: 'Certificates', singular: 'Certificate', group: 'Course', icon: 'award', table: 'certificates', title: 'certificate_id', canCreate: false, exportable: true,
    fields: [F('certificate_id', 'Certificate ID', 'text', { readonly: true, list: true, search: true }), F('student_name', 'Student name', 'text', { required: true, list: true, search: true, max: 100 }),
      F('father_name', "Father's name", 'text', { max: 100 }), F('course_name', 'Course', 'text', { required: true, list: true, max: 120 }), F('completion_date', 'Completion date', 'date', { required: true, list: true }),
      F('grade', 'Grade (optional)', 'text', { max: 20 }), F('status', 'Status', 'select', { options: opt('valid', 'revoked'), readonly: true, list: true, filter: true }),
      F('revoke_reason', 'Revocation reason', 'text', { readonly: true }), F('issued_by', 'Issued by', 'text', { readonly: true }), F('issued_at', 'Issued at', 'datetime', { readonly: true, list: true })],
    links: (r) => [{ label: 'View / print certificate', href: `/certificate/${r.certificate_id}`, icon: 'print' }, { label: 'Public verification', href: `/verify?id=${r.certificate_id}`, icon: 'shield' }],
  },
  products: {
    label: 'Products', singular: 'Product', group: 'CCTV', icon: 'cctv', table: 'products', title: 'name', sort: 't.sort_order, t.name', exportable: true,
    searchCols: ['t.name', 't.sku', 't.brand', 't.short_description'],
    fields: [F('image', 'Image', 'image', { list: true }), F('name', 'Product name', 'text', { required: true, list: true, max: 150 }), F('sku', 'SKU', 'text', { list: true, max: 40 }),
      F('category_id', 'Category', 'select', { optionsFrom: { table: 'product_categories', label: 'name' }, list: true, filter: true }),
      F('price', 'Price (PKR)', 'money', { required: true, list: true }), F('unit', 'Unit', 'text', { default: 'piece', max: 20 }),
      F('stock_status', 'Stock status', 'select', { options: opt('in_stock', 'low_stock', 'out_of_stock', 'on_order'), list: true, filter: true, default: 'in_stock' }),
      F('stock_qty', 'Stock quantity', 'number', { int: true, list: true }), F('brand', 'Brand', 'text', { max: 60 }),
      F('installable', 'Counts as a camera for installation charges', 'bool'), F('featured', 'Featured on homepage', 'bool', { filter: true }), F('active', 'Visible in catalogue', 'bool', { list: true, filter: true, default: 1 }),
      F('sort_order', 'Display order', 'number', { int: true }), F('slug', 'Slug', 'text'),
      F('short_description', 'Short description', 'text', { full: true, max: 200 }), F('description', 'Full description', 'textarea', { full: true, max: 5000 }),
      F('specs', 'Specifications', 'lines', { full: true, help: 'One specification per line, e.g. Resolution: 5MP' })],
    beforeSave(d, old) { if ('name' in d || 'slug' in d) d.slug = uniqueSlug('products', d.slug || d.name || old?.name, old?.id); },
  },
  product_categories: {
    label: 'Product Categories', singular: 'Product Category', group: 'CCTV', icon: 'layers', table: 'product_categories', title: 'name', sort: 't.sort_order, t.name',
    select: 't.*, (SELECT COUNT(*) FROM products p WHERE p.category_id = t.id) AS product_count',
    fields: [F('name', 'Name', 'text', { required: true, list: true, search: true }), F('slug', 'Slug', 'text'), F('icon', 'Icon', 'icon', { list: true }),
      F('sort_order', 'Display order', 'number', { int: true, list: true }), F('product_count', 'Products', 'number', { readonly: true, list: true, computed: true })],
    beforeSave(d, old) { if ('name' in d || 'slug' in d) d.slug = uniqueSlug('product_categories', d.slug || d.name || old?.name, old?.id); },
  },
  quotations: {
    label: 'Quotations', singular: 'Quotation', group: 'CCTV', icon: 'file', table: 'quotations', title: 'number', canCreate: false, exportable: true, badge: "SELECT COUNT(*) FROM quotations WHERE status = 'new'",
    select: 't.*, (SELECT COUNT(*) FROM quotation_items i WHERE i.quotation_id = t.id) AS item_count', customView: 'quotation',
    fields: [F('number', 'Quotation no.', 'text', { readonly: true, list: true, search: true }), F('customer_name', 'Customer', 'text', { required: true, list: true, search: true, max: 100 }),
      F('phone', 'Phone', 'tel', { list: true, search: true, max: 20 }), F('email', 'Email', 'email'), F('city', 'City', 'text', { list: true, search: true }), F('address', 'Address', 'text', { full: true, max: 250 }),
      F('status', 'Status', 'select', { options: opt(...QUOTE_STATUS), list: true, filter: true }), F('valid_until', 'Valid until', 'date'),
      F('subtotal', 'Subtotal', 'money', { readonly: true }), F('installation_charge', 'Installation charges', 'money'), F('delivery_charge', 'Delivery charges', 'money'), F('discount', 'Discount', 'money'),
      F('total', 'Total', 'money', { readonly: true, list: true }), F('item_count', 'Items', 'number', { readonly: true, computed: true }),
      F('customer_notes', 'Customer notes', 'textarea', { readonly: true, full: true }), F('notes', 'Internal notes', 'textarea', { full: true }), CREATED],
    beforeSave(d, old) {
      if (!old) return;
      const sub = old.subtotal || 0;
      const inst = d.installation_charge ?? old.installation_charge ?? 0, del = d.delivery_charge ?? old.delivery_charge ?? 0, disc = d.discount ?? old.discount ?? 0;
      d.total = Math.max(0, sub + inst + del - disc);
      d.include_installation = inst > 0 ? 1 : 0;
    },
    links: (r) => [{ label: 'Open printable quotation', href: `/quotation/${r.number}`, icon: 'print' }],
  },
  service_requests: {
    label: 'CCTV Service Requests', singular: 'Service Request', group: 'CCTV', icon: 'wrench', table: 'service_requests', title: 'ref', canCreate: false, exportable: true, badge: "SELECT COUNT(*) FROM service_requests WHERE status = 'new'",
    fields: [F('ref', 'Reference', 'text', { readonly: true, list: true, search: true }), F('name', 'Customer', 'text', { readonly: true, list: true, search: true }), F('phone', 'Phone', 'tel', { readonly: true, list: true, search: true }),
      F('city', 'City', 'text', { readonly: true, list: true, search: true }), F('address', 'Address', 'text', { readonly: true, full: true }), F('service_type', 'Service', 'text', { readonly: true, list: true, search: true }),
      F('cameras', 'Cameras', 'number', { readonly: true }), F('preferred_date', 'Preferred date', 'date', { readonly: true, list: true }), F('details', 'Details', 'textarea', { readonly: true, full: true }),
      F('status', 'Status', 'select', { options: opt('new', 'contacted', 'scheduled', 'in_progress', 'completed', 'cancelled'), list: true, filter: true }), F('notes', 'Internal notes', 'textarea', { full: true }), CREATED],
  },
  scheme: {
    label: 'Scheme Submissions', singular: 'Scheme Submission', group: 'Apna Ghar Apni Chat', icon: 'home', table: 'scheme_submissions', title: 'ref', canCreate: false, exportable: true, adminOnly: true,
    badge: "SELECT COUNT(*) FROM scheme_submissions WHERE status = 'pending'", searchCols: ['t.ref', 't.full_name', 't.father_name', 't.mobile', 't.alt_mobile', 't.city', 't.district'],
    searchHook(term) { const d = term.replace(/\D/g, ''); return d.length === 13 ? { sql: 't.cnic_index = ?', params: [blindIndex(normCnic(d))] } : null; },
    fields: [F('ref', 'Reference', 'text', { readonly: true, list: true }), F('full_name', 'Applicant name', 'text', { list: true, max: 100 }), F('father_name', "Father's / husband's name", 'text', { max: 100 }),
      F('cnic', 'CNIC', 'cnic', { virtual: true, list: true, help: 'Stored encrypted. Enter a new CNIC only to correct it.' }), F('mobile', 'Mobile', 'tel', { list: true, max: 20 }), F('alt_mobile', 'Alternate number', 'tel', { max: 20 }),
      F('email', 'Email', 'email'), F('gender', 'Gender', 'text'), F('marital_status', 'Marital status', 'text'), F('family_members', 'Family members', 'number', { int: true }),
      F('city', 'City', 'text', { list: true }), F('district', 'District / Tehsil', 'text'), F('address', 'Address', 'text', { full: true, max: 300 }), F('occupation', 'Occupation', 'text'),
      F('monthly_income', 'Monthly income', 'text'), F('owns_plot', 'Owns a plot', 'text'), F('plot_size', 'Plot size', 'text'), F('plot_location', 'Plot location', 'text', { full: true }),
      F('additional_info', 'Additional information', 'textarea', { full: true, max: 2000 }), F('documents', 'Uploaded documents', 'files', { readonly: true, full: true }),
      F('consent_at', 'Consent given', 'datetime', { readonly: true }),
      F('status', 'Status', 'select', { options: opt('pending', 'contacted', 'processed', 'completed'), list: true, filter: true }), F('notes', 'Internal notes', 'textarea', { full: true, max: 5000 }), CREATED],
    afterLoad(r, mode, req) {
      r.cnic = mode === 'detail' || mode === 'export' ? decrypt(r.cnic_enc) : maskCnic(r.cnic_last4);
      if (mode === 'detail' && req) logActivity(req, 'Viewed scheme submission (CNIC decrypted)', 'scheme', r.id, r.ref);
      try { r.documents = JSON.parse(r.documents || '[]').map((d) => ({ name: d.original || d.file, size: d.size, url: `/admin/files/scheme/${r.id}/${d.file}` })); } catch { r.documents = []; }
      delete r.cnic_enc; delete r.cnic_index; delete r.ip_hash;
      return r;
    },
    beforeSave(d, old, virt) {
      if (virt.cnic && virt.cnic !== decrypt(old?.cnic_enc)) {
        if (!V.cnic(virt.cnic)) throw new HttpError(422, 'Invalid CNIC.', { cnic: 'Enter a valid 13-digit CNIC.' });
        const c = normCnic(virt.cnic);
        d.cnic_enc = encrypt(c); d.cnic_index = blindIndex(c); d.cnic_last4 = c.replace(/\D/g, '').slice(-4);
      }
    },
    onDelete(row) { try { for (const doc of JSON.parse(row.documents || '[]')) fs.unlinkSync(path.join(DIRS.private, path.basename(doc.file))); } catch { /* already gone */ } },
  },
  team: {
    label: 'Team Members', singular: 'Team Member', group: 'Website', icon: 'users', table: 'team_members', title: 'name', sort: 't.sort_order, t.id',
    fields: [F('photo', 'Profile picture', 'image', { list: true, help: 'Square or portrait image, at least 600 px wide.' }), F('name', 'Name', 'text', { required: true, list: true, search: true, max: 100 }),
      F('position', 'Position', 'text', { required: true, list: true, search: true, max: 100 }), F('sort_order', 'Display order', 'number', { int: true, list: true }), F('active', 'Active', 'bool', { list: true, default: 1 }),
      F('bio', 'Short bio', 'textarea', { full: true, max: 600 }), F('email', 'Email', 'email'), F('phone', 'Phone', 'tel'),
      F('facebook', 'Facebook URL', 'url'), F('linkedin', 'LinkedIn URL', 'url'), F('instagram', 'Instagram URL', 'url'), F('x', 'X (Twitter) URL', 'url')],
  },
  services: {
    label: 'Services', singular: 'Service', group: 'Website', icon: 'grid', table: 'services', title: 'title', sort: "t.grp, t.sort_order, t.id",
    fields: [F('grp', 'Section', 'select', { options: [['main', 'Main services'], ['cctv', 'CCTV services']], list: true, filter: true, required: true, default: 'main' }),
      F('title', 'Title', 'text', { required: true, list: true, search: true, max: 120 }), F('icon', 'Icon', 'icon', { list: true }), F('sort_order', 'Display order', 'number', { int: true, list: true }),
      F('active', 'Active', 'bool', { list: true, default: 1 }), F('link', 'Link (optional)', 'url'), F('summary', 'Summary', 'textarea', { full: true, max: 300 }), F('description', 'Extra details (services page)', 'textarea', { full: true, max: 2000 })],
    beforeSave(d, old) { if ('title' in d) d.slug = slugify(d.title); },
  },
  testimonials: {
    label: 'Testimonials', singular: 'Testimonial', group: 'Website', icon: 'quote', table: 'testimonials', title: 'name', sort: 't.sort_order, t.id',
    fields: [F('name', 'Customer name', 'text', { required: true, list: true, search: true, max: 100 }), F('role', 'Role / company', 'text', { max: 100 }), F('city', 'City', 'text', { list: true }),
      F('rating', 'Rating (1–5)', 'number', { int: true, default: 5, list: true }), F('active', 'Visible', 'bool', { list: true, default: 1 }),
      F('is_demo', 'Demo / sample content', 'bool', { list: true, help: 'Sample testimonials are publicly labelled “Demo content”. Only publish real reviews unmarked.' }),
      F('sort_order', 'Display order', 'number', { int: true }), F('photo', 'Photo', 'image'), F('content', 'Testimonial', 'textarea', { required: true, full: true, max: 800 })],
  },
  contacts: {
    label: 'Contact Messages', singular: 'Message', group: 'Inbox', icon: 'mail', table: 'contact_messages', title: 'subject', canCreate: false, exportable: true, badge: "SELECT COUNT(*) FROM contact_messages WHERE status = 'new'",
    fields: [F('ref', 'Reference', 'text', { readonly: true }), F('name', 'Name', 'text', { readonly: true, list: true, search: true }), F('email', 'Email', 'email', { readonly: true, list: true, search: true }),
      F('phone', 'Phone', 'tel', { readonly: true, search: true }), F('subject', 'Subject', 'text', { readonly: true, list: true, search: true }), F('message', 'Message', 'textarea', { readonly: true, full: true, search: true }),
      F('status', 'Status', 'select', { options: opt('new', 'read', 'replied', 'resolved'), list: true, filter: true }), F('notes', 'Internal notes', 'textarea', { full: true }), CREATED],
    links: (r) => [{ label: 'Reply by email', href: `mailto:${r.email}?subject=${encodeURIComponent('Re: ' + (r.subject || 'Your message to SDS'))}`, icon: 'mail' }],
  },
  admins: {
    label: 'Admin Users', singular: 'Admin User', group: 'System', icon: 'lock', table: 'admin_users', title: 'name', adminOnly: true,
    select: 't.id, t.name, t.email, t.role, t.active, t.last_login, t.created_at, t.updated_at',
    fields: [F('name', 'Name', 'text', { required: true, list: true, search: true, max: 100 }), F('email', 'Email (login)', 'email', { required: true, list: true, search: true }),
      F('role', 'Role', 'select', { options: [['admin', 'Administrator (full access)'], ['editor', 'Editor (no scheme data, users or system settings)']], list: true, default: 'admin', required: true }),
      F('active', 'Active', 'bool', { list: true, default: 1 }), F('password', 'Password', 'password', { virtual: true, help: 'Minimum 10 characters. Leave empty to keep the current password.' }),
      F('last_login', 'Last login', 'datetime', { readonly: true, list: true }), CREATED],
    beforeSave(d, old, virt, req) {
      if (d.email && q.get('SELECT id FROM admin_users WHERE email = ? AND id != ?', d.email, old?.id || 0)) throw new HttpError(422, 'Email already in use.', { email: 'Another admin uses this email.' });
      if (!old && !virt.password) throw new HttpError(422, 'Password is required.', { password: 'Password is required for new users.' });
      if (virt.password) { if (String(virt.password).length < 10) throw new HttpError(422, 'Password too short.', { password: 'Use at least 10 characters.' }); d.password_hash = hashPassword(virt.password); }
      if (old && old.id === req.admin.id && (d.active === 0 || (d.role && d.role !== 'admin'))) throw new HttpError(422, 'You cannot deactivate or downgrade your own account.');
    },
    afterSave(id, d, virt, old) { if (old && (virt.password || d.active === 0)) q.run('DELETE FROM sessions WHERE admin_id = ?', id); },
    beforeDelete(row, req) {
      if (row.id === req.admin.id) throw new HttpError(422, 'You cannot delete your own account.');
      if (q.val("SELECT COUNT(*) FROM admin_users WHERE role = 'admin' AND active = 1 AND id != ?", row.id) < 1) throw new HttpError(422, 'At least one active administrator must remain.');
    },
  },
  activity: {
    label: 'Activity Log', singular: 'Activity', group: 'System', icon: 'activity', table: 'activity_logs', title: 'action', canCreate: false, canEdit: false, canDelete: false, adminOnly: true, sort: 't.id DESC',
    fields: [F('created_at', 'Time', 'datetime', { readonly: true, list: true }), F('actor', 'User', 'text', { readonly: true, list: true, search: true }), F('action', 'Action', 'text', { readonly: true, list: true, search: true }),
      F('entity', 'Area', 'text', { readonly: true, list: true, filter: true, search: true }), F('details', 'Details', 'text', { readonly: true, list: true, search: true }), F('ip', 'IP', 'text', { readonly: true })],
    filterOptions: { entity: () => q.all('SELECT DISTINCT entity FROM activity_logs WHERE entity IS NOT NULL ORDER BY entity').map((r) => [r.entity, r.entity]) },
  },
};
for (const [key, R] of Object.entries(RESOURCES)) {
  R.key = key;
  if (R.canCreate === undefined) R.canCreate = true;
  if (R.canEdit === undefined) R.canEdit = true;
  if (R.canDelete === undefined) R.canDelete = true;
  R.sort = R.sort || 't.id DESC';
}
const canAccess = (R, admin) => !R.adminOnly || admin.role === 'admin';
function getResource(req) {
  const R = RESOURCES[req.params.key];
  if (!R) throw new HttpError(404, 'Unknown section.');
  if (!canAccess(R, req.admin)) throw new HttpError(403, 'You do not have permission to access this section.');
  return R;
}
function fieldOptions(f) {
  if (f.options) return f.options;
  if (f.optionsFrom) return q.all(`SELECT id AS v, ${f.optionsFrom.label} AS l FROM ${f.optionsFrom.table} ORDER BY 2 LIMIT 2000`).map((r) => [r.v, r.l]);
  if (f.type === 'icon') return ICON_NAMES.map((n) => [n, n]);
  return null;
}
function coerceField(f, raw, errors) {
  const max = f.max || (f.type === 'html' ? 400000 : ['textarea', 'lines'].includes(f.type) ? 20000 : 300);
  let v = raw;
  switch (f.type) {
    case 'bool': return raw === true || raw === 1 || raw === '1' || raw === 'true' || raw === 'on' ? 1 : 0;
    case 'number': case 'money': {
      if (raw === '' || raw === null || raw === undefined) return null;
      v = Number(raw);
      if (!isFinite(v)) { errors[f.name] = 'Enter a valid number.'; return null; }
      if (f.type === 'money' && v < 0) { errors[f.name] = 'Must be zero or more.'; return null; }
      return f.int ? Math.round(v) : Math.round(v * 100) / 100;
    }
    case 'html': return cleanHtml(raw);
    case 'date': if (!raw) return null; if (!V.date(raw)) errors[f.name] = 'Enter a valid date.'; return String(raw).slice(0, 10);
    case 'datetime': { if (!raw) return null; const d = new Date(raw); if (isNaN(d)) { errors[f.name] = 'Enter a valid date and time.'; return null; } return d.toISOString(); }
    case 'select': case 'icon': {
      if (raw === '' || raw === null || raw === undefined) return null;
      const options = fieldOptions(f) || [];
      const hit = options.find(([val]) => String(val) === String(raw));
      if (!hit) { errors[f.name] = 'Choose a valid option.'; return null; }
      return hit[0];
    }
    case 'email': v = cleanText(raw, 190).toLowerCase(); if (v && !V.email(v)) errors[f.name] = 'Enter a valid email.'; return v;
    case 'url': v = cleanText(raw, 500); if (v && !/^(https?:\/\/|\/(?!\/)|#|mailto:|tel:)/i.test(v)) errors[f.name] = 'Enter a full URL starting with https:// or a site path starting with /'; return v;
    case 'image': v = cleanText(raw, 500); if (v && !/^(\/uploads\/images\/[\w.-]+|https:\/\/[^\s"'<>]+)$/.test(v)) errors[f.name] = 'Upload an image or use an https:// image URL.'; return v;
    default: return cleanText(raw, max);
  }
}
function collectData(R, body, old) {
  const data = {}, virt = {}, errors = {};
  for (const f of R.fields) {
    if (f.readonly || f.computed) continue;
    if (!(f.name in body)) { if (!old && f.default !== undefined) data[f.name] = f.default; continue; }
    if (f.virtual) { virt[f.name] = typeof body[f.name] === 'string' ? body[f.name].trim() : body[f.name]; continue; }
    data[f.name] = coerceField(f, body[f.name], errors);
    if (f.required && (data[f.name] === null || data[f.name] === '')) errors[f.name] = `${f.label} is required.`;
  }
  if (!old) for (const f of R.fields) if (f.required && !f.virtual && !f.readonly && !(f.name in data)) errors[f.name] = `${f.label} is required.`;
  if (Object.keys(errors).length) throw new HttpError(422, 'Please correct the highlighted fields.', errors);
  return { data, virt };
}
function loadRow(R, id) { return q.get(`SELECT ${R.select || 't.*'} FROM ${R.from || R.table + ' t'} WHERE t.id = ?`, id); }
function rawRow(R, id) { return q.get(`SELECT * FROM ${R.table} WHERE id = ?`, id); }
function buildListQuery(R, query) {
  const where = [], params = [];
  const term = cleanText(query.q, 100);
  if (term) {
    const cols = R.searchCols || R.fields.filter((f) => f.search && !f.computed).map((f) => `t.${f.name}`);
    const ors = cols.map((c) => `${c} LIKE ?`);
    cols.forEach(() => params.push(`%${term}%`));
    const extra = R.searchHook && R.searchHook(term);
    if (extra) { ors.push(extra.sql); params.push(...extra.params); }
    if (ors.length) where.push(`(${ors.join(' OR ')})`);
  }
  for (const f of R.fields.filter((x) => x.filter && !x.computed)) {
    const v = query[f.name];
    if (v !== undefined && v !== '') { where.push(`t.${f.name} = ?`); params.push(f.type === 'bool' ? (v === '1' ? 1 : 0) : v); }
  }
  return { where: where.length ? 'WHERE ' + where.join(' AND ') : '', params };
}
function listOrder(R, query) {
  const f = R.fields.find((x) => x.name === query.sort && x.list && !x.virtual);
  if (!f) return R.sort;
  return `${f.computed ? f.name : 't.' + f.name} ${query.dir === 'asc' ? 'ASC' : 'DESC'}`;
}

/* ============================== 13. ADMIN APIs & PAGES ============================== */
const adminApi = express.Router();
const loginLimiter = rateLimit({ name: 'login', windowMs: 15 * 60 * 1000, max: 8 });
const loginEmailLimiter = rateLimit({ name: 'login-email', windowMs: 15 * 60 * 1000, max: 5, keyFn: (req) => String(req.body?.email || '').toLowerCase().slice(0, 190) });

const adminCount = () => q.val('SELECT COUNT(*) FROM admin_users');
let SETUP_TOKEN = null;
function bootstrapAdmin() {
  if (adminCount()) return;
  const email = (process.env.ADMIN_EMAIL || '').trim(), pass = process.env.ADMIN_PASSWORD || '';
  if (email && V.email(email) && pass.length >= 10) {
    q.run('INSERT INTO admin_users (name, email, password_hash, role, active, created_at) VALUES (?,?,?,?,1,?)', process.env.ADMIN_NAME || 'Administrator', email.toLowerCase(), hashPassword(pass), 'admin', nowIso());
    console.log(`[setup] Initial admin account created for ${email}. Remove ADMIN_PASSWORD from .env now if you like — it is not needed again.`);
    return;
  }
  if (email && pass.length < 10) console.warn('[setup] ADMIN_PASSWORD must be at least 10 characters — falling back to first-run setup.');
  SETUP_TOKEN = randomToken(12);
  fs.writeFileSync(path.join(DATA_DIR, 'setup-token.txt'), SETUP_TOKEN + '\n', { mode: 0o600 });
  console.log('\n================ FIRST-RUN SETUP ================');
  console.log(`No admin account exists yet. Open /admin/setup and use this one-time setup token:\n\n    ${SETUP_TOKEN}\n`);
  console.log('(The token is also saved in data/setup-token.txt)');
  console.log('=================================================\n');
}

adminApi.use(csrfCheck);
adminApi.post('/setup', loginLimiter, (req, res) => {
  if (adminCount() || !SETUP_TOKEN) throw new HttpError(403, 'Setup has already been completed.');
  const b = req.body || {};
  if (!safeEqual(String(b.token || '').trim(), SETUP_TOKEN)) throw new HttpError(403, 'Invalid setup token.', { token: 'The setup token is not correct.' });
  requireFields(b, { name: 'Name', email: 'Email', password: 'Password' });
  if (!V.email(b.email)) throw new HttpError(422, 'Invalid email.', { email: 'Enter a valid email.' });
  if (String(b.password).length < 10) throw new HttpError(422, 'Password too short.', { password: 'Use at least 10 characters.' });
  if (b.password !== b.confirm) throw new HttpError(422, 'Passwords do not match.', { confirm: 'Passwords do not match.' });
  const r = q.run('INSERT INTO admin_users (name, email, password_hash, role, active, created_at) VALUES (?,?,?,?,1,?)', cleanText(b.name, 100), cleanText(b.email, 190).toLowerCase(), hashPassword(b.password), 'admin', nowIso());
  SETUP_TOKEN = null;
  try { fs.unlinkSync(path.join(DATA_DIR, 'setup-token.txt')); } catch { /* ignore */ }
  const admin = q.get('SELECT * FROM admin_users WHERE id = ?', r.lastInsertRowid);
  createSession(req, res, admin);
  req.admin = admin;
  logActivity(req, 'Initial admin account created', 'admins', admin.id);
  res.json({ ok: true, redirect: '/admin' });
});
adminApi.post('/login', loginLimiter, loginEmailLimiter, (req, res) => {
  const email = cleanText(req.body?.email, 190).toLowerCase(), password = String(req.body?.password || '');
  const user = q.get('SELECT * FROM admin_users WHERE email = ?', email);
  const ok = verifyPassword(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok || !user.active) {
    logActivity(req, 'Failed admin login', 'auth', null, email);
    throw new HttpError(401, 'Incorrect email or password.');
  }
  q.run('DELETE FROM sessions WHERE admin_id = ? AND (expires_at < ? OR last_seen < ?)', user.id, Date.now(), Date.now() - SESSION_IDLE_MS);
  createSession(req, res, user);
  q.run('UPDATE admin_users SET last_login = ? WHERE id = ?', nowIso(), user.id);
  req.admin = user;
  logActivity(req, 'Admin logged in', 'auth', user.id);
  let next = String(req.body?.next || '/admin');
  if (!/^\/admin(\/|$|#|\?)/.test(next) || next.startsWith('//')) next = '/admin';
  res.json({ ok: true, redirect: next });
});
adminApi.post('/logout', (req, res) => {
  const tok = req.cookies.sds_admin;
  if (tok) q.run('DELETE FROM sessions WHERE id = ?', sha256(tok));
  res.clearCookie('sds_admin', { path: '/' });
  res.json({ ok: true, redirect: '/admin/login' });
});

adminApi.use(requireAdmin);
const adminOnly = (req, res, next) => (req.admin.role === 'admin' ? next() : next(new HttpError(403, 'Administrator access required.')));

const SETTINGS_SCHEMA = {
  general: { label: 'General', icon: 'settings', fields: [F('site_name', 'Website name'), F('short_name', 'Short name'), F('tagline', 'Tagline'), F('service_area', 'Service area'), F('logo', 'Logo', 'image', { help: 'Square PNG/WEBP recommended.' }), F('favicon', 'Favicon', 'image', { help: 'PNG or ICO, 64×64 px or larger.' })] },
  contact: { label: 'Contact details', icon: 'call', fields: [F('phone', 'Phone number'), F('email', 'Support email', 'email'), F('whatsapp', 'WhatsApp number', 'text', { help: 'International format without + or spaces, e.g. 923001234567. Leave empty to hide WhatsApp buttons.' }), F('address', 'Business address'), F('hours', 'Working hours'), F('map_link', 'Google Maps link', 'url'), F('support_note', 'Email support note')] },
  social: { label: 'Social media', icon: 'globe', fields: ['facebook', 'instagram', 'youtube', 'tiktok', 'linkedin', 'x'].map((k) => F(k, k === 'x' ? 'X (Twitter) URL' : `${k[0].toUpperCase() + k.slice(1)} URL`, 'url')) },
  seo: { label: 'SEO', icon: 'search', fields: [F('meta_title', 'Default meta title', 'text', { max: 120 }), F('meta_description', 'Default meta description', 'textarea', { max: 300 }), F('keywords', 'Keywords', 'text', { max: 500 }), F('og_image', 'Default social share image', 'image', { help: '1200 × 630 px JPG/PNG.' }), F('base_url', 'Website URL', 'url', { help: 'e.g. https://www.yourdomain.pk — used for sitemap and certificate links.' }), F('google_verification', 'Google Search Console verification code')] },
  footer: { label: 'Footer', icon: 'list', fields: [F('about', 'Footer about text', 'textarea'), F('copyright', 'Copyright text', 'text', { help: '{year} is replaced with the current year.' }), F('note', 'Footer note')] },
  currency: { label: 'Currency', icon: 'tag', fields: [F('code', 'Currency code'), F('symbol', 'Currency symbol'), F('position', 'Symbol position', 'select', { options: [['before', 'Before amount (Rs 1,000)'], ['after', 'After amount (1,000 Rs)']] })] },
  charges: { label: 'Quotation charges', icon: 'cart', fields: [F('installation_base', 'Installation base charge', 'money'), F('installation_per_camera', 'Installation charge per camera', 'money'), F('delivery_charge', 'Delivery charge', 'money'), F('free_delivery_above', 'Free delivery above (0 = never)', 'money'), F('discount_percent', 'Automatic discount %', 'number'), F('discount_threshold', 'Discount applies above subtotal', 'money'), F('quotation_validity_days', 'Quotation validity (days)', 'number', { int: true }), F('terms', 'Quotation terms & conditions', 'lines', { help: 'One term per line.' })] },
  certificate: { label: 'Certificate design', icon: 'award', fields: [F('title', 'Certificate title'), F('subtitle', 'Presented-to line'), F('body', 'Body text before course name'), F('footer_text', 'Footer text'), F('signatory_name', 'Authorised signatory name'), F('signatory_title', 'Signatory title'), F('signature_image', 'Signature image', 'image', { help: 'Transparent PNG works best.' }), F('logo', 'Certificate logo', 'image', { help: 'Defaults to the website logo.' }), F('background_image', 'Background image', 'image', { help: 'A4 landscape (3508 × 2480 px). Optional.' }), F('accent', 'Accent colour', 'color'), F('prefix', 'Certificate ID prefix', 'text', { max: 8 }), F('public_download', 'Allow public view/print from verification page', 'bool')] },
  blog: { label: 'Blog', icon: 'file', fields: [F('posts_per_page', 'Posts per page', 'number', { int: true }), F('comments_enabled', 'Enable comments', 'bool'), F('default_author', 'Default author')] },
  scheme: { label: 'Scheme form', icon: 'home', adminOnly: true, fields: [F('form_enabled', 'Accept new submissions', 'bool'), F('uploads_enabled', 'Allow document uploads', 'bool'), F('notice', 'Disclaimer notice', 'textarea')] },
  smtp: { label: 'Email (SMTP)', icon: 'mail', adminOnly: true, fields: [F('enabled', 'Send email notifications', 'bool'), F('host', 'SMTP host'), F('port', 'SMTP port', 'number', { int: true }), F('secure', 'Use SSL/TLS (port 465)', 'bool'), F('user', 'SMTP username'), F('pass', 'SMTP password', 'secret', { help: 'Stored encrypted. Leave blank to keep the current password.' }), F('from', 'From address', 'text', { help: 'e.g. SDS Website <no-reply@yourdomain.pk>' }), F('notify_to', 'Send notifications to', 'email')] },
  legal: { label: 'Privacy & terms', icon: 'shield', fields: [F('privacy_html', 'Privacy policy', 'html'), F('terms_html', 'Terms & conditions', 'html')] },
};
const prettify = (k) => k.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
const HOME_LABELS = { banner: 'Announcement banner', hero: 'Hero section', intro: 'Introduction / About', services: 'Services overview', blog: 'Blog highlights', course: 'Computer course', cctv: 'CCTV services', products: 'CCTV products', scheme: 'Apna Ghar Apni Chat', team: 'Team section', certificate: 'Certificates', why: 'Why choose SDS', testimonials: 'Testimonials', contact: 'Contact section', cta: 'Call to action' };
const HOME_SCHEMA = Object.fromEntries(Object.entries(DEFAULT_HOME).map(([sec, vals]) => [sec, {
  label: HOME_LABELS[sec] || prettify(sec),
  fields: Object.keys(vals).map((k) => F(k, k === 'enabled' ? 'Show this section' : prettify(k).replace('Stat1', 'Stat 1').replace('Stat2', 'Stat 2').replace('Stat3', 'Stat 3'),
    k === 'enabled' ? 'bool' : k === 'image' ? 'image' : ['points', 'items'].includes(k) ? 'lines' : ['text', 'subtitle'].includes(k) ? 'textarea' : /link$/.test(k) ? 'url' : 'text',
    k === 'items' ? { help: 'One per line:  Title | Description' } : k === 'points' ? { help: 'One point per line.' } : sec === 'hero' && k === 'title' ? { help: 'The phrase “homes, students & businesses” or the word “technology” is highlighted automatically.' } : {})),
}]));

adminApi.get('/meta', (req, res) => {
  const resources = Object.values(RESOURCES).filter((R) => canAccess(R, req.admin)).map((R) => ({
    key: R.key, label: R.label, singular: R.singular, group: R.group, icon: R.icon, title: R.title, canCreate: R.canCreate, canEdit: R.canEdit, canDelete: R.canDelete,
    exportable: !!R.exportable, customView: R.customView || null, badge: R.badge ? q.val(R.badge) : 0,
    fields: R.fields.map((f) => ({ ...f, options: fieldOptions(f) || (R.filterOptions?.[f.name] ? R.filterOptions[f.name]() : undefined), optionsFrom: undefined })),
  }));
  const settings = Object.fromEntries(Object.entries(SETTINGS_SCHEMA).filter(([, g]) => !g.adminOnly || req.admin.role === 'admin'));
  res.json({ ok: true, admin: { id: req.admin.id, name: req.admin.name, email: req.admin.email, role: req.admin.role }, resources, settings, home: HOME_SCHEMA, siteName: S().general.site_name, currency: S().currency });
});

adminApi.get('/dashboard', (req, res) => {
  const c = (sql, ...p) => q.val(sql, ...p) || 0;
  const days = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    const n = ['contact_messages', 'enrollments', 'service_requests', 'quotations', 'scheme_submissions'].reduce((s, t) => s + c(`SELECT COUNT(*) FROM ${t} WHERE substr(created_at, 1, 10) = ?`, d), 0);
    days.push({ d, n });
  }
  const isAdmin = req.admin.role === 'admin';
  res.json({
    ok: true,
    stats: {
      posts: c('SELECT COUNT(*) FROM blog_posts'), posts_published: c("SELECT COUNT(*) FROM blog_posts WHERE status = 'published'"),
      enrollments: c('SELECT COUNT(*) FROM enrollments'), enrollments_pending: c("SELECT COUNT(*) FROM enrollments WHERE status = 'pending'"),
      students: c('SELECT COUNT(*) FROM students'), service_requests: c('SELECT COUNT(*) FROM service_requests'), service_new: c("SELECT COUNT(*) FROM service_requests WHERE status = 'new'"),
      quotations: c('SELECT COUNT(*) FROM quotations'), quotations_new: c("SELECT COUNT(*) FROM quotations WHERE status = 'new'"), quotation_value: c("SELECT COALESCE(SUM(total), 0) FROM quotations WHERE status NOT IN ('rejected', 'cancelled')"),
      scheme: isAdmin ? c('SELECT COUNT(*) FROM scheme_submissions') : null, scheme_pending: isAdmin ? c("SELECT COUNT(*) FROM scheme_submissions WHERE status = 'pending'") : null,
      contacts: c('SELECT COUNT(*) FROM contact_messages'), contacts_new: c("SELECT COUNT(*) FROM contact_messages WHERE status = 'new'"),
      certificates: c('SELECT COUNT(*) FROM certificates'), certificates_valid: c("SELECT COUNT(*) FROM certificates WHERE status = 'valid'"),
      products: c('SELECT COUNT(*) FROM products WHERE active = 1'), comments_pending: c("SELECT COUNT(*) FROM blog_comments WHERE status = 'pending'"),
      verifications: c('SELECT COUNT(*) FROM certificate_verifications'),
    },
    chart: days,
    activity: q.all('SELECT actor, action, entity, details, created_at FROM activity_logs ORDER BY id DESC LIMIT 12'),
    recent: {
      enrollments: q.all('SELECT e.id, e.ref, e.status, e.created_at, s.full_name AS name FROM enrollments e JOIN students s ON s.id = e.student_id ORDER BY e.id DESC LIMIT 5'),
      contacts: q.all('SELECT id, name, subject, status, created_at FROM contact_messages ORDER BY id DESC LIMIT 5'),
      quotations: q.all('SELECT id, number, customer_name AS name, total, status, created_at FROM quotations ORDER BY id DESC LIMIT 5'),
      service_requests: q.all('SELECT id, ref, name, service_type, status, created_at FROM service_requests ORDER BY id DESC LIMIT 5'),
      scheme: isAdmin ? q.all('SELECT id, ref, full_name AS name, city, status, created_at FROM scheme_submissions ORDER BY id DESC LIMIT 5') : [],
    },
    smtp: !!(S().smtp.enabled && S().smtp.host),
    vercel: ON_VERCEL,
  });
});

adminApi.get('/r/:key', (req, res) => {
  const R = getResource(req);
  const page = Math.max(1, parseInt(req.query.page, 10) || 1), per = Math.min(100, Math.max(5, parseInt(req.query.per, 10) || 20));
  const { where, params } = buildListQuery(R, req.query);
  const from = R.from || `${R.table} t`;
  const total = q.val(`SELECT COUNT(*) FROM ${from} ${where}`, ...params);
  const rows = q.all(`SELECT ${R.select || 't.*'} FROM ${from} ${where} ORDER BY ${listOrder(R, req.query)} LIMIT ? OFFSET ?`, ...params, per, (page - 1) * per)
    .map((r) => { if (R.afterLoad) r = R.afterLoad(r, 'list', null); delete r.password_hash; if (R.key === 'posts') delete r.content; return r; });
  res.json({ ok: true, rows, total, page, pages: Math.max(1, Math.ceil(total / per)) });
});
adminApi.get('/r/:key/:id', (req, res) => {
  const R = getResource(req);
  let row = loadRow(R, parseInt(req.params.id, 10) || 0);
  if (!row) throw new HttpError(404, `${R.singular} not found.`);
  if (R.afterLoad) row = R.afterLoad(row, 'detail', req);
  delete row.password_hash;
  res.json({ ok: true, row, links: R.links ? R.links(row) : [] });
});
adminApi.post('/r/:key', (req, res) => {
  const R = getResource(req);
  if (!R.canCreate) throw new HttpError(405, 'Items cannot be created here.');
  const { data, virt } = collectData(R, req.body || {}, null);
  if (R.beforeSave) R.beforeSave(data, null, virt, req);
  const cols = columnsOf(R.table), t = nowIso();
  if (cols.has('created_at')) data.created_at = t;
  if (cols.has('updated_at')) data.updated_at = t;
  const keys = Object.keys(data).filter((k) => cols.has(k));
  const id = Number(tx(() => {
    const r = q.run(`INSERT INTO ${R.table} (${keys.join(', ')}) VALUES (${keys.map(() => '?').join(', ')})`, ...keys.map((k) => data[k]));
    if (R.afterSave) R.afterSave(Number(r.lastInsertRowid), data, virt, null, req);
    return r.lastInsertRowid;
  }));
  logActivity(req, `Created ${R.singular.toLowerCase()}`, R.key, id, data[R.title] || '');
  res.json({ ok: true, id, message: `${R.singular} created.` });
});
adminApi.put('/r/:key/:id', (req, res) => {
  const R = getResource(req);
  if (!R.canEdit) throw new HttpError(405, 'Items cannot be edited here.');
  const id = parseInt(req.params.id, 10) || 0;
  const old = rawRow(R, id);
  if (!old) throw new HttpError(404, `${R.singular} not found.`);
  const { data, virt } = collectData(R, req.body || {}, old);
  if (R.beforeSave) R.beforeSave(data, old, virt, req);
  const cols = columnsOf(R.table);
  if (cols.has('updated_at')) data.updated_at = nowIso();
  const keys = Object.keys(data).filter((k) => cols.has(k) && k !== 'id');
  tx(() => {
    if (keys.length) q.run(`UPDATE ${R.table} SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE id = ?`, ...keys.map((k) => data[k]), id);
    if (R.afterSave) R.afterSave(id, data, virt, old, req);
  });
  const changed = keys.filter((k) => k !== 'updated_at');
  logActivity(req, `Updated ${R.singular.toLowerCase()}`, R.key, id, `${old[R.title] || ''}${changed.length <= 4 ? ' — ' + changed.map((k) => (k === 'status' ? `status: ${data.status}` : k)).join(', ') : ''}`);
  if (R.key === 'courses' || R.key === 'services') loadSettings();
  res.json({ ok: true, id, message: `${R.singular} saved.` });
});
adminApi.delete('/r/:key/:id', (req, res) => {
  const R = getResource(req);
  if (!R.canDelete) throw new HttpError(405, 'Items cannot be deleted here.');
  const id = parseInt(req.params.id, 10) || 0;
  const row = rawRow(R, id);
  if (!row) throw new HttpError(404, `${R.singular} not found.`);
  if (R.beforeDelete) R.beforeDelete(row, req);
  q.run(`DELETE FROM ${R.table} WHERE id = ?`, id);
  if (R.onDelete) R.onDelete(row);
  logActivity(req, `Deleted ${R.singular.toLowerCase()}`, R.key, id, row[R.title] || '');
  res.json({ ok: true, message: `${R.singular} deleted.` });
});

function toCsv(rows, cols) {
  const cell = (v) => {
    let s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // spreadsheet formula-injection guard
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return '﻿' + [cols.map((c) => cell(c.label)).join(','), ...rows.map((r) => cols.map((c) => cell(r[c.name])).join(','))].join('\r\n');
}
adminApi.get('/export/:key', (req, res) => {
  const R = getResource(req);
  if (!R.exportable) throw new HttpError(405, 'This section cannot be exported.');
  const { where, params } = buildListQuery(R, req.query);
  const rows = q.all(`SELECT ${R.select || 't.*'} FROM ${R.from || R.table + ' t'} ${where} ORDER BY ${R.sort} LIMIT 20000`, ...params).map((r) => {
    if (R.afterLoad) r = R.afterLoad(r, 'export', null);
    if (Array.isArray(r.documents)) r.documents = r.documents.map((d) => d.name).join('; ');
    return r;
  });
  const cols = [{ name: 'id', label: 'ID' }, ...R.fields.filter((f) => f.type !== 'html' && f.type !== 'password' && f.type !== 'image').map((f) => ({ name: f.name, label: f.label }))];
  logActivity(req, `Exported ${R.label} (${rows.length} records)`, R.key, null, where ? 'filtered' : 'all');
  res.set('Content-Type', 'text/csv; charset=utf-8').set('Content-Disposition', `attachment; filename="sds-${R.key}-${today()}.csv"`).send(toCsv(rows, cols));
});

adminApi.get('/settings/:group', (req, res) => {
  const g = SETTINGS_SCHEMA[req.params.group];
  if (!g || (g.adminOnly && req.admin.role !== 'admin')) throw new HttpError(404, 'Unknown settings group.');
  const values = { ...S()[req.params.group] };
  for (const f of g.fields) if (f.type === 'secret') values[f.name] = values[f.name] ? '__SET__' : '';
  res.json({ ok: true, values });
});
adminApi.put('/settings/:group', (req, res) => {
  const key = req.params.group, g = SETTINGS_SCHEMA[key];
  if (!g || (g.adminOnly && req.admin.role !== 'admin')) throw new HttpError(404, 'Unknown settings group.');
  const cur = { ...S()[key] }, errors = {}, b = req.body || {};
  for (const f of g.fields) {
    if (!(f.name in b)) continue;
    if (f.type === 'secret') { if (b[f.name] && b[f.name] !== '__SET__') cur[f.name] = encrypt(String(b[f.name]).slice(0, 300)); else if (b[f.name] === '') cur[f.name] = ''; continue; }
    if (f.type === 'color') { const v = String(b[f.name] || ''); if (/^#[0-9a-f]{3,8}$/i.test(v)) cur[f.name] = v; else errors[f.name] = 'Choose a valid colour.'; continue; }
    const v = coerceField(f.type === 'lines' ? { ...f, max: 20000 } : f, b[f.name], errors);
    cur[f.name] = f.type === 'number' || f.type === 'money' ? (v ?? 0) : v ?? '';
  }
  if (key === 'seo' && cur.base_url) cur.base_url = String(cur.base_url).replace(/\/+$/, '');
  if (Object.keys(errors).length) throw new HttpError(422, 'Please correct the highlighted fields.', errors);
  saveSettingGroup(key, cur);
  logActivity(req, `Updated settings: ${g.label}`, 'settings', key);
  res.json({ ok: true, message: `${g.label} settings saved.` });
});
adminApi.get('/home', (req, res) => res.json({ ok: true, values: HOME }));
adminApi.put('/home/:section', (req, res) => {
  const sec = req.params.section, schema = HOME_SCHEMA[sec];
  if (!schema) throw new HttpError(404, 'Unknown homepage section.');
  const errors = {}, cur = { ...HOME[sec] }, b = req.body || {};
  for (const f of schema.fields) if (f.name in b) cur[f.name] = coerceField(f.type === 'lines' || f.type === 'textarea' ? { ...f, max: 5000 } : { ...f, max: 500 }, b[f.name], errors) ?? '';
  if (Object.keys(errors).length) throw new HttpError(422, 'Please correct the highlighted fields.', errors);
  const stored = (() => { try { return JSON.parse(q.val('SELECT value FROM settings WHERE key = ?', 'home') || '{}'); } catch { return {}; } })();
  stored[sec] = cur;
  saveSettingGroup('home', stored);
  logActivity(req, `Updated homepage: ${schema.label}`, 'homepage', sec);
  res.json({ ok: true, message: `${schema.label} saved.` });
});

adminApi.post('/upload', (req, res, next) => {
  memUpload.single('file')(req, res, (err) => {
    if (err) return next(err);
    try {
      if (!req.file) throw new HttpError(422, 'Please choose a file to upload.');
      const kind = req.body?.kind === 'document' ? 'document' : 'image';
      const stored = kind === 'document'
        ? storeFile(req.file, { allowed: ['pdf'], dir: 'documents', maxBytes: MAX_DOC_BYTES })
        : storeFile(req.file, { allowed: req.body?.purpose === 'favicon' ? [...IMAGE_TYPES, 'ico'] : IMAGE_TYPES, dir: 'images', maxBytes: MAX_IMAGE_BYTES });
      logActivity(req, `Uploaded ${kind}`, 'media', stored.file, stored.original);
      res.json({ ok: true, url: stored.url, name: stored.original, size: stored.size });
    } catch (e) { next(e); }
  });
});
adminApi.get('/media', (req, res) => {
  const out = [];
  for (const dir of ['images', 'documents']) {
    for (const file of fs.readdirSync(DIRS[dir])) {
      if (file.startsWith('.')) continue;
      const st = fs.statSync(path.join(DIRS[dir], file));
      out.push({ dir, file, url: `/uploads/${dir}/${file}`, size: st.size, modified: st.mtime.toISOString() });
    }
  }
  out.sort((a, b) => b.modified.localeCompare(a.modified));
  res.json({ ok: true, files: out });
});
adminApi.delete('/media/:dir/:file', (req, res) => {
  const { dir, file } = req.params;
  if (!['images', 'documents'].includes(dir) || !/^[a-z0-9-]+\.[a-z]{3,4}$/.test(file)) throw new HttpError(400, 'Invalid file.');
  if (!deleteUploadByUrl(`/uploads/${dir}/${file}`)) throw new HttpError(404, 'File not found.');
  logActivity(req, 'Deleted uploaded file', 'media', file);
  res.json({ ok: true, message: 'File deleted.' });
});

function newCertificateId(courseName) {
  const prefix = (S().certificate.prefix || 'SDS').replace(/[^A-Z0-9]/gi, '').toUpperCase().slice(0, 8) || 'SDS';
  const code = String(courseName || 'Course').split(/\s+/).filter(Boolean).map((w) => w[0]).join('').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 4) || 'C';
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  for (;;) {
    const rand = Array.from(crypto.randomBytes(6), (b) => alphabet[b % alphabet.length]).join('');
    const id = `${prefix}-${code}-${new Date().getFullYear()}-${rand}`;
    if (!q.get('SELECT id FROM certificates WHERE certificate_id = ?', id)) return id;
  }
}
adminApi.get('/certificates/eligible', (req, res) => {
  res.json({ ok: true, rows: q.all(`SELECT e.id, e.ref, e.status, e.completion_date, e.certificate_eligible, s.full_name, s.father_name, s.phone, c.name AS course_name
    FROM enrollments e JOIN students s ON s.id = e.student_id JOIN courses c ON c.id = e.course_id
    WHERE (e.status = 'completed' OR e.certificate_eligible = 1) AND NOT EXISTS (SELECT 1 FROM certificates x WHERE x.enrollment_id = e.id AND x.status = 'valid')
    ORDER BY e.completion_date DESC, e.id DESC LIMIT 500`) });
});
adminApi.post('/certificates/generate', (req, res) => {
  const b = req.body || {}, created = [], t = nowIso();
  if (b.manual) {
    const m = b.manual;
    requireFields(m, { student_name: 'Student name', course_name: 'Course name', completion_date: 'Completion date' });
    if (!V.date(m.completion_date)) throw new HttpError(422, 'Invalid date.', { completion_date: 'Choose a valid date.' });
    const cid = newCertificateId(m.course_name);
    q.run('INSERT INTO certificates (certificate_id, student_name, father_name, course_name, completion_date, grade, status, issued_by, issued_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      cid, cleanText(m.student_name, 100), cleanText(m.father_name, 100), cleanText(m.course_name, 120), m.completion_date, cleanText(m.grade, 20), 'valid', req.admin.name, t, t, t);
    created.push(cid);
  } else {
    const ids = (Array.isArray(b.enrollment_ids) ? b.enrollment_ids : []).map((x) => parseInt(x, 10)).filter(Boolean).slice(0, 200);
    if (!ids.length) throw new HttpError(422, 'Select at least one eligible student.');
    tx(() => {
      for (const id of ids) {
        const e = q.get('SELECT e.*, s.full_name, s.father_name, c.name AS course_name FROM enrollments e JOIN students s ON s.id = e.student_id JOIN courses c ON c.id = e.course_id WHERE e.id = ?', id);
        if (!e || !(e.status === 'completed' || e.certificate_eligible)) continue;
        if (q.get("SELECT id FROM certificates WHERE enrollment_id = ? AND status = 'valid'", id)) continue;
        const cid = newCertificateId(e.course_name);
        const done = e.completion_date || today();
        q.run('INSERT INTO certificates (certificate_id, student_id, enrollment_id, student_name, father_name, course_name, completion_date, grade, status, issued_by, issued_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
          cid, e.student_id, e.id, e.full_name, e.father_name, e.course_name, done, cleanText(b.grade, 20) || null, 'valid', req.admin.name, t, t, t);
        q.run("UPDATE enrollments SET status = 'completed', completion_date = COALESCE(completion_date, ?), certificate_eligible = 1, updated_at = ? WHERE id = ?", done, t, id);
        created.push(cid);
      }
    });
  }
  if (!created.length) throw new HttpError(422, 'No certificates were generated. The selected students may already have valid certificates.');
  logActivity(req, `Generated ${created.length} certificate(s)`, 'certificates', null, created.join(', '));
  res.json({ ok: true, created, message: `${created.length} certificate(s) generated.` });
});
adminApi.post('/certificates/:id/revoke', (req, res) => {
  const cert = q.get('SELECT * FROM certificates WHERE id = ?', parseInt(req.params.id, 10) || 0);
  if (!cert) throw new HttpError(404, 'Certificate not found.');
  q.run("UPDATE certificates SET status = 'revoked', revoke_reason = ?, revoked_at = ?, updated_at = ? WHERE id = ?", cleanText(req.body?.reason, 300) || 'Revoked by administrator', nowIso(), nowIso(), cert.id);
  logActivity(req, 'Revoked certificate', 'certificates', cert.id, `${cert.certificate_id} — ${cleanText(req.body?.reason, 200)}`);
  res.json({ ok: true, message: `Certificate ${cert.certificate_id} revoked.` });
});
adminApi.post('/certificates/:id/restore', (req, res) => {
  const cert = q.get('SELECT * FROM certificates WHERE id = ?', parseInt(req.params.id, 10) || 0);
  if (!cert) throw new HttpError(404, 'Certificate not found.');
  q.run("UPDATE certificates SET status = 'valid', revoke_reason = NULL, revoked_at = NULL, updated_at = ? WHERE id = ?", nowIso(), cert.id);
  logActivity(req, 'Restored certificate', 'certificates', cert.id, cert.certificate_id);
  res.json({ ok: true, message: `Certificate ${cert.certificate_id} restored.` });
});
adminApi.get('/certificates/lookup', (req, res) => {
  const id = cleanText(req.query.id, 40).toUpperCase();
  const cert = q.get('SELECT * FROM certificates WHERE certificate_id = ?', id);
  res.json({ ok: true, cert: cert || null, history: q.all('SELECT result, checked_at FROM certificate_verifications WHERE certificate_id = ? ORDER BY id DESC LIMIT 20', id) });
});

adminApi.get('/quotations/:id/items', (req, res) => {
  const qt = q.get('SELECT * FROM quotations WHERE id = ?', parseInt(req.params.id, 10) || 0);
  if (!qt) throw new HttpError(404, 'Quotation not found.');
  res.json({ ok: true, quotation: { id: qt.id, number: qt.number, access_token: qt.access_token }, items: q.all('SELECT * FROM quotation_items WHERE quotation_id = ? ORDER BY id', qt.id), products: q.all('SELECT id, name, sku, price, installable FROM products ORDER BY name') });
});
adminApi.put('/quotations/:id/items', (req, res) => {
  const qt = q.get('SELECT * FROM quotations WHERE id = ?', parseInt(req.params.id, 10) || 0);
  if (!qt) throw new HttpError(404, 'Quotation not found.');
  const raw = Array.isArray(req.body?.items) ? req.body.items.slice(0, 100) : [];
  const items = raw.map((it) => {
    const p = it.product_id ? q.get('SELECT * FROM products WHERE id = ?', parseInt(it.product_id, 10)) : null;
    const name = cleanText(it.product_name || p?.name, 150);
    const price = Math.max(0, Number(it.unit_price ?? p?.price) || 0), qty = Math.min(9999, Math.max(1, parseInt(it.quantity, 10) || 1));
    return name ? { product_id: p?.id || null, product_name: name, sku: p?.sku || cleanText(it.sku, 40), unit_price: price, quantity: qty, installable: p ? p.installable : (it.installable ? 1 : 0) } : null;
  }).filter(Boolean);
  if (!items.length) throw new HttpError(422, 'A quotation needs at least one item.');
  const subtotal = items.reduce((s, i) => s + i.unit_price * i.quantity, 0);
  let installation = qt.installation_charge;
  if (req.body?.recalculate_charges) {
    const tot = computeTotals(items, { include_installation: !!qt.include_installation || qt.installation_charge > 0, include_delivery: !!qt.include_delivery });
    installation = tot.installation;
    qt.delivery_charge = tot.delivery; qt.discount = tot.discount;
  }
  const total = Math.max(0, subtotal + installation + qt.delivery_charge - qt.discount);
  tx(() => {
    q.run('DELETE FROM quotation_items WHERE quotation_id = ?', qt.id);
    for (const it of items) q.run('INSERT INTO quotation_items (quotation_id, product_id, product_name, sku, unit_price, quantity, line_total, installable) VALUES (?,?,?,?,?,?,?,?)', qt.id, it.product_id, it.product_name, it.sku, it.unit_price, it.quantity, it.unit_price * it.quantity, it.installable);
    q.run('UPDATE quotations SET subtotal = ?, installation_charge = ?, delivery_charge = ?, discount = ?, total = ?, updated_at = ? WHERE id = ?', subtotal, installation, qt.delivery_charge, qt.discount, total, nowIso(), qt.id);
  });
  logActivity(req, 'Updated quotation items', 'quotations', qt.id, `${qt.number} — ${money(total)}`);
  res.json({ ok: true, message: 'Quotation items saved.', total });
});

adminApi.post('/account/password', (req, res) => {
  const user = q.get('SELECT * FROM admin_users WHERE id = ?', req.admin.id);
  const b = req.body || {};
  if (!verifyPassword(b.current || '', user.password_hash)) throw new HttpError(422, 'Current password is incorrect.', { current: 'Incorrect password.' });
  if (String(b.password || '').length < 10) throw new HttpError(422, 'Password too short.', { password: 'Use at least 10 characters.' });
  if (b.password !== b.confirm) throw new HttpError(422, 'Passwords do not match.', { confirm: 'Passwords do not match.' });
  q.run('UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?', hashPassword(b.password), nowIso(), user.id);
  q.run('DELETE FROM sessions WHERE admin_id = ? AND id != ?', user.id, req.admin.sessionId);
  logActivity(req, 'Changed own password', 'auth', user.id);
  res.json({ ok: true, message: 'Password changed. Other sessions have been signed out.' });
});
adminApi.post('/smtp/test', adminOnly, async (req, res) => {
  if (!S().smtp.enabled || !S().smtp.host) throw new HttpError(422, 'Enable SMTP and save the settings first.');
  const ok = await sendMail({ subject: '[SDS] Test email', text: `This is a test email from the ${S().general.site_name} admin dashboard.`, to: req.admin.email });
  if (!ok) throw new HttpError(502, 'Sending failed. Check the SMTP settings and the server log.');
  res.json({ ok: true, message: `Test email sent to ${req.admin.email}.` });
});
app.use('/admin/api', adminApi);

app.get('/admin/files/scheme/:id/:file', requireAdmin, (req, res, next) => {
  if (req.admin.role !== 'admin') return res.status(403).send('Forbidden');
  const row = q.get('SELECT id, ref, documents FROM scheme_submissions WHERE id = ?', parseInt(req.params.id, 10) || 0);
  if (!row) return next();
  let docs = [];
  try { docs = JSON.parse(row.documents || '[]'); } catch { /* ignore */ }
  const doc = docs.find((d) => d.file === req.params.file);
  if (!doc) return next();
  logActivity(req, 'Downloaded scheme document', 'scheme', row.id, `${row.ref} — ${doc.original || doc.file}`);
  res.set('Content-Type', doc.mime || 'application/octet-stream').set('X-Content-Type-Options', 'nosniff').set('Cache-Control', 'private, no-store')
    .set('Content-Disposition', `${doc.mime === 'application/pdf' || /^image\//.test(doc.mime) ? 'inline' : 'attachment'}; filename="${String(doc.original || doc.file).replace(/[^\w.-]+/g, '_')}"`)
    .sendFile(path.join(DIRS.private, path.basename(doc.file)));
});

function adminShell(req, { title, body, bodyClass = '' }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)} · ${esc(S().general.site_name)} Admin</title>
<meta name="robots" content="noindex, nofollow"><meta name="csrf-token" content="${req.csrfToken}"><link rel="icon" href="${esc(S().general.favicon || '/favicon.svg')}">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@700;800&display=swap">
<link rel="stylesheet" href="/assets/admin.css?v=${ASSET_VERSION}"></head><body class="${bodyClass}">${body}<script src="/assets/admin.js?v=${ASSET_VERSION}" defer></script></body></html>`;
}
function authCard(inner) {
  return `<div class="auth"><div class="auth-card"><div class="auth-brand">${brand()}</div>${inner}</div><p class="auth-foot"><a href="/">← Back to website</a></p></div>`;
}
app.get('/admin/login', (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (loadSession(req)) return res.redirect('/admin');
  if (!adminCount()) return res.redirect('/admin/setup');
  res.send(adminShell(req, { title: 'Sign in', bodyClass: 'auth-page', body: authCard(`<h1>Admin sign in</h1><p class="muted">Sign in to manage your website.</p>
    <form id="loginForm" class="stack" novalidate><div class="form-status"></div><input type="hidden" name="next" value="${esc(String(req.query.next || '/admin').slice(0, 200))}">
    <label class="fld"><span>Email</span><input type="email" name="email" required autocomplete="username" maxlength="190" autofocus></label>
    <label class="fld"><span>Password</span><input type="password" name="password" required autocomplete="current-password" maxlength="200"></label>
    <button class="btn btn-primary btn-block" type="submit">Sign in</button></form>
    <p class="muted small" style="margin-top:18px">${icon('lock')} Protected area. Sessions expire after ${Math.round(SESSION_IDLE_MS / 60000)} minutes of inactivity.</p>`) }));
});
app.get('/admin/setup', (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (adminCount()) return res.redirect('/admin/login');
  res.send(adminShell(req, { title: 'First-run setup', bodyClass: 'auth-page', body: authCard(`<h1>Create the first admin</h1><p class="muted">Enter the one-time setup token shown in the server console (also saved in <code>data/setup-token.txt</code>).</p>
    <form id="setupForm" class="stack" novalidate><div class="form-status"></div>
    <label class="fld"><span>Setup token</span><input type="text" name="token" required autocomplete="off" maxlength="64"></label>
    <label class="fld"><span>Your name</span><input type="text" name="name" required maxlength="100"></label>
    <label class="fld"><span>Email (login)</span><input type="email" name="email" required autocomplete="username" maxlength="190"></label>
    <label class="fld"><span>Password (min. 10 characters)</span><input type="password" name="password" required minlength="10" autocomplete="new-password"></label>
    <label class="fld"><span>Confirm password</span><input type="password" name="confirm" required minlength="10" autocomplete="new-password"></label>
    <button class="btn btn-primary btn-block" type="submit">Create admin account</button></form>`) }));
});
app.get('/admin', requireAdmin, (req, res) => {
  res.send(adminShell(req, { title: 'Dashboard', body: `<div class="app" id="app"><aside class="side" id="side"><div class="side-brand">${brand()}</div><nav id="sideNav" aria-label="Admin navigation"></nav></aside>
    <div class="main"><header class="top"><button class="icon-btn menu-btn" id="menuBtn" type="button" aria-label="Toggle menu">${icon('menu')}</button><div class="crumb" id="crumb"></div>
      <div class="top-actions"><a class="icon-btn" href="/" target="_blank" rel="noopener" title="View website">${icon('external')}</a><button class="icon-btn" id="themeBtn" type="button" title="Toggle dark mode">${icon('moon', 'i-moon')}${icon('sun', 'i-sun')}</button>
      <div class="user"><span class="av">${esc(initials(req.admin.name))}</span><span class="who"><strong>${esc(req.admin.name)}</strong><small>${esc(req.admin.role)}</small></span></div>
      <button class="icon-btn" id="logoutBtn" type="button" title="Sign out">${icon('logout')}</button></div></header>
      <main class="content" id="view"><div class="loading">Loading…</div></main></div></div>
    <div class="toasts" id="toasts" aria-live="polite"></div><div class="modal-root" id="modalRoot"></div>
    <template id="icons">${Object.keys(ICONS).map((k) => `<span data-icon="${k}">${icon(k)}</span>`).join('')}</template>` }));
});
app.get('/admin/*splat', requireAdmin, (req, res) => res.redirect('/admin'));

/* ===================== 14. CLIENT JAVASCRIPT (served as static assets) ===================== */
/* These functions are never executed on the server — they are serialised with .toString()
   and served as /assets/site.js and /assets/admin.js. */
function siteClient() {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

  const header = $('.site-header');
  const onScroll = () => header && header.classList.toggle('scrolled', window.scrollY > 8);
  window.addEventListener('scroll', onScroll, { passive: true }); onScroll();
  const toggle = $('.nav-toggle');
  if (toggle) toggle.addEventListener('click', () => {
    const open = document.body.classList.toggle('menu-open');
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  });
  $$('.main-nav a').forEach((a) => a.addEventListener('click', () => document.body.classList.remove('menu-open')));
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') document.body.classList.remove('menu-open'); });

  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver((entries) => entries.forEach((en) => { if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); } }), { rootMargin: '0px 0px -40px 0px', threshold: 0.06 });
    $$('.reveal').forEach((el) => io.observe(el));
  } else $$('.reveal').forEach((el) => el.classList.add('in'));

  function toast(msg, err) {
    const w = $('#toasts');
    if (!w) return;
    const t = document.createElement('div');
    t.className = 'toast' + (err ? ' err' : '');
    t.textContent = msg;
    w.appendChild(t);
    setTimeout(() => t.remove(), 4200);
  }
  $$('[data-print]').forEach((b) => b.addEventListener('click', () => window.print()));
  $$('[data-copy]').forEach((b) => b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy); toast('Link copied to clipboard'); } catch { window.prompt('Copy this link:', b.dataset.copy); }
  }));
  $$('[data-cnic]').forEach((i) => i.addEventListener('input', () => {
    const d = i.value.replace(/\D/g, '').slice(0, 13);
    let v = d.slice(0, 5);
    if (d.length > 5) v += '-' + d.slice(5, 12);
    if (d.length > 12) v += '-' + d.slice(12);
    i.value = v;
  }));

  /* ---- Quotation cart (stored in this browser only) ---- */
  const CART_KEY = 'sds_quote_cart_v1';
  const readCart = () => { try { const c = JSON.parse(localStorage.getItem(CART_KEY) || '{}'); return c && typeof c === 'object' ? c : {}; } catch { return {}; } };
  const writeCart = (c) => { try { localStorage.setItem(CART_KEY, JSON.stringify(c)); } catch { /* storage unavailable */ } updateBadge(); };
  function updateBadge() {
    const n = Object.values(readCart()).reduce((s, i) => s + (i.qty || 0), 0);
    $$('[data-cart-count]').forEach((el) => { el.textContent = String(n); el.hidden = !n; });
    $$('[data-cart-count-label]').forEach((el) => { el.textContent = n + (n === 1 ? ' item' : ' items'); });
  }
  const panel = $('#quote');
  let cfg = null, catalog = {};
  if (panel) {
    try { cfg = JSON.parse(panel.dataset.cfg); } catch { cfg = null; }
    try { JSON.parse(($('#productData') || {}).textContent || '[]').forEach((p) => { catalog[p.id] = p; }); } catch { catalog = {}; }
    const c = readCart();
    let changed = false;
    for (const id of Object.keys(c)) {
      const p = catalog[id];
      if (!p || p.out) { delete c[id]; changed = true; } else { c[id] = { ...c[id], name: p.name, price: p.price, installable: p.installable, unit: p.unit }; }
    }
    if (changed) writeCart(c); else updateBadge();
  } else updateBadge();
  const fmt = (n) => { const s = Math.round(n || 0).toLocaleString('en-PK'); return cfg && cfg.position === 'after' ? `${s} ${cfg.symbol}` : `${cfg ? cfg.symbol : 'Rs'} ${s}`; };
  const escH = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  function totals(items) {
    const subtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
    const cams = items.reduce((s, i) => s + (i.installable ? i.qty : 0), 0);
    const inst = $('#optInstall') && $('#optInstall').checked && items.length ? cfg.installation_base + cfg.installation_per_camera * cams : 0;
    const del = $('#optDelivery') && $('#optDelivery').checked && items.length ? (cfg.free_delivery_above > 0 && subtotal >= cfg.free_delivery_above ? 0 : cfg.delivery_charge) : 0;
    const disc = cfg.discount_percent > 0 && subtotal >= cfg.discount_threshold ? Math.round(subtotal * cfg.discount_percent / 100) : 0;
    return { subtotal, inst, del, disc, total: Math.max(0, subtotal + inst + del - disc), cams };
  }
  function renderCart() {
    if (!panel || !cfg) return;
    const items = Object.values(readCart());
    const list = $('#cartItems');
    $('#cartEmpty').hidden = items.length > 0;
    list.innerHTML = items.map((i) => `<li data-id="${i.id}"><span class="nm">${escH(i.name)}<br><small class="muted">${fmt(i.price)} / ${escH(i.unit || 'piece')}</small></span><span class="lt">${fmt(i.price * i.qty)}</span>
      <span class="qty"><button type="button" data-act="dec" aria-label="Decrease quantity">−</button><input type="number" min="1" max="999" value="${i.qty}" aria-label="Quantity for ${escH(i.name)}"><button type="button" data-act="inc" aria-label="Increase quantity">+</button></span>
      <button type="button" class="rm" data-act="rm">Remove</button></li>`).join('');
    const t = totals(items);
    $('#totals').innerHTML = `<div><span>Subtotal</span><strong>${fmt(t.subtotal)}</strong></div>
      ${$('#optInstall').checked ? `<div><span>Installation (${t.cams} camera${t.cams === 1 ? '' : 's'})</span><strong>${fmt(t.inst)}</strong></div>` : ''}
      ${$('#optDelivery').checked ? `<div><span>Delivery</span><strong>${t.del ? fmt(t.del) : (items.length ? 'Free' : fmt(0))}</strong></div>` : ''}
      ${t.disc ? `<div><span>Discount</span><strong>− ${fmt(t.disc)}</strong></div>` : ''}
      <div class="grand"><span>Estimated total</span><span>${fmt(t.total)}</span></div>`;
    updateBadge();
  }
  if (panel) {
    $('#cartItems').addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-act]');
      if (!btn) return;
      const id = btn.closest('li').dataset.id, c = readCart();
      if (!c[id]) return;
      if (btn.dataset.act === 'inc') c[id].qty = Math.min(999, c[id].qty + 1);
      if (btn.dataset.act === 'dec') c[id].qty = Math.max(1, c[id].qty - 1);
      if (btn.dataset.act === 'rm') delete c[id];
      writeCart(c); renderCart();
    });
    $('#cartItems').addEventListener('change', (e) => {
      if (e.target.tagName !== 'INPUT') return;
      const id = e.target.closest('li').dataset.id, c = readCart();
      if (c[id]) { c[id].qty = Math.min(999, Math.max(1, parseInt(e.target.value, 10) || 1)); writeCart(c); renderCart(); }
    });
    ['#optInstall', '#optDelivery'].forEach((s) => $(s).addEventListener('change', renderCart));
    renderCart();
  }
  $$('[data-add]').forEach((btn) => btn.addEventListener('click', () => {
    let p;
    try { p = JSON.parse(btn.dataset.add); } catch { return; }
    const c = readCart();
    c[p.id] = { ...p, qty: Math.min(999, ((c[p.id] && c[p.id].qty) || 0) + 1) };
    writeCart(c); renderCart();
    if (!btn.dataset.orig) btn.dataset.orig = btn.innerHTML;
    clearTimeout(btn._t);
    btn.classList.add('added'); btn.textContent = 'Added ✓';
    btn._t = setTimeout(() => { btn.classList.remove('added'); btn.innerHTML = btn.dataset.orig; }, 1300);
    toast(`${p.name} added to your quotation`);
  }));
  $$('.cat-tabs [data-filter]').forEach((b) => b.addEventListener('click', () => {
    $$('.cat-tabs [data-filter]').forEach((x) => x.classList.toggle('active', x === b));
    $$('#productGrid .product-card').forEach((card) => { card.style.display = b.dataset.filter === 'all' || card.dataset.cat === b.dataset.filter ? '' : 'none'; card.classList.add('in'); });
  }));

  /* ---- AJAX forms ---- */
  function setStatus(form, type, msg) {
    const box = form.querySelector('.form-status');
    if (!box) return toast(msg, type !== 'ok');
    box.innerHTML = '';
    if (!msg) return;
    const d = document.createElement('div');
    d.className = 'alert ' + (type === 'ok' ? 'alert-ok' : 'alert-err');
    d.setAttribute('role', type === 'ok' ? 'status' : 'alert');
    d.textContent = msg;
    box.appendChild(d);
    box.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  function clearErrors(form) { $$('.field.invalid', form).forEach((f) => f.classList.remove('invalid')); $$('.err', form).forEach((e) => e.remove()); }
  function fieldError(form, name, msg) {
    const input = form.querySelector(`[name="${name}"]`);
    if (!input) return;
    const wrap = input.closest('.field') || input.closest('.consent') || input.parentElement;
    wrap.classList.add('invalid');
    const p = document.createElement('p'); p.className = 'err'; p.textContent = msg;
    wrap.appendChild(p);
  }
  $$('form.ajax-form').forEach((form) => form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearErrors(form); setStatus(form, 'ok', '');
    const invalid = $$('input, select, textarea', form).filter((el) => el.name && el.name !== 'website' && !el.checkValidity());
    if (invalid.length) {
      invalid.forEach((el) => fieldError(form, el.name, el.type === 'checkbox' ? 'Please tick this box to continue.' : el.validity.valueMissing ? 'This field is required.' : el.validationMessage));
      invalid[0].focus();
      return;
    }
    const headers = { 'X-CSRF-Token': csrf(), Accept: 'application/json' };
    let body;
    if (form.dataset.multipart) {
      body = new FormData(form);
      const files = form.querySelector('input[type=file]');
      if (files && files.files.length > 3) return setStatus(form, 'err', 'You can upload up to 3 files.');
      if (files) for (const f of files.files) if (f.size > 5 * 1024 * 1024) return setStatus(form, 'err', `"${f.name}" is larger than 5 MB.`);
    } else {
      const data = Object.fromEntries(new FormData(form));
      if (form.dataset.quote) {
        data.items = Object.values(readCart()).map((i) => ({ id: i.id, qty: i.qty }));
        data.include_installation = !!($('#optInstall') && $('#optInstall').checked);
        data.include_delivery = !!($('#optDelivery') && $('#optDelivery').checked);
        if (!data.items.length) return setStatus(form, 'err', 'Your quotation is empty. Add at least one product first.');
      }
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(data);
    }
    const btn = form.querySelector('[type=submit]');
    const orig = btn ? btn.innerHTML : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Please wait…'; }
    try {
      const r = await fetch(form.dataset.endpoint, { method: 'POST', headers, body, credentials: 'same-origin' });
      const j = await r.json().catch(() => ({ ok: false, error: 'Unexpected response from the server. Please try again.' }));
      if (j.ok) {
        if (form.dataset.quote) writeCart({});
        if (j.redirect) { window.location.href = j.redirect; return; }
        form.reset();
        setStatus(form, 'ok', j.message || 'Thank you! Submitted successfully.');
      } else {
        if (j.fields) Object.entries(j.fields).forEach(([k, v]) => fieldError(form, k, v));
        setStatus(form, 'err', j.error || 'Something went wrong. Please try again.');
      }
    } catch {
      setStatus(form, 'err', 'Network error — please check your internet connection and try again.');
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = orig; }
    }
  }));
}

function adminClient() {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  const h = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const ic = (name) => { const t = $('#icons'); const el = t && t.content.querySelector(`[data-icon="${name}"]`); return el ? el.innerHTML : ''; };

  /* theme */
  const applyTheme = (t) => { document.documentElement.dataset.theme = t; try { localStorage.setItem('sds_admin_theme', t); } catch { /* ignore */ } };
  let theme = 'light';
  try { theme = localStorage.getItem('sds_admin_theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); } catch { /* ignore */ }
  applyTheme(theme);

  async function api(method, url, body, isForm) {
    const opts = { method, headers: { 'X-CSRF-Token': csrf(), Accept: 'application/json' }, credentials: 'same-origin' };
    if (body !== undefined) { if (isForm) opts.body = body; else { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); } }
    const r = await fetch(url, opts);
    if (r.status === 401 && !url.includes('/login') && !url.includes('/setup')) { window.location.href = '/admin/login?next=' + encodeURIComponent('/admin' + window.location.hash); throw new Error('Session expired'); }
    const j = await r.json().catch(() => ({ ok: false, error: `Unexpected server response (${r.status}).` }));
    if (!j.ok) { const e = new Error(j.error || 'Request failed.'); e.fields = j.fields; throw e; }
    return j;
  }
  function toast(msg, type = 'ok') {
    const w = $('#toasts') || document.body;
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    w.appendChild(t);
    setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, 3800);
  }
  function modal({ title, body, confirmText = 'Confirm', danger = false, cancelText = 'Cancel', input = null }) {
    return new Promise((resolve) => {
      const root = $('#modalRoot') || document.body;
      const m = document.createElement('div');
      m.className = 'modal';
      m.innerHTML = `<div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="mt"><h3 id="mt">${h(title)}</h3><div class="modal-body">${body || ''}</div>
        ${input ? `<label class="fld"><span>${h(input.label)}</span><input type="text" class="modal-input" maxlength="300" placeholder="${h(input.placeholder || '')}"></label>` : ''}
        <div class="modal-actions"><button class="btn btn-ghost" data-r="0" type="button">${h(cancelText)}</button><button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-r="1" type="button">${h(confirmText)}</button></div></div>`;
      root.appendChild(m);
      const close = (v) => { m.remove(); document.removeEventListener('keydown', onKey); resolve(v); };
      const onKey = (e) => { if (e.key === 'Escape') close(false); };
      document.addEventListener('keydown', onKey);
      m.addEventListener('click', (e) => {
        if (e.target === m) return close(false);
        const b = e.target.closest('[data-r]');
        if (b) close(b.dataset.r === '1' ? (input ? ($('.modal-input', m).value || '').trim() || true : true) : false);
      });
      ($('.modal-input', m) || $('[data-r="1"]', m)).focus();
    });
  }
  const confirmDelete = (what) => modal({ title: 'Delete permanently?', body: `<p>This will permanently delete <strong>${h(what)}</strong>. This cannot be undone.</p>`, confirmText: 'Delete', danger: true });
  function showFieldErrors(form, fields) {
    $$('.fld.invalid', form).forEach((f) => f.classList.remove('invalid'));
    $$('.fld .err', form).forEach((e) => e.remove());
    if (!fields) return;
    let first = null;
    for (const [k, v] of Object.entries(fields)) {
      const el = form.querySelector(`[data-field="${k}"]`) || form.querySelector(`[name="${k}"]`);
      const wrap = el && (el.closest('.fld') || el);
      if (!wrap) continue;
      wrap.classList.add('invalid');
      const p = document.createElement('p'); p.className = 'err'; p.textContent = v; wrap.appendChild(p);
      first = first || wrap;
    }
    if (first) first.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  /* ---------- login / setup pages ---------- */
  const authForm = $('#loginForm') || $('#setupForm');
  if (authForm) {
    authForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = authForm.querySelector('[type=submit]'), status = authForm.querySelector('.form-status');
      status.innerHTML = '';
      btn.disabled = true;
      try {
        const j = await api('POST', authForm.id === 'loginForm' ? '/admin/api/login' : '/admin/api/setup', Object.fromEntries(new FormData(authForm)));
        window.location.href = j.redirect || '/admin';
      } catch (err) {
        const d = document.createElement('div'); d.className = 'alert alert-err'; d.textContent = err.message; status.appendChild(d);
        showFieldErrors(authForm, err.fields);
        btn.disabled = false;
      }
    });
    return;
  }
  if (!$('#app')) return;

  /* ---------- app shell ---------- */
  let META = null;
  const view = $('#view');
  const R = (key) => META.resources.find((r) => r.key === key);
  $('#themeBtn').addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  $('#menuBtn').addEventListener('click', () => document.body.classList.toggle('side-open'));
  $('#logoutBtn').addEventListener('click', async () => { const j = await api('POST', '/admin/api/logout', {}); window.location.href = j.redirect; });
  document.addEventListener('click', (e) => { if (document.body.classList.contains('side-open') && !e.target.closest('#side') && !e.target.closest('#menuBtn')) document.body.classList.remove('side-open'); });

  function renderNav() {
    const res = (key) => { const r = R(key); return r ? [r.icon, r.label, `#/r/${key}`, r.badge] : null; };
    const groups = [
      ['Overview', [['dashboard', 'Dashboard', '#/dashboard']]],
      ['Website', [['home', 'Homepage content', '#/home'], res('team'), res('services'), res('testimonials'), ['image', 'Media library', '#/media']]],
      ['Blog', [res('posts'), res('blog_categories'), res('blog_tags'), res('comments')]],
      ['Course', [res('courses'), res('enrollments'), res('students'), res('certificates'), ['award', 'Generate certificates', '#/certificates/generate']]],
      ['CCTV', [res('products'), res('product_categories'), res('quotations'), res('service_requests')]],
      ['Apna Ghar Apni Chat', [res('scheme')]],
      ['Inbox', [res('contacts')]],
      ['Settings', Object.entries(META.settings).map(([k, g]) => [g.icon, g.label, `#/settings/${k}`])],
      ['System', [res('admins'), res('activity'), ['user', 'My account', '#/account']]],
    ];
    const cur = window.location.hash || '#/dashboard';
    $('#sideNav').innerHTML = groups.map(([g, items]) => {
      const list = items.filter(Boolean);
      if (!list.length) return '';
      return `<div class="nav-group"><p>${h(g)}</p>${list.map(([icn, label, href, badge]) => {
        const active = cur === href || (href !== '#/dashboard' && cur.startsWith(href + '/')) || cur.startsWith(href + '?');
        return `<a href="${href}" class="${active ? 'active' : ''}">${ic(icn)}<span>${h(label)}</span>${badge ? `<em>${badge}</em>` : ''}</a>`;
      }).join('')}</div>`;
    }).join('');
  }
  async function refreshMeta() { META = await api('GET', '/admin/api/meta'); renderNav(); }
  const setCrumb = (parts) => { $('#crumb').innerHTML = parts.map(([l, href]) => (href ? `<a href="${href}">${h(l)}</a>` : `<span>${h(l)}</span>`)).join('<i>/</i>'); document.title = `${parts[parts.length - 1][0]} · ${META.siteName} Admin`; };

  /* ---------- formatting helpers ---------- */
  const fmtMoney = (n) => { const c = META.currency; const s = Math.round(Number(n) || 0).toLocaleString('en-PK'); return c.position === 'after' ? `${s} ${c.symbol}` : `${c.symbol} ${s}`; };
  const fmtDate = (v, withTime) => { if (!v) return '—'; const d = new Date(String(v).length === 10 ? v + 'T00:00:00' : v); if (isNaN(d)) return h(v); return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) + (withTime ? ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }) : ''); };
  const toLocalInput = (iso) => { if (!iso) return ''; const d = new Date(iso); if (isNaN(d)) return ''; const p = (n) => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; };
  const STATUS_TONE = { new: 'blue', pending: 'amber', draft: 'gray', unpaid: 'gray', read: 'indigo', contacted: 'indigo', scheduled: 'indigo', active: 'indigo', sent: 'indigo', partial: 'amber', low_stock: 'amber', on_order: 'indigo',
    replied: 'violet', processed: 'violet', in_progress: 'violet', resolved: 'green', completed: 'green', approved: 'green', valid: 'green', published: 'green', accepted: 'green', paid: 'green', waived: 'green', in_stock: 'green',
    cancelled: 'red', rejected: 'red', revoked: 'red', spam: 'red', out_of_stock: 'red' };
  const optLabel = (f, v) => { const o = (f.options || []).find(([val]) => String(val) === String(v)); return o ? o[1] : v; };
  const badge = (v, label) => `<span class="badge ${STATUS_TONE[v] || 'gray'}">${h(label || String(v || '').replace(/_/g, ' '))}</span>`;
  function cell(f, row) {
    const v = row[f.name];
    if (f.type === 'bool') return v ? `<span class="yes">${ic('check')}</span>` : '<span class="no">—</span>';
    if (f.type === 'image') return v ? `<img class="thumb" src="${h(v)}" alt="" loading="lazy">` : '<span class="thumb empty"></span>';
    if (f.type === 'money') return `<span class="num">${fmtMoney(v)}</span>`;
    if (f.type === 'datetime') return `<span class="nowrap">${fmtDate(v, true)}</span>`;
    if (f.type === 'date') return `<span class="nowrap">${fmtDate(v)}</span>`;
    if (f.type === 'icon') return `<span class="ic-inline">${ic(v)}</span>`;
    if (f.type === 'select' && /status$/.test(f.name)) return v ? badge(v, optLabel(f, v)) : '—';
    if (f.type === 'select') return h(optLabel(f, v) ?? '—');
    if (v === null || v === undefined || v === '') return '<span class="no">—</span>';
    const s = String(v);
    return h(s.length > 70 ? s.slice(0, 68) + '…' : s);
  }

  /* ---------- field inputs ---------- */
  let uid = 0;
  function fieldInput(f, value) {
    const id = `fld_${++uid}`;
    const v = value === null || value === undefined ? (f.default !== undefined && value === undefined ? f.default : '') : value;
    const help = f.help ? `<small class="help">${h(f.help)}</small>` : '';
    const full = f.full || ['html', 'textarea', 'lines', 'image', 'files'].includes(f.type) ? ' full' : '';
    const label = `<label for="${id}">${h(f.label)}${f.required ? ' <b class="req">*</b>' : ''}</label>`;
    if (f.readonly) {
      let shown;
      if (f.type === 'files') shown = Array.isArray(v) && v.length ? `<ul class="files">${v.map((d) => `<li>${ic('file')}<a href="${h(d.url)}" target="_blank" rel="noopener">${h(d.name)}</a> <small>${Math.round((d.size || 0) / 1024)} KB</small></li>`).join('')}</ul>` : '<span class="no">No documents uploaded</span>';
      else if (f.type === 'money') shown = fmtMoney(v);
      else if (f.type === 'datetime') shown = fmtDate(v, true);
      else if (f.type === 'date') shown = fmtDate(v);
      else if (f.type === 'select') shown = v ? badge(v, optLabel(f, v)) : '—';
      else if (f.type === 'bool') shown = v ? 'Yes' : 'No';
      else shown = v === '' || v === null ? '<span class="no">—</span>' : `<span class="pre">${h(v)}</span>`;
      return `<div class="fld ro${full}" data-field="${f.name}"><span class="lbl">${h(f.label)}</span><div class="ro-val">${shown}</div></div>`;
    }
    let input;
    switch (f.type) {
      case 'textarea': case 'lines': input = `<textarea id="${id}" name="${f.name}" rows="${f.type === 'lines' ? 8 : 5}" ${f.max ? `maxlength="${f.max}"` : ''}>${h(v)}</textarea>`; break;
      case 'html': input = `<div class="rte" data-rte><div class="rte-bar">${[['bold', 'B', 'Bold'], ['italic', 'I', 'Italic'], ['underline', 'U', 'Underline'], ['h2', 'H2', 'Heading'], ['h3', 'H3', 'Sub-heading'], ['p', '¶', 'Paragraph'], ['insertUnorderedList', '• List', 'Bullet list'], ['insertOrderedList', '1. List', 'Numbered list'], ['blockquote', '❝', 'Quote'], ['link', 'Link', 'Insert link'], ['unlink', 'Unlink', 'Remove link'], ['image', 'Image', 'Upload image'], ['tip', 'Tip box', 'Insert tip box'], ['note', 'Note box', 'Insert note box'], ['warning', 'Warning', 'Insert warning box'], ['table', 'Table', 'Insert table'], ['hr', '—', 'Divider'], ['removeFormat', 'Clear', 'Clear formatting'], ['source', '</>', 'Edit HTML source']].map(([c, l, t]) => `<button type="button" data-cmd="${c}" title="${t}">${h(l)}</button>`).join('')}</div>
        <div class="rte-area prose" contenteditable="true" spellcheck="true">${v || '<p></p>'}</div><textarea class="rte-src" name="${f.name}" hidden>${h(v)}</textarea></div>`; break;
      case 'bool': input = `<label class="switch"><input id="${id}" type="checkbox" name="${f.name}" ${Number(v) ? 'checked' : ''}><span></span></label>`; break;
      case 'select': case 'icon': input = `<select id="${id}" name="${f.name}"><option value="">— Select —</option>${(f.options || []).map(([val, l]) => `<option value="${h(val)}" ${String(val) === String(v) ? 'selected' : ''}>${h(l)}</option>`).join('')}</select>${f.type === 'icon' ? `<span class="icon-preview">${ic(v)}</span>` : ''}`; break;
      case 'image': input = `<div class="img-field"><div class="img-prev">${v ? `<img src="${h(v)}" alt="">` : `<span>${ic('image')}</span>`}</div><div class="img-ctl"><input id="${id}" type="text" name="${f.name}" value="${h(v)}" placeholder="/uploads/images/… or https://…"><div class="row"><label class="btn btn-sm btn-outline upl">${ic('download')} Upload<input type="file" accept="image/png,image/jpeg,image/webp,image/gif${f.name === 'favicon' ? ',.ico' : ''}" hidden data-purpose="${f.name}"></label><button type="button" class="btn btn-sm btn-ghost" data-clear>Remove</button></div></div></div>`; break;
      case 'datetime': input = `<input id="${id}" type="datetime-local" name="${f.name}" value="${h(toLocalInput(v))}">`; break;
      case 'date': input = `<input id="${id}" type="date" name="${f.name}" value="${h(String(v || '').slice(0, 10))}">`; break;
      case 'number': case 'money': input = `<input id="${id}" type="number" step="${f.int ? 1 : 'any'}" name="${f.name}" value="${h(v)}">`; break;
      case 'password': input = `<input id="${id}" type="password" name="${f.name}" autocomplete="new-password" placeholder="••••••••••">`; break;
      case 'secret': input = `<input id="${id}" type="password" name="${f.name}" autocomplete="new-password" value="${v === '__SET__' ? '__SET__' : ''}" placeholder="${v === '__SET__' ? 'Saved — type to replace' : 'Not set'}">`; break;
      case 'color': input = `<input id="${id}" type="color" name="${f.name}" value="${h(v || '#1d4ed8')}">`; break;
      case 'email': input = `<input id="${id}" type="email" name="${f.name}" value="${h(v)}">`; break;
      case 'files': input = '<span class="no">—</span>'; break;
      default: input = `<input id="${id}" type="text" name="${f.name}" value="${h(v)}" ${f.max ? `maxlength="${f.max}"` : ''}>`;
    }
    return `<div class="fld${full}${f.type === 'bool' ? ' fld-bool' : ''}" data-field="${f.name}">${label}${input}${help}</div>`;
  }
  function readForm(form, fields) {
    const out = {};
    for (const f of fields) {
      if (f.readonly || f.type === 'files') continue;
      const el = form.querySelector(`[name="${f.name}"]`);
      if (!el) continue;
      if (f.type === 'bool') out[f.name] = el.checked ? 1 : 0;
      else if (f.type === 'html') { const area = el.closest('[data-rte]').querySelector('.rte-area'); out[f.name] = area.dataset.mode === 'source' ? el.value : area.innerHTML; }
      else if (f.type === 'datetime') out[f.name] = el.value ? new Date(el.value).toISOString() : '';
      else if (f.type === 'password') { if (el.value) out[f.name] = el.value; }
      else out[f.name] = el.value;
    }
    return out;
  }
  async function uploadFile(file, purpose, kind = 'image') {
    const fd = new FormData();
    fd.append('file', file); fd.append('kind', kind); if (purpose) fd.append('purpose', purpose);
    return api('POST', '/admin/api/upload', fd, true);
  }
  function bindFieldWidgets(form) {
    $$('.img-field', form).forEach((w) => {
      const input = $('input[type=text]', w), prev = $('.img-prev', w);
      const show = () => { prev.innerHTML = input.value ? `<img src="${h(input.value)}" alt="">` : `<span>${ic('image')}</span>`; };
      input.addEventListener('change', show);
      $('[data-clear]', w).addEventListener('click', () => { input.value = ''; show(); });
      $('input[type=file]', w).addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        try { const j = await uploadFile(file, e.target.dataset.purpose); input.value = j.url; show(); toast('Image uploaded'); } catch (err) { toast(err.message, 'err'); }
        e.target.value = '';
      });
    });
    $$('select', form).forEach((s) => { const p = s.parentElement.querySelector('.icon-preview'); if (p) s.addEventListener('change', () => { p.innerHTML = ic(s.value); }); });
    $$('[data-rte]', form).forEach((rte) => {
      const area = $('.rte-area', rte), src = $('.rte-src', rte);
      const sync = () => { if (area.dataset.mode !== 'source') src.value = area.innerHTML; };
      area.addEventListener('input', sync);
      $('.rte-bar', rte).addEventListener('mousedown', (e) => { if (e.target.closest('button')) e.preventDefault(); });
      $('.rte-bar', rte).addEventListener('click', async (e) => {
        const b = e.target.closest('button');
        if (!b) return;
        const cmd = b.dataset.cmd;
        if (cmd === 'source') {
          if (area.dataset.mode === 'source') { area.innerHTML = src.value; area.dataset.mode = ''; src.hidden = true; area.hidden = false; b.classList.remove('on'); }
          else { src.value = area.innerHTML; area.dataset.mode = 'source'; src.hidden = false; area.hidden = true; b.classList.add('on'); }
          return;
        }
        if (area.dataset.mode === 'source') return;
        area.focus();
        if (['h2', 'h3', 'p', 'blockquote'].includes(cmd)) document.execCommand('formatBlock', false, cmd);
        else if (cmd === 'link') { const url = window.prompt('Link URL (https://… or /page):', 'https://'); if (url) document.execCommand('createLink', false, url); }
        else if (['tip', 'note', 'warning'].includes(cmd)) document.execCommand('insertHTML', false, `<p class="${cmd}"><strong>${cmd === 'tip' ? 'Tip' : cmd === 'note' ? 'Note' : 'Warning'}:</strong> Write here…</p><p></p>`);
        else if (cmd === 'table') document.execCommand('insertHTML', false, '<table><thead><tr><th>Heading</th><th>Heading</th></tr></thead><tbody><tr><td>Cell</td><td>Cell</td></tr><tr><td>Cell</td><td>Cell</td></tr></tbody></table><p></p>');
        else if (cmd === 'hr') document.execCommand('insertHorizontalRule');
        else if (cmd === 'image') {
          const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/png,image/jpeg,image/webp,image/gif';
          const sel = window.getSelection(), range = sel.rangeCount ? sel.getRangeAt(0) : null;
          inp.onchange = async () => {
            if (!inp.files[0]) return;
            try {
              const j = await uploadFile(inp.files[0]);
              const alt = window.prompt('Describe the image (alt text for accessibility & SEO):', '') || '';
              area.focus(); if (range) { sel.removeAllRanges(); sel.addRange(range); }
              document.execCommand('insertHTML', false, `<img src="${h(j.url)}" alt="${h(alt)}">`);
              sync();
            } catch (err) { toast(err.message, 'err'); }
          };
          inp.click();
        } else document.execCommand(cmd);
        sync();
      });
    });
  }

  /* ---------- views ---------- */
  function parseHash() {
    const raw = window.location.hash.replace(/^#/, '') || '/dashboard';
    const [p, qs] = raw.split('?');
    return { parts: p.split('/').filter(Boolean), query: new URLSearchParams(qs || '') };
  }
  async function route() {
    document.body.classList.remove('side-open');
    if (!META) await refreshMeta(); else renderNav();
    const { parts, query } = parseHash();
    view.innerHTML = '<div class="loading"><span class="spin"></span> Loading…</div>';
    try {
      if (parts[0] === 'dashboard') return await viewDashboard();
      if (parts[0] === 'r' && parts[1]) { if (!R(parts[1])) throw new Error('Section not found or access denied.'); return parts[2] ? await viewForm(parts[1], parts[2] === 'new' ? null : parts[2]) : await viewList(parts[1], query); }
      if (parts[0] === 'quotations' && parts[1]) return await viewQuotation(parts[1]);
      if (parts[0] === 'home') return await viewHome(parts[1]);
      if (parts[0] === 'settings' && parts[1]) return await viewSettings(parts[1]);
      if (parts[0] === 'certificates') return await viewCertGenerator();
      if (parts[0] === 'media') return await viewMedia();
      if (parts[0] === 'account') return viewAccount();
      window.location.hash = '#/dashboard';
    } catch (err) {
      view.innerHTML = `<div class="panel empty-state">${ic('x')}<h2>Something went wrong</h2><p>${h(err.message)}</p><a class="btn btn-outline" href="#/dashboard">Back to dashboard</a></div>`;
    }
  }
  window.addEventListener('hashchange', route);

  async function viewDashboard() {
    setCrumb([['Dashboard']]);
    const d = await api('GET', '/admin/api/dashboard');
    const s = d.stats;
    const cards = [
      ['file', 'Blog posts', s.posts, `${s.posts_published} published`, '#/r/posts'],
      ['list', 'Course enrollments', s.enrollments, `${s.enrollments_pending} pending`, '#/r/enrollments'],
      ['wrench', 'CCTV service requests', s.service_requests, `${s.service_new} new`, '#/r/service_requests'],
      ['cart', 'Quotations', s.quotations, `${s.quotations_new} new · ${fmtMoney(s.quotation_value)}`, '#/r/quotations'],
      s.scheme !== null ? ['home', 'Scheme submissions', s.scheme, `${s.scheme_pending} pending`, '#/r/scheme'] : null,
      ['mail', 'Contact messages', s.contacts, `${s.contacts_new} unread`, '#/r/contacts'],
      ['award', 'Certificates', s.certificates, `${s.certificates_valid} valid · ${s.verifications} verifications`, '#/r/certificates'],
      ['users', 'Students', s.students, `${s.products} active products`, '#/r/students'],
    ].filter(Boolean);
    const max = Math.max(1, ...d.chart.map((x) => x.n));
    const recent = (title, rows, href, fn) => `<div class="panel"><div class="panel-head"><h3>${h(title)}</h3><a href="${href}" class="link">View all</a></div>${rows.length ? `<ul class="mini-list">${rows.map(fn).join('')}</ul>` : '<p class="no pad">Nothing yet.</p>'}</div>`;
    view.innerHTML = `<div class="page-head"><div><h1>Welcome back, ${h(META.admin.name.split(' ')[0])}</h1><p class="muted">Here is what is happening on ${h(META.siteName)}.</p></div><div class="actions"><a class="btn btn-primary" href="#/r/posts/new">${ic('plus')} New blog post</a><a class="btn btn-outline" href="#/certificates/generate">${ic('award')} Generate certificates</a></div></div>
      ${d.vercel ? `<div class="alert alert-warn">${ic('activity')}<div><strong>Vercel test mode:</strong> data and uploads are stored temporarily and will be reset when Vercel restarts the server. Use cPanel or another host with permanent storage for the live website.</div></div>` : ''}
      ${!d.smtp ? `<div class="alert alert-info">${ic('mail')}<div>Email notifications are off. Everything still works and is saved in the dashboard — configure SMTP in <a href="#/settings/smtp">Email settings</a> to receive alerts.</div></div>` : ''}
      ${s.comments_pending ? `<div class="alert alert-warn">${ic('chat')}<div>${s.comments_pending} blog comment(s) awaiting moderation. <a href="#/r/comments?status=pending">Review now</a></div></div>` : ''}
      <div class="stats">${cards.map(([icn, label, n, sub, href]) => `<a class="stat" href="${href}"><span class="stat-ic">${ic(icn)}</span><span class="stat-n">${n}</span><span class="stat-l">${h(label)}</span><span class="stat-s">${h(sub)}</span></a>`).join('')}</div>
      <div class="grid-2"><div class="panel"><div class="panel-head"><h3>Submissions — last 14 days</h3><span class="muted small">Enrollments, requests, quotations, scheme & messages</span></div>
        <div class="chart">${d.chart.map((x) => `<div class="bar" title="${h(x.d)}: ${x.n}"><span style="height:${Math.round((x.n / max) * 100)}%"></span><em>${x.n || ''}</em><small>${new Date(x.d + 'T00:00:00').getDate()}</small></div>`).join('')}</div></div>
        <div class="panel"><div class="panel-head"><h3>Recent activity</h3>${R('activity') ? '<a href="#/r/activity" class="link">Full log</a>' : ''}</div><ul class="activity">${d.activity.map((a) => `<li><span class="dot"></span><div><strong>${h(a.action)}</strong>${a.details ? ` <span class="muted">— ${h(a.details)}</span>` : ''}<br><small>${h(a.actor || '')} · ${fmtDate(a.created_at, true)}</small></div></li>`).join('') || '<li class="no">No activity yet.</li>'}</ul></div></div>
      <div class="grid-3">
        ${recent('New enrollments', d.recent.enrollments, '#/r/enrollments', (r) => `<li><a href="#/r/enrollments/${r.id}"><strong>${h(r.name)}</strong><small>${h(r.ref)} · ${fmtDate(r.created_at)}</small></a>${badge(r.status)}</li>`)}
        ${recent('Latest quotations', d.recent.quotations, '#/r/quotations', (r) => `<li><a href="#/quotations/${r.id}"><strong>${h(r.name)}</strong><small>${h(r.number)} · ${fmtMoney(r.total)}</small></a>${badge(r.status)}</li>`)}
        ${recent('Service requests', d.recent.service_requests, '#/r/service_requests', (r) => `<li><a href="#/r/service_requests/${r.id}"><strong>${h(r.name)}</strong><small>${h(r.service_type)} · ${fmtDate(r.created_at)}</small></a>${badge(r.status)}</li>`)}
        ${recent('Contact messages', d.recent.contacts, '#/r/contacts', (r) => `<li><a href="#/r/contacts/${r.id}"><strong>${h(r.name)}</strong><small>${h(r.subject)} · ${fmtDate(r.created_at)}</small></a>${badge(r.status)}</li>`)}
        ${R('scheme') ? recent('Scheme submissions', d.recent.scheme, '#/r/scheme', (r) => `<li><a href="#/r/scheme/${r.id}"><strong>${h(r.name)}</strong><small>${h(r.ref)} · ${h(r.city)}</small></a>${badge(r.status)}</li>`) : ''}
      </div>`;
  }

  async function viewList(key, query) {
    const res = R(key);
    setCrumb([[res.group], [res.label]]);
    const page = parseInt(query.get('page'), 10) || 1;
    const params = new URLSearchParams(query);
    params.set('page', page);
    const j = await api('GET', `/admin/api/r/${key}?${params}`);
    const cols = res.fields.filter((f) => f.list);
    const filters = res.fields.filter((f) => f.filter);
    const statusField = res.fields.find((f) => f.name === 'status' && f.type === 'select' && !f.readonly);
    const bulk = key === 'enrollments';
    const sortBy = query.get('sort'), dir = query.get('dir');
    const qsWith = (changes) => { const p = new URLSearchParams(query); for (const [k, v] of Object.entries(changes)) { if (v === '' || v == null) p.delete(k); else p.set(k, v); } return `#/r/${key}?${p}`; };
    view.innerHTML = `<div class="page-head"><div><h1>${h(res.label)}</h1><p class="muted">${j.total} record${j.total === 1 ? '' : 's'}</p></div><div class="actions">
        ${res.exportable ? `<a class="btn btn-outline" href="/admin/api/export/${key}?${new URLSearchParams([...query].filter(([k]) => k !== 'page'))}" download>${ic('download')} Export CSV</a>` : ''}
        ${key === 'certificates' ? `<a class="btn btn-primary" href="#/certificates/generate">${ic('award')} Generate certificates</a>` : ''}
        ${res.canCreate ? `<a class="btn btn-primary" href="#/r/${key}/new">${ic('plus')} Add ${h(res.singular.toLowerCase())}</a>` : ''}</div></div>
      <div class="panel"><form class="toolbar" id="filterForm"><div class="search">${ic('search')}<input type="search" name="q" value="${h(query.get('q') || '')}" placeholder="Search ${h(res.label.toLowerCase())}…"></div>
        ${filters.map((f) => `<select name="${f.name}" aria-label="${h(f.label)}"><option value="">${h(f.label)}: all</option>${(f.type === 'bool' ? [['1', 'Yes'], ['0', 'No']] : f.options || []).map(([v, l]) => `<option value="${h(v)}" ${query.get(f.name) === String(v) ? 'selected' : ''}>${h(l)}</option>`).join('')}</select>`).join('')}
        <button class="btn btn-dark" type="submit">Filter</button>${[...query.keys()].some((k) => k !== 'page') ? `<a class="btn btn-ghost" href="#/r/${key}">Reset</a>` : ''}
        ${bulk ? `<button class="btn btn-outline" type="button" id="bulkCert" disabled>${ic('award')} Generate certificates (<span>0</span>)</button>` : ''}</form>
      ${j.rows.length ? `<div class="table-wrap"><table class="tbl"><thead><tr>${bulk ? '<th class="chk"><input type="checkbox" id="chkAll" aria-label="Select all"></th>' : ''}${cols.map((f) => `<th><a href="${qsWith({ sort: f.name, dir: sortBy === f.name && dir !== 'asc' ? 'asc' : 'desc', page: '' })}">${h(f.label)}${sortBy === f.name ? (dir === 'asc' ? ' ↑' : ' ↓') : ''}</a></th>`).join('')}<th class="act">Actions</th></tr></thead>
        <tbody>${j.rows.map((r) => `<tr data-id="${r.id}">${bulk ? `<td class="chk"><input type="checkbox" class="rowchk" value="${r.id}" ${r.certificate_id || !(r.status === 'completed' || r.certificate_eligible) ? 'disabled title="Not eligible or already certified"' : ''}></td>` : ''}
          ${cols.map((f, i) => `<td data-label="${h(f.label)}">${f === statusField && res.canEdit ? `<select class="inline-status" data-id="${r.id}">${f.options.map(([v, l]) => `<option value="${h(v)}" ${String(r[f.name]) === String(v) ? 'selected' : ''}>${h(l)}</option>`).join('')}</select>` : i === 0 || f.name === res.title ? `<a class="row-link" href="${key === 'quotations' ? `#/quotations/${r.id}` : `#/r/${key}/${r.id}`}">${cell(f, r)}</a>` : cell(f, r)}</td>`).join('')}
          <td class="act">${res.canEdit || key === 'activity' ? `<a class="icon-btn sm" title="${res.canEdit ? 'Edit' : 'View'}" href="${key === 'quotations' ? `#/quotations/${r.id}` : `#/r/${key}/${r.id}`}">${ic(res.canEdit ? 'edit' : 'eye')}</a>` : ''}
            ${key === 'certificates' ? `<a class="icon-btn sm" title="Print" href="/certificate/${h(r.certificate_id)}" target="_blank">${ic('print')}</a>${r.status === 'valid' ? `<button class="icon-btn sm warn" title="Revoke" data-revoke="${r.id}" data-cid="${h(r.certificate_id)}">${ic('x')}</button>` : `<button class="icon-btn sm" title="Restore" data-restore="${r.id}">${ic('check')}</button>`}` : ''}
            ${key === 'quotations' ? `<a class="icon-btn sm" title="Print" href="/quotation/${h(r.number)}" target="_blank">${ic('print')}</a>` : ''}
            ${res.canDelete ? `<button class="icon-btn sm danger" title="Delete" data-del="${r.id}" data-name="${h(r[res.title] || res.singular)}">${ic('trash')}</button>` : ''}</td></tr>`).join('')}</tbody></table></div>`
      : `<div class="empty-state">${ic('inbox')}<h3>No records found</h3><p class="muted">${[...query.keys()].some((k) => k !== 'page') ? 'Try changing the search or filters.' : 'Nothing has been added yet.'}</p></div>`}
      ${j.pages > 1 ? `<div class="pager"><span class="muted">Page ${j.page} of ${j.pages}</span><div>${j.page > 1 ? `<a class="btn btn-sm btn-outline" href="${qsWith({ page: j.page - 1 })}">← Previous</a>` : ''}${j.page < j.pages ? `<a class="btn btn-sm btn-outline" href="${qsWith({ page: j.page + 1 })}">Next →</a>` : ''}</div></div>` : ''}</div>`;
    $('#filterForm').addEventListener('submit', (e) => {
      e.preventDefault();
      const p = new URLSearchParams();
      for (const [k, v] of new FormData(e.target)) if (v) p.set(k, v);
      if (sortBy) { p.set('sort', sortBy); if (dir) p.set('dir', dir); }
      window.location.hash = `#/r/${key}?${p}`;
    });
    $$('.inline-status', view).forEach((s) => s.addEventListener('change', async () => {
      try { await api('PUT', `/admin/api/r/${key}/${s.dataset.id}`, { status: s.value }); toast(`Status updated to “${s.options[s.selectedIndex].text}”`); refreshMeta(); } catch (err) { toast(err.message, 'err'); }
    }));
    $$('[data-del]', view).forEach((b) => b.addEventListener('click', async () => {
      if (!(await confirmDelete(b.dataset.name))) return;
      try { await api('DELETE', `/admin/api/r/${key}/${b.dataset.del}`); toast(`${res.singular} deleted`); await refreshMeta(); route(); } catch (err) { toast(err.message, 'err'); }
    }));
    $$('[data-revoke]', view).forEach((b) => b.addEventListener('click', async () => {
      const reason = await modal({ title: `Revoke certificate ${b.dataset.cid}?`, body: '<p>The certificate will show as <strong>revoked</strong> on the public verification page.</p>', confirmText: 'Revoke', danger: true, input: { label: 'Reason (internal & optional)' } });
      if (!reason) return;
      try { await api('POST', `/admin/api/certificates/${b.dataset.revoke}/revoke`, { reason: reason === true ? '' : reason }); toast('Certificate revoked'); route(); } catch (err) { toast(err.message, 'err'); }
    }));
    $$('[data-restore]', view).forEach((b) => b.addEventListener('click', async () => {
      if (!(await modal({ title: 'Restore certificate?', body: '<p>The certificate will become valid again.</p>', confirmText: 'Restore' }))) return;
      try { await api('POST', `/admin/api/certificates/${b.dataset.restore}/restore`, {}); toast('Certificate restored'); route(); } catch (err) { toast(err.message, 'err'); }
    }));
    if (bulk) {
      const btn = $('#bulkCert');
      const upd = () => { const n = $$('.rowchk:checked', view).length; btn.disabled = !n; $('span', btn).textContent = n; };
      $$('.rowchk', view).forEach((c) => c.addEventListener('change', upd));
      const all = $('#chkAll');
      if (all) all.addEventListener('change', () => { $$('.rowchk:not(:disabled)', view).forEach((c) => { c.checked = all.checked; }); upd(); });
      btn.addEventListener('click', async () => {
        const ids = $$('.rowchk:checked', view).map((c) => c.value);
        if (!(await modal({ title: `Generate ${ids.length} certificate(s)?`, body: '<p>Selected enrollments will be marked as completed and receive a unique certificate ID.</p>', confirmText: 'Generate' }))) return;
        try { const r = await api('POST', '/admin/api/certificates/generate', { enrollment_ids: ids }); toast(r.message); route(); } catch (err) { toast(err.message, 'err'); }
      });
    }
  }

  async function viewForm(key, id) {
    if (!id || key !== 'quotations') await refreshMeta();
    const res = R(key);
    let row = {}, links = [];
    if (id) { const j = await api('GET', `/admin/api/r/${key}/${id}`); row = j.row; links = j.links || []; }
    if (key === 'contacts' && row.status === 'new') { api('PUT', `/admin/api/r/${key}/${id}`, { status: 'read' }).then(refreshMeta).catch(() => {}); row.status = 'read'; }
    const title = id ? (row[res.title] || `${res.singular} #${id}`) : `New ${res.singular.toLowerCase()}`;
    setCrumb([[res.group], [res.label, `#/r/${key}`], [String(title)]]);
    const editable = res.canEdit || !id;
    const fields = res.fields.filter((f) => !(f.computed && !id) && !(f.readonly && !id));
    view.innerHTML = `<div class="page-head"><div><a class="back" href="#/r/${key}">← ${h(res.label)}</a><h1>${h(title)}</h1>${row.created_at ? `<p class="muted">Created ${fmtDate(row.created_at, true)}${row.updated_at ? ` · Updated ${fmtDate(row.updated_at, true)}` : ''}</p>` : ''}</div>
      <div class="actions">${links.map((l) => `<a class="btn btn-outline" href="${h(l.href)}" target="${l.href.startsWith('mailto:') ? '_self' : '_blank'}" rel="noopener">${ic(l.icon || 'external')} ${h(l.label)}</a>`).join('')}</div></div>
      ${key === 'scheme' ? `<div class="alert alert-warn">${ic('lock')}<div>This record contains sensitive personal information (CNIC). Viewing is logged. Do not share outside the authorised team.</div></div>` : ''}
      <form class="panel form" id="editForm" novalidate><div class="form-grid">${fields.map((f) => fieldInput(editable ? f : { ...f, readonly: true }, id ? row[f.name] : undefined)).join('')}</div>
      ${editable ? `<div class="form-foot"><button class="btn btn-primary" type="submit">${ic('check')} ${id ? 'Save changes' : `Create ${h(res.singular.toLowerCase())}`}</button><a class="btn btn-ghost" href="#/r/${key}">Cancel</a>
        ${id && res.canDelete ? `<button class="btn btn-danger-ghost push" type="button" id="delBtn">${ic('trash')} Delete</button>` : ''}</div>` : ''}</form>`;
    const form = $('#editForm');
    bindFieldWidgets(form);
    if (!editable) return;
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      showFieldErrors(form, null);
      const btn = form.querySelector('[type=submit]');
      btn.disabled = true;
      try {
        const data = readForm(form, fields);
        const j = id ? await api('PUT', `/admin/api/r/${key}/${id}`, data) : await api('POST', `/admin/api/r/${key}`, data);
        toast(j.message || 'Saved');
        await refreshMeta();
        if (!id) window.location.hash = `#/r/${key}/${j.id}`; else route();
      } catch (err) { toast(err.message, 'err'); showFieldErrors(form, err.fields); } finally { btn.disabled = false; }
    });
    const del = $('#delBtn');
    if (del) del.addEventListener('click', async () => {
      if (!(await confirmDelete(String(title)))) return;
      try { await api('DELETE', `/admin/api/r/${key}/${id}`); toast(`${res.singular} deleted`); await refreshMeta(); window.location.hash = `#/r/${key}`; } catch (err) { toast(err.message, 'err'); }
    });
  }

  async function viewQuotation(id) {
    const res = R('quotations');
    const [d, it] = await Promise.all([api('GET', `/admin/api/r/quotations/${id}`), api('GET', `/admin/api/quotations/${id}/items`)]);
    const row = d.row;
    setCrumb([['CCTV'], ['Quotations', '#/r/quotations'], [row.number]]);
    const customerLink = `${window.location.origin}/quotation/${encodeURIComponent(row.number)}?t=${it.quotation.access_token}`;
    let items = it.items.map((x) => ({ ...x }));
    const editFields = res.fields.filter((f) => ['status', 'valid_until', 'installation_charge', 'delivery_charge', 'discount', 'notes', 'customer_name', 'phone', 'email', 'city', 'address'].includes(f.name));
    view.innerHTML = `<div class="page-head"><div><a class="back" href="#/r/quotations">← Quotations</a><h1>Quotation ${h(row.number)}</h1><p class="muted">Created ${fmtDate(row.created_at, true)} · ${badge(row.status)}</p></div>
      <div class="actions"><a class="btn btn-outline" href="/quotation/${h(row.number)}" target="_blank">${ic('print')} Print / PDF</a><button class="btn btn-outline" type="button" id="copyLink">${ic('link')} Copy customer link</button><button class="btn btn-danger-ghost" type="button" id="delQ">${ic('trash')} Delete</button></div></div>
      <div class="grid-2 wide-left"><div class="panel"><div class="panel-head"><h3>Items</h3><span class="muted small">Prices are locked at the time of the quotation — edit them here if needed.</span></div>
        <div class="table-wrap"><table class="tbl items-tbl"><thead><tr><th>Item</th><th>Unit price</th><th>Qty</th><th class="num">Total</th><th></th></tr></thead><tbody id="qItems"></tbody></table></div>
        <div class="add-row"><select id="addProd"><option value="">+ Add a product…</option>${it.products.map((p) => `<option value="${p.id}">${h(p.name)} — ${fmtMoney(p.price)}</option>`).join('')}</select><button type="button" class="btn btn-sm btn-outline" id="addCustom">+ Custom line</button></div>
        <label class="check"><input type="checkbox" id="recalc"> Recalculate installation, delivery &amp; discount from current settings</label>
        <div class="form-foot"><button class="btn btn-primary" type="button" id="saveItems">${ic('check')} Save items</button><span class="muted" id="itemsTotal"></span></div></div>
      <form class="panel form" id="qForm" novalidate><div class="panel-head"><h3>Details &amp; charges</h3></div><div class="form-grid one">${editFields.map((f) => fieldInput(f, row[f.name])).join('')}</div>
        <div class="sum-box"><div><span>Subtotal</span><strong>${fmtMoney(row.subtotal)}</strong></div><div><span>Installation</span><strong>${fmtMoney(row.installation_charge)}</strong></div><div><span>Delivery</span><strong>${fmtMoney(row.delivery_charge)}</strong></div><div><span>Discount</span><strong>− ${fmtMoney(row.discount)}</strong></div><div class="grand"><span>Total</span><strong>${fmtMoney(row.total)}</strong></div></div>
        ${row.customer_notes ? `<div class="alert alert-info">${ic('chat')}<div><strong>Customer notes:</strong> ${h(row.customer_notes)}</div></div>` : ''}
        <div class="form-foot"><button class="btn btn-primary" type="submit">${ic('check')} Save details</button></div></form></div>`;
    const tbody = $('#qItems');
    const renderItems = () => {
      tbody.innerHTML = items.map((x, i) => `<tr data-i="${i}"><td>${x.product_id ? h(x.product_name) : `<input type="text" class="in-name" value="${h(x.product_name)}" maxlength="150">`}${x.sku ? `<br><small class="muted">${h(x.sku)}</small>` : ''}</td>
        <td><input type="number" class="in-price" min="0" step="any" value="${x.unit_price}"></td><td><input type="number" class="in-qty" min="1" max="9999" value="${x.quantity}"></td><td class="num">${fmtMoney(x.unit_price * x.quantity)}</td><td><button type="button" class="icon-btn sm danger" data-rm="${i}" title="Remove">${ic('trash')}</button></td></tr>`).join('') || '<tr><td colspan="5" class="no">No items.</td></tr>';
      $('#itemsTotal').textContent = `Items subtotal: ${fmtMoney(items.reduce((s, x) => s + x.unit_price * x.quantity, 0))}`;
    };
    renderItems();
    tbody.addEventListener('change', (e) => {
      const tr = e.target.closest('tr'); if (!tr) return;
      const x = items[+tr.dataset.i];
      if (e.target.classList.contains('in-price')) x.unit_price = Math.max(0, Number(e.target.value) || 0);
      if (e.target.classList.contains('in-qty')) x.quantity = Math.max(1, parseInt(e.target.value, 10) || 1);
      if (e.target.classList.contains('in-name')) x.product_name = e.target.value;
      renderItems();
    });
    tbody.addEventListener('click', (e) => { const b = e.target.closest('[data-rm]'); if (b) { items.splice(+b.dataset.rm, 1); renderItems(); } });
    $('#addProd').addEventListener('change', (e) => {
      const p = it.products.find((x) => String(x.id) === e.target.value);
      if (p) { const ex = items.find((x) => x.product_id === p.id); if (ex) ex.quantity++; else items.push({ product_id: p.id, product_name: p.name, sku: p.sku, unit_price: p.price, quantity: 1, installable: p.installable }); }
      e.target.value = ''; renderItems();
    });
    $('#addCustom').addEventListener('click', () => { items.push({ product_id: null, product_name: 'Custom item / service', unit_price: 0, quantity: 1 }); renderItems(); });
    $('#saveItems').addEventListener('click', async () => {
      try { const r = await api('PUT', `/admin/api/quotations/${id}/items`, { items, recalculate_charges: $('#recalc').checked }); toast(`${r.message} New total: ${fmtMoney(r.total)}`); route(); } catch (err) { toast(err.message, 'err'); }
    });
    const form = $('#qForm');
    bindFieldWidgets(form);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      try { await api('PUT', `/admin/api/r/quotations/${id}`, readForm(form, editFields)); toast('Quotation saved'); await refreshMeta(); route(); } catch (err) { toast(err.message, 'err'); showFieldErrors(form, err.fields); }
    });
    $('#copyLink').addEventListener('click', async () => { try { await navigator.clipboard.writeText(customerLink); toast('Customer link copied'); } catch { window.prompt('Customer link:', customerLink); } });
    $('#delQ').addEventListener('click', async () => {
      if (!(await confirmDelete(`quotation ${row.number}`))) return;
      try { await api('DELETE', `/admin/api/r/quotations/${id}`); toast('Quotation deleted'); window.location.hash = '#/r/quotations'; } catch (err) { toast(err.message, 'err'); }
    });
  }

  async function viewHome(section) {
    const j = await api('GET', '/admin/api/home');
    const keys = Object.keys(META.home);
    const sec = keys.includes(section) ? section : 'hero';
    const schema = META.home[sec];
    setCrumb([['Website'], ['Homepage content', '#/home'], [schema.label]]);
    view.innerHTML = `<div class="page-head"><div><h1>Homepage content</h1><p class="muted">Edit headings, text, images, links and visibility of every homepage section.</p></div><div class="actions"><a class="btn btn-outline" href="/" target="_blank">${ic('external')} View homepage</a></div></div>
      <div class="split-view"><nav class="sub-nav">${keys.map((k) => `<a href="#/home/${k}" class="${k === sec ? 'active' : ''}">${h(META.home[k].label)}${j.values[k] && j.values[k].enabled === false ? ' <small>(hidden)</small>' : ''}</a>`).join('')}</nav>
      <form class="panel form" id="homeForm" novalidate><div class="panel-head"><h3>${h(schema.label)}</h3></div><div class="form-grid">${schema.fields.map((f) => fieldInput(f, j.values[sec][f.name])).join('')}</div>
      <div class="form-foot"><button class="btn btn-primary" type="submit">${ic('check')} Save section</button></div></form></div>`;
    const form = $('#homeForm');
    bindFieldWidgets(form);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      try { const r = await api('PUT', `/admin/api/home/${sec}`, readForm(form, schema.fields)); toast(r.message); } catch (err) { toast(err.message, 'err'); showFieldErrors(form, err.fields); }
    });
  }

  async function viewSettings(group) {
    const schema = META.settings[group];
    if (!schema) throw new Error('Unknown settings group.');
    setCrumb([['Settings'], [schema.label]]);
    const j = await api('GET', `/admin/api/settings/${group}`);
    view.innerHTML = `<div class="page-head"><div><h1>${h(schema.label)}</h1><p class="muted">Changes apply to the website immediately after saving.</p></div>${group === 'smtp' ? `<div class="actions"><button class="btn btn-outline" id="testMail" type="button">${ic('mail')} Send test email</button></div>` : ''}</div>
      <form class="panel form" id="setForm" novalidate><div class="form-grid">${schema.fields.map((f) => fieldInput(f, j.values[f.name])).join('')}</div><div class="form-foot"><button class="btn btn-primary" type="submit">${ic('check')} Save settings</button></div></form>`;
    const form = $('#setForm');
    bindFieldWidgets(form);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      try { const r = await api('PUT', `/admin/api/settings/${group}`, readForm(form, schema.fields)); toast(r.message); META = null; route(); } catch (err) { toast(err.message, 'err'); showFieldErrors(form, err.fields); }
    });
    const t = $('#testMail');
    if (t) t.addEventListener('click', async () => { t.disabled = true; try { const r = await api('POST', '/admin/api/smtp/test', {}); toast(r.message); } catch (err) { toast(err.message, 'err'); } t.disabled = false; });
  }

  async function viewCertGenerator() {
    setCrumb([['Course'], ['Generate certificates']]);
    const j = await api('GET', '/admin/api/certificates/eligible');
    const courses = (R('enrollments').fields.find((f) => f.name === 'course_id') || {}).options || [];
    view.innerHTML = `<div class="page-head"><div><h1>Certificate generator</h1><p class="muted">Issue certificates to students who completed the course, or create one manually.</p></div><div class="actions"><a class="btn btn-outline" href="#/r/certificates">${ic('award')} All certificates</a><a class="btn btn-outline" href="#/settings/certificate">${ic('settings')} Certificate design</a></div></div>
      <div class="grid-2 wide-left"><div class="panel"><div class="panel-head"><h3>Eligible students (${j.rows.length})</h3><span class="muted small">Completed or marked eligible, without a valid certificate.</span></div>
        ${j.rows.length ? `<div class="table-wrap"><table class="tbl"><thead><tr><th class="chk"><input type="checkbox" id="chkAll"></th><th>Student</th><th>Father's name</th><th>Course</th><th>Status</th><th>Completion</th></tr></thead><tbody>${j.rows.map((r) => `<tr><td class="chk"><input type="checkbox" class="rowchk" value="${r.id}"></td><td><strong>${h(r.full_name)}</strong><br><small class="muted">${h(r.ref)} · ${h(r.phone)}</small></td><td>${h(r.father_name || '—')}</td><td>${h(r.course_name)}</td><td>${badge(r.status)}</td><td>${fmtDate(r.completion_date)}</td></tr>`).join('')}</tbody></table></div>
        <div class="form-foot"><label class="fld inline"><span>Grade (optional)</span><input type="text" id="grade" maxlength="20" placeholder="e.g. A"></label><button class="btn btn-primary" id="genBtn" type="button" disabled>${ic('award')} Generate for selected (<span>0</span>)</button></div>`
        : `<div class="empty-state">${ic('award')}<h3>No eligible students</h3><p class="muted">Mark an enrollment as <em>completed</em> or <em>certificate eligible</em> in <a href="#/r/enrollments">Enrollments</a>.</p></div>`}</div>
      <div><form class="panel form" id="manualForm" novalidate><div class="panel-head"><h3>Manual certificate</h3></div><div class="form-grid one">
        <div class="fld" data-field="student_name"><label>Student name <b class="req">*</b></label><input type="text" name="student_name" maxlength="100"></div>
        <div class="fld" data-field="father_name"><label>Father's name</label><input type="text" name="father_name" maxlength="100"></div>
        <div class="fld" data-field="course_name"><label>Course name <b class="req">*</b></label><input type="text" name="course_name" maxlength="120" list="courseList" value="${h(courses[0] ? courses[0][1] : 'Basic Computer Course')}"><datalist id="courseList">${courses.map(([, l]) => `<option value="${h(l)}">`).join('')}</datalist></div>
        <div class="fld" data-field="completion_date"><label>Completion date <b class="req">*</b></label><input type="date" name="completion_date" value="${new Date().toISOString().slice(0, 10)}"></div>
        <div class="fld" data-field="grade"><label>Grade (optional)</label><input type="text" name="grade" maxlength="20"></div></div>
        <div class="form-foot"><button class="btn btn-primary" type="submit">${ic('award')} Generate certificate</button></div></form>
      <form class="panel form" id="lookupForm"><div class="panel-head"><h3>Verify / search a certificate ID</h3></div><div class="toolbar"><div class="search">${ic('search')}<input type="search" name="id" placeholder="SDS-BCC-2026-XXXXXX" required></div><button class="btn btn-dark" type="submit">Check</button></div><div id="lookupRes"></div></form></div></div>`;
    const upd = () => { const n = $$('.rowchk:checked', view).length; const b = $('#genBtn'); if (b) { b.disabled = !n; $('span', b).textContent = n; } };
    $$('.rowchk', view).forEach((c) => c.addEventListener('change', upd));
    const all = $('#chkAll');
    if (all) all.addEventListener('change', () => { $$('.rowchk', view).forEach((c) => { c.checked = all.checked; }); upd(); });
    const gen = $('#genBtn');
    if (gen) gen.addEventListener('click', async () => {
      const ids = $$('.rowchk:checked', view).map((c) => c.value);
      try { const r = await api('POST', '/admin/api/certificates/generate', { enrollment_ids: ids, grade: $('#grade').value }); await showCreated(r); } catch (err) { toast(err.message, 'err'); }
    });
    async function showCreated(r) {
      await modal({ title: r.message, body: `<ul class="files">${r.created.map((c) => `<li>${ic('award')}<a href="/certificate/${h(c)}" target="_blank">${h(c)}</a> — open &amp; print</li>`).join('')}</ul>`, confirmText: 'Done', cancelText: 'Close' });
      route();
    }
    $('#manualForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      try { const r = await api('POST', '/admin/api/certificates/generate', { manual: Object.fromEntries(new FormData(e.target)) }); await showCreated(r); } catch (err) { toast(err.message, 'err'); showFieldErrors(e.target, err.fields); }
    });
    $('#lookupForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = new FormData(e.target).get('id');
      const r = await api('GET', `/admin/api/certificates/lookup?id=${encodeURIComponent(id)}`);
      $('#lookupRes').innerHTML = r.cert ? `<div class="alert ${r.cert.status === 'valid' ? 'alert-ok' : 'alert-err'}">${ic(r.cert.status === 'valid' ? 'check' : 'x')}<div><strong>${h(r.cert.certificate_id)}</strong> — ${badge(r.cert.status)}<br>${h(r.cert.student_name)} · ${h(r.cert.course_name)} · completed ${fmtDate(r.cert.completion_date)}<br>Verified publicly ${r.history.length} time(s). <a href="/certificate/${h(r.cert.certificate_id)}" target="_blank">Open certificate</a></div></div>` : `<div class="alert alert-err">${ic('x')}<div>No certificate found with ID <strong>${h(String(id).toUpperCase())}</strong>.</div></div>`;
    });
  }

  async function viewMedia() {
    setCrumb([['Website'], ['Media library']]);
    const j = await api('GET', '/admin/api/media');
    view.innerHTML = `<div class="page-head"><div><h1>Media library</h1><p class="muted">${j.files.length} uploaded file(s). Images up to 3 MB (JPG, PNG, WEBP, GIF) · PDF documents up to 5 MB.</p></div>
      <div class="actions"><label class="btn btn-primary">${ic('image')} Upload image<input type="file" id="upImg" accept="image/png,image/jpeg,image/webp,image/gif" hidden multiple></label><label class="btn btn-outline">${ic('file')} Upload PDF<input type="file" id="upDoc" accept="application/pdf" hidden></label></div></div>
      <div class="panel">${j.files.length ? `<div class="media-grid">${j.files.map((f) => `<figure class="media">${f.dir === 'images' ? `<img src="${h(f.url)}" alt="" loading="lazy">` : `<span class="doc">${ic('file')}PDF</span>`}<figcaption><code title="${h(f.url)}">${h(f.file)}</code><small>${Math.round(f.size / 1024)} KB · ${fmtDate(f.modified)}</small>
        <span class="row"><button class="btn btn-sm btn-outline" data-copy="${h(f.url)}" type="button">${ic('link')} Copy URL</button><button class="icon-btn sm danger" data-delmedia="${h(f.dir)}/${h(f.file)}" type="button" title="Delete">${ic('trash')}</button></span></figcaption></figure>`).join('')}</div>`
      : `<div class="empty-state">${ic('image')}<h3>No uploads yet</h3><p class="muted">Upload images here or directly from any image field.</p></div>`}</div>`;
    const up = async (input, kind) => {
      for (const file of input.files) { try { await uploadFile(file, null, kind); toast(`Uploaded ${file.name}`); } catch (err) { toast(`${file.name}: ${err.message}`, 'err'); } }
      route();
    };
    $('#upImg').addEventListener('change', (e) => up(e.target, 'image'));
    $('#upDoc').addEventListener('change', (e) => up(e.target, 'document'));
    $$('[data-copy]', view).forEach((b) => b.addEventListener('click', async () => { try { await navigator.clipboard.writeText(b.dataset.copy); toast('URL copied'); } catch { window.prompt('URL:', b.dataset.copy); } }));
    $$('[data-delmedia]', view).forEach((b) => b.addEventListener('click', async () => {
      if (!(await confirmDelete(b.dataset.delmedia.split('/')[1] + ' (pages using it will show a broken image)'))) return;
      try { await api('DELETE', `/admin/api/media/${b.dataset.delmedia}`); toast('File deleted'); route(); } catch (err) { toast(err.message, 'err'); }
    }));
  }

  function viewAccount() {
    setCrumb([['System'], ['My account']]);
    view.innerHTML = `<div class="page-head"><div><h1>My account</h1><p class="muted">${h(META.admin.name)} · ${h(META.admin.email)} · ${h(META.admin.role)}</p></div></div>
      <form class="panel form narrow" id="pwForm" novalidate><div class="panel-head"><h3>Change password</h3></div><div class="form-grid one">
        <div class="fld" data-field="current"><label>Current password</label><input type="password" name="current" autocomplete="current-password"></div>
        <div class="fld" data-field="password"><label>New password (min. 10 characters)</label><input type="password" name="password" autocomplete="new-password"></div>
        <div class="fld" data-field="confirm"><label>Confirm new password</label><input type="password" name="confirm" autocomplete="new-password"></div></div>
        <div class="form-foot"><button class="btn btn-primary" type="submit">${ic('lock')} Update password</button></div></form>`;
    $('#pwForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      try { const r = await api('POST', '/admin/api/account/password', Object.fromEntries(new FormData(e.target))); toast(r.message); e.target.reset(); showFieldErrors(e.target, null); } catch (err) { toast(err.message, 'err'); showFieldErrors(e.target, err.fields); }
    });
  }

  route();
}

const ADMIN_CSS = `
:root{--bg:#f4f6fb;--panel:#fff;--ink:#0f172a;--text:#334155;--muted:#64748b;--line:#e3e8f0;--line2:#eef1f6;--side:#0b1b33;--side2:#11284a;--side-text:#a9b8cf;--blue:#2563eb;--blue-d:#1d4ed8;--blue-50:#eef4ff;--ok:#047857;--ok-bg:#ecfdf5;--err:#b91c1c;--err-bg:#fef2f2;--warn:#92400e;--warn-bg:#fffbeb;--shadow:0 1px 2px rgba(15,23,42,.05),0 2px 8px rgba(15,23,42,.04);--r:12px;font-family:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif}
[data-theme=dark]{--bg:#0a1220;--panel:#111c2e;--ink:#e8eef8;--text:#c3cede;--muted:#8a9ab3;--line:#22324b;--line2:#1a283d;--side:#070e1a;--side2:#0f1b30;--blue-50:#16264a;--ok-bg:#062a1f;--err-bg:#2c1015;--warn-bg:#2a1f07;--shadow:none}
*{box-sizing:border-box}html,body{margin:0}body{background:var(--bg);color:var(--text);font-size:14.5px;line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:var(--blue)}h1,h2,h3{color:var(--ink);font-family:'Plus Jakarta Sans','Inter',sans-serif;letter-spacing:-.01em;margin:0}
h1{font-size:1.55rem;font-weight:800}h3{font-size:1rem;font-weight:700}
.ico{width:18px;height:18px;flex:none}.muted{color:var(--muted)}.small{font-size:.82rem}.no{color:var(--muted)}.pad{padding:14px 0}.nowrap{white-space:nowrap}.pre{white-space:pre-wrap}
code{font-family:ui-monospace,Consolas,monospace;font-size:.85em;background:var(--line2);padding:2px 6px;border-radius:5px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:9px 15px;border-radius:9px;border:1px solid transparent;font:600 .88rem/1.2 inherit;font-family:inherit;cursor:pointer;text-decoration:none;white-space:nowrap;transition:background .15s,border-color .15s,color .15s}
.btn .ico{width:16px;height:16px}.btn[disabled]{opacity:.55;cursor:not-allowed}
.btn-primary{background:var(--blue);color:#fff}.btn-primary:hover{background:var(--blue-d)}
.btn-dark{background:var(--ink);color:var(--panel)}.btn-outline{background:var(--panel);border-color:var(--line);color:var(--ink)}.btn-outline:hover{border-color:var(--blue);color:var(--blue)}
.btn-ghost{background:transparent;color:var(--muted)}.btn-ghost:hover{color:var(--ink);background:var(--line2)}
.btn-danger{background:#dc2626;color:#fff}.btn-danger-ghost{background:transparent;color:#dc2626;border-color:transparent}.btn-danger-ghost:hover{background:var(--err-bg)}
.btn-sm{padding:6px 11px;font-size:.8rem}.btn-block{width:100%}
.icon-btn{display:inline-grid;place-items:center;width:38px;height:38px;border-radius:9px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer;text-decoration:none}
.icon-btn:hover{border-color:var(--blue);color:var(--blue)}.icon-btn.sm{width:30px;height:30px;border-radius:7px}.icon-btn.sm .ico{width:15px;height:15px}
.icon-btn.danger:hover{border-color:#dc2626;color:#dc2626}.icon-btn.warn:hover{border-color:#d97706;color:#d97706}
/* layout */
.app{display:grid;grid-template-columns:262px 1fr;min-height:100vh}
.side{background:var(--side);color:var(--side-text);position:sticky;top:0;height:100vh;overflow-y:auto;padding:18px 12px 30px;scrollbar-width:thin}
.side-brand{padding:4px 8px 18px}.side .brand{display:flex;align-items:center;gap:10px;color:#fff;text-decoration:none}.side .brand-mark svg,.side .brand-logo{width:36px;height:36px;border-radius:9px}
.side .brand-text{display:flex;flex-direction:column;line-height:1.15}.side .brand-text strong{font-family:'Plus Jakarta Sans',sans-serif;font-size:.92rem}.side .brand-text small{font-size:.7rem;color:#7d8ea8}
.nav-group{margin-top:14px}.nav-group p{font-size:.68rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#5f7290;margin:0 10px 6px}
.nav-group a{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;color:var(--side-text);text-decoration:none;font-size:.88rem;font-weight:500}
.nav-group a:hover{background:var(--side2);color:#fff}.nav-group a.active{background:var(--blue);color:#fff}
.nav-group a em{margin-left:auto;font-style:normal;font-size:.7rem;font-weight:700;background:#ef4444;color:#fff;border-radius:10px;padding:1px 7px}
.main{min-width:0;display:flex;flex-direction:column}
.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:14px;height:64px;padding:0 26px;background:color-mix(in srgb,var(--panel) 92%,transparent);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.menu-btn{display:none}.crumb{font-size:.88rem;color:var(--muted);display:flex;gap:8px;align-items:center;min-width:0;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}.crumb a{color:var(--muted);text-decoration:none}.crumb a:hover{color:var(--blue)}.crumb span:last-child{color:var(--ink);font-weight:600;overflow:hidden;text-overflow:ellipsis}.crumb i{font-style:normal;opacity:.5}
.top-actions{margin-left:auto;display:flex;align-items:center;gap:8px}
.user{display:flex;align-items:center;gap:9px;padding:0 6px}.user .av{width:34px;height:34px;border-radius:50%;background:var(--blue);color:#fff;display:grid;place-items:center;font-weight:700;font-size:.8rem}.user .who{display:flex;flex-direction:column;line-height:1.2}.user strong{color:var(--ink);font-size:.85rem}.user small{color:var(--muted);font-size:.72rem;text-transform:capitalize}
[data-theme=dark] .i-moon,:root:not([data-theme=dark]) .i-sun{display:none}
.content{padding:26px;max-width:1400px;width:100%}
.loading{padding:60px;text-align:center;color:var(--muted);display:flex;gap:10px;justify-content:center;align-items:center}
.spin{width:18px;height:18px;border:2px solid var(--line);border-top-color:var(--blue);border-radius:50%;animation:sp 1s linear infinite}@keyframes sp{to{transform:rotate(360deg)}}
.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:20px;flex-wrap:wrap}.page-head p{margin:4px 0 0}.actions{display:flex;gap:8px;flex-wrap:wrap}
.back{display:inline-block;font-size:.84rem;color:var(--muted);text-decoration:none;margin-bottom:6px}.back:hover{color:var(--blue)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:20px;box-shadow:var(--shadow);margin-bottom:18px;min-width:0}
.panel-head{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap}.link{font-size:.84rem;text-decoration:none;font-weight:600}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:18px}.grid-2.wide-left{grid-template-columns:1.6fr 1fr}.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.grid-2>.panel,.grid-3>.panel{margin-bottom:0}.grid-2+.grid-3,.grid-2+.grid-2{margin-top:18px}
/* stats */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:18px;text-decoration:none;display:grid;grid-template-columns:auto 1fr;grid-template-rows:auto auto auto;column-gap:14px;box-shadow:var(--shadow);transition:border-color .15s,transform .15s}
.stat:hover{border-color:var(--blue);transform:translateY(-2px)}
.stat-ic{grid-row:1/4;width:44px;height:44px;border-radius:11px;background:var(--blue-50);color:var(--blue);display:grid;place-items:center}.stat-ic .ico{width:22px;height:22px}
.stat-n{font:800 1.6rem/1.1 'Plus Jakarta Sans',sans-serif;color:var(--ink)}.stat-l{color:var(--ink);font-weight:600;font-size:.86rem}.stat-s{color:var(--muted);font-size:.78rem}
.chart{display:flex;align-items:flex-end;gap:6px;height:170px;padding-top:10px}
.bar{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%;position:relative}
.bar span{display:block;width:100%;max-width:26px;background:linear-gradient(180deg,var(--blue),#60a5fa);border-radius:5px 5px 2px 2px;min-height:3px}
.bar em{font-style:normal;font-size:.68rem;color:var(--muted);margin-bottom:3px;order:-1}.bar small{font-size:.68rem;color:var(--muted);margin-top:5px}
.activity{list-style:none;margin:0;padding:0;display:grid;gap:12px;max-height:280px;overflow-y:auto}.activity li{display:flex;gap:10px;font-size:.85rem}.activity .dot{width:8px;height:8px;border-radius:50%;background:var(--blue);margin-top:7px;flex:none}.activity strong{color:var(--ink);font-weight:600}.activity small{color:var(--muted)}
.mini-list{list-style:none;margin:0;padding:0}.mini-list li{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--line2)}.mini-list li:last-child{border:0}
.mini-list a{text-decoration:none;min-width:0}.mini-list strong{display:block;color:var(--ink);font-size:.88rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.mini-list small{color:var(--muted);font-size:.78rem}
/* badges */
.badge{display:inline-block;font-size:.72rem;font-weight:700;padding:3px 9px;border-radius:999px;text-transform:capitalize;white-space:nowrap;background:var(--line2);color:var(--muted)}
.badge.blue{background:#dbeafe;color:#1e40af}.badge.amber{background:#fef3c7;color:#92400e}.badge.green{background:#d1fae5;color:#065f46}.badge.red{background:#fee2e2;color:#991b1b}.badge.indigo{background:#e0e7ff;color:#3730a3}.badge.violet{background:#ede9fe;color:#5b21b6}
[data-theme=dark] .badge.blue{background:#1e3a8a55;color:#93c5fd}[data-theme=dark] .badge.amber{background:#78350f55;color:#fcd34d}[data-theme=dark] .badge.green{background:#065f4655;color:#6ee7b7}[data-theme=dark] .badge.red{background:#7f1d1d55;color:#fca5a5}[data-theme=dark] .badge.indigo{background:#3730a355;color:#a5b4fc}[data-theme=dark] .badge.violet{background:#5b21b655;color:#c4b5fd}
/* toolbar & tables */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.search{flex:1;min-width:220px;position:relative}.search .ico{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);width:16px;height:16px}.search input{padding-left:34px}
input,select,textarea{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:9px;background:var(--panel);color:var(--ink);font:inherit;font-size:.9rem}
.toolbar select{width:auto;min-width:150px}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px color-mix(in srgb,var(--blue) 18%,transparent)}
textarea{resize:vertical;min-height:90px}input[type=color]{height:42px;padding:4px;width:90px}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
.tbl{width:100%;border-collapse:collapse;font-size:.86rem}
.tbl th{text-align:left;font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:var(--line2);padding:10px 12px;white-space:nowrap;font-weight:700}
.tbl th a{color:inherit;text-decoration:none}.tbl td{padding:10px 12px;border-top:1px solid var(--line);vertical-align:middle}
.tbl tbody tr:hover td{background:color-mix(in srgb,var(--blue) 4%,transparent)}
.tbl .act{text-align:right;white-space:nowrap}.tbl .act>*{margin-left:4px}.tbl .chk{width:36px}.tbl .chk input{width:16px;height:16px}
.tbl .num,.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.row-link{color:var(--ink);font-weight:600;text-decoration:none}.row-link:hover{color:var(--blue)}
.thumb{width:44px;height:44px;border-radius:8px;object-fit:cover;display:block;background:var(--line2)}.thumb.empty{display:block}
.yes{color:var(--ok)}.ic-inline .ico{color:var(--blue)}
.inline-status{width:auto;padding:5px 8px;font-size:.8rem;border-radius:7px}
.pager{display:flex;justify-content:space-between;align-items:center;margin-top:14px;gap:10px}.pager div{display:flex;gap:6px}
.empty-state{text-align:center;padding:48px 20px}.empty-state>.ico{width:40px;height:40px;color:var(--muted);margin-bottom:8px}
/* forms */
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px 18px}.form-grid.one{grid-template-columns:1fr}
.fld{display:flex;flex-direction:column;gap:6px;min-width:0}.fld.full{grid-column:1/-1}
.fld label,.fld .lbl,.fld>span{font-weight:600;font-size:.84rem;color:var(--ink)}.req{color:#dc2626}
.help{color:var(--muted);font-size:.78rem}.fld .err{color:#dc2626;font-size:.8rem;margin:0}.fld.invalid input,.fld.invalid select,.fld.invalid textarea,.fld.invalid .rte{border-color:#dc2626}
.fld.ro .ro-val{padding:9px 12px;background:var(--line2);border-radius:9px;min-height:40px;color:var(--ink);word-break:break-word}
.fld-bool{flex-direction:row;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border:1px solid var(--line);border-radius:9px}.fld-bool .help{flex-basis:100%}
.fld.inline{flex-direction:row;align-items:center}.fld.inline input{width:140px}
.switch{position:relative;display:inline-block;width:42px;height:24px;flex:none}.switch input{opacity:0;width:0;height:0}.switch span{position:absolute;inset:0;background:#cbd5e1;border-radius:24px;transition:.2s;cursor:pointer}.switch span::before{content:'';position:absolute;width:18px;height:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}.switch input:checked+span{background:var(--blue)}.switch input:checked+span::before{transform:translateX(18px)}.switch input:focus-visible+span{outline:2px solid var(--blue);outline-offset:2px}
.form-foot{display:flex;gap:10px;align-items:center;margin-top:20px;padding-top:16px;border-top:1px solid var(--line);flex-wrap:wrap}.push{margin-left:auto}
.check{display:flex;gap:8px;align-items:center;font-size:.86rem;margin-top:12px}.check input{width:16px;height:16px}
.img-field{display:flex;gap:14px;align-items:flex-start}.img-prev{width:110px;height:84px;border-radius:9px;background:var(--line2);display:grid;place-items:center;overflow:hidden;flex:none;border:1px solid var(--line)}.img-prev img{width:100%;height:100%;object-fit:cover}.img-prev .ico{width:28px;height:28px;color:var(--muted)}
.img-ctl{flex:1;display:flex;flex-direction:column;gap:8px;min-width:0}.img-ctl .row{display:flex;gap:8px}.upl{cursor:pointer}
.icon-preview{display:inline-grid;place-items:center;width:38px;height:38px;border-radius:9px;background:var(--blue-50);color:var(--blue);margin-top:6px}
.rte{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--panel)}
.rte-bar{display:flex;flex-wrap:wrap;gap:3px;padding:7px;border-bottom:1px solid var(--line);background:var(--line2);position:sticky;top:64px;z-index:2}
.rte-bar button{border:1px solid transparent;background:transparent;color:var(--ink);font:600 .76rem inherit;font-family:inherit;padding:5px 8px;border-radius:6px;cursor:pointer}.rte-bar button:hover,.rte-bar button.on{background:var(--panel);border-color:var(--line)}
.rte-area{min-height:340px;max-height:70vh;overflow-y:auto;padding:16px 20px;outline:none;color:var(--ink);line-height:1.7;font-size:.95rem}
.rte-area h2{font-size:1.35rem;margin:1.2em 0 .5em}.rte-area h3{font-size:1.1rem;margin:1em 0 .4em}.rte-area img{max-width:100%;border-radius:8px}.rte-area blockquote{border-left:4px solid var(--blue);margin:1em 0;padding:8px 16px;background:var(--blue-50)}
.rte-area table{border-collapse:collapse;width:100%}.rte-area td,.rte-area th{border:1px solid var(--line);padding:6px 10px}
.rte-area .tip,.rte-area .note,.rte-area .warning{padding:10px 14px;border-radius:8px;border:1px solid}.rte-area .tip{background:var(--ok-bg);border-color:#a7f3d0}.rte-area .note{background:var(--blue-50);border-color:#bfdbfe}.rte-area .warning{background:var(--warn-bg);border-color:#fde68a}
.rte-src{min-height:340px;border:0;border-radius:0;font-family:ui-monospace,Consolas,monospace;font-size:.82rem}
.files{list-style:none;margin:0;padding:0;display:grid;gap:8px}.files li{display:flex;gap:8px;align-items:center}.files small{color:var(--muted)}
.alert{display:flex;gap:12px;align-items:flex-start;padding:13px 16px;border-radius:10px;border:1px solid;margin-bottom:16px;font-size:.88rem}.alert .ico{margin-top:1px}
.alert-ok{background:var(--ok-bg);border-color:#a7f3d0;color:var(--ok)}.alert-err{background:var(--err-bg);border-color:#fecaca;color:var(--err)}.alert-warn{background:var(--warn-bg);border-color:#fde68a;color:var(--warn)}.alert-info{background:var(--blue-50);border-color:#bfdbfe;color:#1e40af}
[data-theme=dark] .alert-info{color:#93c5fd;border-color:#1e3a8a}[data-theme=dark] .alert-ok{color:#6ee7b7;border-color:#065f46}[data-theme=dark] .alert-err{color:#fca5a5;border-color:#7f1d1d}[data-theme=dark] .alert-warn{color:#fcd34d;border-color:#78350f}
.split-view{display:grid;grid-template-columns:230px 1fr;gap:18px;align-items:start}
.sub-nav{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:8px;display:grid;gap:2px;position:sticky;top:80px}
.sub-nav a{padding:8px 12px;border-radius:8px;text-decoration:none;color:var(--text);font-size:.87rem}.sub-nav a:hover{background:var(--line2)}.sub-nav a.active{background:var(--blue-50);color:var(--blue);font-weight:600}.sub-nav small{color:var(--muted)}
.items-tbl input{padding:6px 8px;min-width:80px}.items-tbl .in-qty{width:80px}.items-tbl .in-price{width:120px}
.add-row{display:flex;gap:8px;margin-top:12px}.add-row select{flex:1}
.sum-box{display:grid;gap:6px;margin:18px 0;padding:14px;background:var(--line2);border-radius:10px;font-size:.88rem}.sum-box div{display:flex;justify-content:space-between}.sum-box .grand{font-size:1.05rem;border-top:1px solid var(--line);padding-top:8px;margin-top:4px}.sum-box strong{color:var(--ink)}
.narrow{max-width:560px}
.media-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px}
.media{margin:0;border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--panel)}.media img,.media .doc{width:100%;aspect-ratio:4/3;object-fit:cover;display:grid;place-items:center;background:var(--line2);color:var(--muted);font-weight:700;gap:4px}
.media figcaption{padding:10px;display:grid;gap:4px}.media code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}.media small{color:var(--muted)}.media .row{display:flex;justify-content:space-between;align-items:center;margin-top:4px}
/* toasts & modal */
.toasts{position:fixed;right:20px;bottom:20px;z-index:100;display:grid;gap:8px;width:min(380px,calc(100% - 40px))}
.toast{background:#0f172a;color:#fff;padding:12px 16px;border-radius:10px;box-shadow:0 12px 30px -10px rgba(0,0,0,.4);font-size:.88rem;animation:tin .2s ease;border-left:4px solid #22c55e;transition:opacity .3s}.toast.err{border-left-color:#ef4444}.toast.out{opacity:0}
@keyframes tin{from{opacity:0;transform:translateY(8px)}}
.modal{position:fixed;inset:0;background:rgba(2,6,23,.55);display:grid;place-items:center;z-index:200;padding:20px;animation:tin .15s}
.modal-card{background:var(--panel);border-radius:14px;padding:24px;width:min(480px,100%);box-shadow:0 30px 80px -20px rgba(0,0,0,.5);border:1px solid var(--line)}
.modal-card h3{font-size:1.12rem;margin-bottom:10px}.modal-body{margin-bottom:14px;font-size:.9rem}.modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
/* auth */
.auth-page{background:radial-gradient(circle at 70% 0%,#1d4ed855,transparent 50%),#060f1d;min-height:100vh}
.auth{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
.auth-card{background:#fff;color:#334155;border-radius:18px;padding:34px;width:min(420px,100%);box-shadow:0 30px 80px -30px rgba(0,0,0,.6)}
.auth-card h1{color:#0f172a;font-size:1.4rem;margin:22px 0 4px}.auth-card .brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:#0f172a}.auth-card .brand-mark svg,.auth-card .brand-logo{width:40px;height:40px;border-radius:10px}.auth-card .brand-text{display:flex;flex-direction:column;line-height:1.15}.auth-card .brand-text strong{font-family:'Plus Jakarta Sans',sans-serif}.auth-card .brand-text small{font-size:.72rem;color:#64748b}
.auth-card input{background:#fff;color:#0f172a;border-color:#d5dde9;padding:11px 13px}.auth-card .fld span{color:#0f172a}.auth-card .muted{color:#64748b}.auth-card .small{display:flex;gap:6px;align-items:center}
.stack{display:grid;gap:14px;margin-top:20px}.auth-foot a{color:#a9b8cf;font-size:.88rem;text-decoration:none}.auth-foot{margin-top:18px}
/* responsive */
@media (max-width:1200px){.stats{grid-template-columns:repeat(2,1fr)}.grid-3{grid-template-columns:1fr 1fr}}
@media (max-width:960px){
  .app{grid-template-columns:1fr}.side{position:fixed;left:0;top:0;bottom:0;width:270px;z-index:50;transform:translateX(-100%);transition:transform .25s;box-shadow:20px 0 60px -20px rgba(0,0,0,.5)}
  .side-open .side{transform:none}.menu-btn{display:inline-grid}.user .who{display:none}
  .grid-2,.grid-2.wide-left,.grid-3,.split-view{grid-template-columns:1fr}.sub-nav{position:static;grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}
  .content{padding:18px}.top{padding:0 14px}
}
@media (max-width:640px){
  .stats{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}.img-field{flex-direction:column}
  .tbl thead{display:none}.tbl,.tbl tbody,.tbl tr,.tbl td{display:block;width:100%}.tbl tr{border-top:1px solid var(--line);padding:8px 0}.tbl td{border:0;padding:5px 12px;display:flex;justify-content:space-between;gap:12px}.tbl td[data-label]::before{content:attr(data-label);font-weight:600;color:var(--muted);font-size:.78rem}.tbl .act{justify-content:flex-end}
  .top-actions .icon-btn[title="View website"]{display:none}h1{font-size:1.3rem}
}
`;

const SITE_JS = `(${siteClient.toString()})();`;
const ADMIN_JS = `(${adminClient.toString()})();`;
const sendAsset = (type, body) => (req, res) => res.type(type).set('Cache-Control', 'public, max-age=31536000, immutable').send(body);
app.get('/assets/site.css', sendAsset('text/css', SITE_CSS));
app.get('/assets/site.js', sendAsset('application/javascript', SITE_JS));
app.get('/assets/admin.css', sendAsset('text/css', ADMIN_CSS));
app.get('/assets/admin.js', sendAsset('application/javascript', ADMIN_JS));
app.get('/healthz', (req, res) => res.json({ ok: true, uptime: Math.round(process.uptime()) }));

/* ============================== 15. ERRORS & START-UP ============================== */
app.use((req, res) => {
  if (req.originalUrl.startsWith('/api/') || req.originalUrl.startsWith('/admin/api/')) return res.status(404).json({ ok: false, error: 'Not found.' });
  res.status(404).send(notFoundPage(req));
});
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  let status = err.status || err.statusCode || 500, message = err.message;
  if (err instanceof multer.MulterError) {
    status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    message = err.code === 'LIMIT_FILE_SIZE' ? 'A file is too large. Maximum size is 5 MB per file.' : err.code === 'LIMIT_FILE_COUNT' || err.code === 'LIMIT_UNEXPECTED_FILE' ? 'Too many files. You can upload up to 3 files.' : 'Upload error: ' + err.message;
  } else if (err.type === 'entity.too.large') { status = 413; message = 'The submitted data is too large.'; }
  else if (err.type === 'entity.parse.failed') { status = 400; message = 'Invalid request data.'; }
  else if (!(err instanceof HttpError) && status >= 500) { console.error(`[error] ${req.method} ${req.originalUrl}:`, err); message = 'An unexpected error occurred. Please try again.'; }
  if (res.headersSent) return;
  const wantsJson = req.originalUrl.startsWith('/api/') || req.originalUrl.startsWith('/admin/api/') || (req.get('accept') || '').includes('application/json');
  if (wantsJson) return res.status(status).json({ ok: false, error: message, fields: err.fields });
  res.status(status).send(layout(req, { title: 'Error', noindex: true, body: `<section class="section"><div class="container empty">${icon('x')}<h1 style="font-size:2rem">Something went wrong</h1><p>${esc(message)}</p><a class="btn btn-primary" href="/">Back to home</a></div></section>` }));
});

bootstrapAdmin();
if (require.main === module) {
  const server = app.listen(PORT, HOST, () => {
    console.log(`\n  Smart Digital Services is running`);
    console.log(`  Website:  http://localhost:${PORT}`);
    console.log(`  Admin:    http://localhost:${PORT}/admin`);
    console.log(`  Database: ${path.join(DATA_DIR, 'sds.sqlite')}\n`);
  });
  const shutdown = () => { console.log('Shutting down…'); server.close(() => { try { db.close(); } catch { /* ignore */ } process.exit(0); }); setTimeout(() => process.exit(0), 5000).unref(); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
module.exports = app;
