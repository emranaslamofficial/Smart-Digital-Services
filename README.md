# Smart Digital Services (SDS) — Website & Admin Dashboard

A complete business website for Smart Digital Services. It includes a public website, technology blog, Basic Computer Course enrolment, certificate generator & public verification, CCTV services, a CCTV product catalogue with a quotation/invoice builder, Apna Ghar Apni Chat application-assistance form, team, contact/support system and a full admin dashboard. All of it is served from one Node.js server (`server.js`) with a SQLite database.

## Requirements

- **Node.js 22.13 or newer** (Node 24 LTS recommended). The app uses Node's built-in SQLite (`node:sqlite`), so there is **nothing to compile** and no Visual Studio / Python build tools are needed on Windows.

## 1. Install on Windows

1. Install Node.js LTS from https://nodejs.org (tick "Add to PATH" during setup).
2. Open the project folder in File Explorer, click the address bar, type `cmd` and press Enter.
3. Install the dependencies:

```bash
npm install
```

4. Create your configuration file by copying the example:

```bash
copy .env.example .env
```

5. Open `.env` in Notepad and set at least:
   - `ADMIN_EMAIL` and `ADMIN_PASSWORD` (10+ characters) for the first admin account, **or** leave them empty and use the one-time setup page (see below).
   - `DATA_ENCRYPTION_KEY` (recommended). Generate one with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 2. Run locally

```bash
npm start
```

- Website: http://localhost:3000
- Admin dashboard: http://localhost:3000/admin

**First admin account.** If `ADMIN_EMAIL`/`ADMIN_PASSWORD` were set, that account is created on first start. Otherwise the console prints a **one-time setup token** (also saved in `data/setup-token.txt`). Open http://localhost:3000/admin/setup, enter the token and create your admin account.

The database (`data/sds.sqlite`) and all tables are created automatically on first start, with demo content (9 original blog articles, the course, 20 demo CCTV products with editable PKR prices, services and 4 placeholder team members). Restarting the server never deletes data.

## 3. First things to do in the admin

1. **Settings → General**: upload your logo and favicon.
2. **Settings → Contact details**: phone, email, WhatsApp number (format `923001234567`), address.
3. **Settings → SEO**: set *Website URL* to your real domain (used for sitemap and certificate verification links).
4. **Website → Team Members**: replace the placeholder names and upload photos.
5. **CCTV → Products**: adjust prices, stock and images. **Settings → Quotation charges**: installation, delivery and discount rules.
6. **Settings → Certificate design**: signatory name, signature image, optional background.
7. **Settings → Email (SMTP)** (optional): enables email alerts for new submissions. The site works fully without it.

## 4. Deploying to a Node.js host

Works on any VPS (Ubuntu, Windows Server), cPanel "Setup Node.js App", Plesk, Render, Railway and similar.

1. Upload all files **except** `node_modules`, `data` and `uploads` (or use Git).
2. Run `npm install --omit=dev` on the server.
3. Create `.env` with:
   - `NODE_ENV=production`
   - `PORT` as required by your host
   - `BASE_URL=https://www.yourdomain.pk`
   - `TRUST_PROXY=1` when behind Nginx, cPanel/Passenger, Cloudflare or a platform load balancer. This is required for correct client IPs and secure cookies.
   - `DATA_ENCRYPTION_KEY` (the **same** key you used before, if migrating data)
4. Start with `npm start` (cPanel: set the startup file to `server.js`). On a VPS, keep it running with PM2:

```bash
npm install -g pm2
```

```bash
pm2 start server.js --name sds && pm2 save && pm2 startup
```

5. Serve it over **HTTPS** (Let's Encrypt via Nginx/Certbot, or your host's SSL). In production with HTTPS, cookies are marked `Secure` and HSTS is enabled.
6. Health check URL: `/healthz`.

**Persistent storage:** the `data/` folder (database, encryption key) and `uploads/` folder must be on persistent disk. On platforms with ephemeral disks (e.g. Render free tier), attach a persistent volume and point `DATA_DIR` / `UPLOAD_DIR` at it.

**Backups:** regularly back up `data/sds.sqlite`, `data/.data-key` (if you did not set `DATA_ENCRYPTION_KEY`) and `uploads/`. Without the encryption key, stored CNIC numbers cannot be decrypted.

Nginx reverse-proxy example:

```nginx
server {
  server_name www.yourdomain.pk;
  client_max_body_size 20m;
  location / { proxy_pass http://127.0.0.1:3000; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto $scheme; }
}
```

## 5. Quick test deployment on Vercel (temporary data)

Vercel is serverless: only `/tmp` is writable and it is wiped whenever Vercel restarts the function. On Vercel the database and uploads live in `/tmp`, so **all data (admin account, posts, forms, uploads) resets from time to time**. Use Vercel for testing only; use cPanel/VPS for the live site.

1. In Vercel: **Add New → Project → Import** the GitHub repo. Leave Framework Preset as **Other**. No build settings needed (`vercel.json` handles routing).
2. Under **Environment Variables** add:
   - `ADMIN_EMAIL` and `ADMIN_PASSWORD` (10+ characters). These are **required** on Vercel, because the first-run setup page cannot be used there.
   - `DATA_ENCRYPTION_KEY` (64 hex characters, see above)
   - `BASE_URL` = your Vercel URL, e.g. `https://smart-digital-services.vercel.app`
   - `NODE_ENV` = `production`
3. Deploy. The admin dashboard shows a "Vercel test mode" warning as a reminder that data is temporary.

Limits on Vercel: requests over ~4.5 MB are rejected (large document uploads), and if Vercel runs more than one instance at once, each has its own temporary database, so you may occasionally be logged out.

`api/index.js`, `vercel.json` and `public/` exist only for Vercel; cPanel and VPS ignore them.

## Project structure

| Path | Purpose |
|---|---|
| `server.js` | The entire application: config, DB schema & seed, security, public pages, APIs, admin dashboard, client JS & CSS |
| `package.json` | Dependencies and `npm start` script |
| `.env` | Your secrets & configuration (never commit it) |
| `data/` | SQLite database, encryption key, first-run token (auto-created) |
| `uploads/images` | Public images (logo, blog, products, team) |
| `uploads/documents` | Public PDF documents uploaded by admins |
| `uploads/private` | **Private** scheme documents. Not web-accessible; admin download only |

## Security summary

- Passwords hashed with scrypt; random session tokens stored hashed; 2-hour idle and 12-hour absolute session expiry; HttpOnly + SameSite=Strict admin cookie (Secure over HTTPS).
- CSRF protection (token + Origin check) on every form and admin action.
- Parameterised SQL everywhere; HTML escaping on output; blog HTML sanitised with an allow-list; strict Content-Security-Policy (no inline scripts) via Helmet.
- Rate limiting on login (per IP and per email) and all public forms; honeypot spam trap.
- Uploads: size limits (3 MB images, 5 MB documents, max 3 per scheme form), file type verified by content (magic bytes), random file names, SVG/HTML refused.
- CNIC encrypted at rest (AES-256-GCM), masked in lists, searchable via a keyed hash, decryption & document downloads logged in the activity log. Scheme data is restricted to *Administrator* role (Editors cannot see it). CSV exports guard against spreadsheet formula injection.
- No hard-coded passwords: first admin comes from `.env` or the one-time setup token.

## Notes

- Quotation and certificate "PDF" output uses the browser's **Print → Save as PDF** (A4, print-optimised layouts).
- Blog covers and product images are original, auto-generated SVG graphics until you upload your own photos. Social platforms prefer JPG/PNG share images, so set a default share image in *Settings → SEO*.
- Testimonials start empty. If you add sample ones, tick *Demo / sample content* and they are publicly labelled "Demo content".
- SDS is presented as a private assistance provider on the Apna Ghar Apni Chat page; no application is ever submitted automatically.
