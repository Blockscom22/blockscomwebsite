# AWS Ubuntu + Nginx Deploy

This app is now set up to run well behind nginx on Ubuntu:
- reverse-proxy aware via `TRUST_PROXY`
- graceful shutdown for `systemd`
- health check endpoint at `/healthz`
- nginx sample config with `200m` upload limit for studio utilities

## 1. Server packages

```bash
sudo apt update
sudo apt install -y nginx curl
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node -v
npm -v
```

## 2. App directory

```bash
sudo mkdir -p /var/www/blockscomwebsite
sudo chown -R ubuntu:www-data /var/www/blockscomwebsite
```

Upload this project into `/var/www/blockscomwebsite`, then install production deps:

```bash
cd /var/www/blockscomwebsite
npm ci --omit=dev
```

## 3. Environment file

Create `/etc/blockscomwebsite.env`:

```bash
sudo nano /etc/blockscomwebsite.env
```

Add your real secrets there, for example:

```env
NODE_ENV=production
PORT=10000
TRUST_PROXY=1
TOKEN_ENCRYPTION_KEY=your-long-random-key
SUPABASE_URL=...
SUPABASE_ANON_KEY=...
SUPABASE_SERVICE_ROLE_KEY=...
OPENROUTER_API_KEY=...
OPENROUTER_API_KEY_UNLIMITED=...
OPENROUTER_API_KEY_LIMITED=...
KLING_ACCESS_KEY=...
KLING_SECRET_KEY=...
FB_APP_SECRET=...
```

Lock it down:

```bash
sudo chmod 600 /etc/blockscomwebsite.env
```

## 4. Systemd service

Copy the provided service file:

```bash
sudo cp deploy/systemd/blockscom.service /etc/systemd/system/blockscom.service
sudo systemctl daemon-reload
sudo systemctl enable --now blockscom
sudo systemctl status blockscom
```

## 5. Nginx

Copy the nginx site config:

```bash
sudo cp deploy/nginx/blockscom.conf /etc/nginx/sites-available/blockscom.conf
```

Edit `server_name` first, then enable it:

```bash
sudo ln -s /etc/nginx/sites-available/blockscom.conf /etc/nginx/sites-enabled/blockscom.conf
sudo nginx -t
sudo systemctl reload nginx
```

## 6. TLS

After DNS points to the server, install HTTPS with Certbot.

If you want both the main site and `tiktok.ramilflaviano.art` covered by the same certificate, run:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx --cert-name blockscom.xyz \
  -d blockscom.xyz \
  -d www.blockscom.xyz \
  -d tiktok.ramilflaviano.art
```

If `blockscom.xyz` already has a certificate and you are adding the subdomain later, expand it explicitly:

```bash
sudo certbot --nginx --cert-name blockscom.xyz --expand \
  -d blockscom.xyz \
  -d www.blockscom.xyz \
  -d tiktok.ramilflaviano.art
```

If `tiktok.ramilflaviano.art` should use a separate certificate instead, use:

```bash
sudo certbot --nginx -d tiktok.ramilflaviano.art
```

## 7. Verify

```bash
curl http://127.0.0.1:10000/healthz
curl https://yourdomain.com/healthz
```

Expected response:

```json
{"ok":true,"service":"blockscomwebsite","uptime":123}
```

## 8. Notes

- This repo still contains legacy `blockimagen/` test files with hardcoded-looking credentials. They should be removed or rotated before a real production rollout.
- `FB_APP_SECRET` must be set in production or webhook signature verification stays disabled.
- The linked Supabase project currently appears behind the application schema expected by `server.js`. Make sure the production database actually contains the main SaaS tables before go-live.
