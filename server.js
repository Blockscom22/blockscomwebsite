const express = require('express');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Multer — memory storage for image uploads (max 5MB per file, 60MB total for multi-upload)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 10, fieldSize: 10 * 1024 * 1024 } });

// Environment
const IS_PROD = process.env.NODE_ENV === 'production' || process.env.VERCEL === '1';
function debugLog(...args) { if (!IS_PROD) console.log(...args); }

const app = express();

// CORS — allow known domains + widget origins
const ALLOWED_ORIGINS = [
  'https://www.blockscom.xyz',
  'https://blockscom.xyz',
  'http://localhost:3000',
  'http://localhost:10000'
];

app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  // Allow listed origins OR any origin for the widget/webhook public endpoints
  const isPublicPath = req.path.startsWith('/api/widget') || req.path.startsWith('/webhook') || req.path.startsWith('/blockscom-chat');
  if (ALLOWED_ORIGINS.includes(origin) || isPublicPath) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    // Only disable cache for HTML and config files (they contain dynamic content)
    if (filePath.endsWith('.html') || filePath.endsWith('config-client.js')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    } else if (filePath.endsWith('.js') || filePath.endsWith('.css')) {
      // Cache static JS/CSS for 1 hour (browser will still revalidate)
      res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
    }
  }
}));

// Load Env
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://placeholder.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder';
const PORT = process.env.PORT || 3000;

if (!process.env.SUPABASE_URL) {
  console.warn("WARNING: SUPABASE_URL is missing! Requests to DB will fail. Add it in Vercel settings.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Secret encryption helpers (AES-256-GCM)
const ENC_KEY = crypto.createHash('sha256').update(process.env.TOKEN_ENCRYPTION_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || 'blockscom-default-key').digest();
if (!process.env.TOKEN_ENCRYPTION_KEY) {
  console.warn("SECURITY WARNING: TOKEN_ENCRYPTION_KEY is not set. Falling back to SUPABASE_SERVICE_ROLE_KEY or default string for encryption. Set a dedicated TOKEN_ENCRYPTION_KEY in production.");
}

// Simple in-memory rate limiter for public endpoints
const rateLimitMap = new Map();
function rateLimit(windowMs, maxRequests) {
  return (req, res, next) => {
    const key = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    const now = Date.now();
    const entry = rateLimitMap.get(key);
    if (!entry || now - entry.start > windowMs) {
      rateLimitMap.set(key, { start: now, count: 1 });
      return next();
    }
    entry.count++;
    if (entry.count > maxRequests) {
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    next();
  };
}
// Clean up rate limit entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap) {
    if (now - entry.start > 300000) rateLimitMap.delete(key);
  }
}, 300000);

// Widget config cache (60s TTL) — avoids hitting Supabase on every page load
const widgetConfigCache = new Map();
const WIDGET_CONFIG_TTL = 60000; // 60 seconds
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of widgetConfigCache) {
    if (now - entry.ts > WIDGET_CONFIG_TTL) widgetConfigCache.delete(key);
  }
}, 60000);

// KB + Inventory context cache (45s TTL) — avoids re-fetching during burst conversations
const kbCache = new Map();
const KB_CACHE_TTL = 45000; // 45 seconds
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of kbCache) {
    if (now - entry.ts > KB_CACHE_TTL) kbCache.delete(key);
  }
}, 60000);

// Facebook Webhook Signature Verification (X-Hub-Signature-256)
const FB_APP_SECRET = process.env.FB_APP_SECRET || '';
if (!FB_APP_SECRET) {
  console.warn('SECURITY WARNING: FB_APP_SECRET is not set. Webhook signature verification is DISABLED. Set FB_APP_SECRET in your environment variables for production.');
}

function verifyFbSignature(req) {
  if (!FB_APP_SECRET) return true; // Skip if not configured (dev mode)
  const signature = req.headers['x-hub-signature-256'];
  if (!signature) return false;
  const expectedHash = 'sha256=' + crypto.createHmac('sha256', FB_APP_SECRET)
    .update(JSON.stringify(req.body))
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedHash));
}

function encryptSecret(plain) {
  if (!plain) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:${iv.toString('base64')}:${tag.toString('base64')}:${enc.toString('base64')}`;
}

function decryptSecret(value) {
  if (!value) {
    console.warn('[DEBUG] decryptSecret: No value provided');
    return '';
  }
  if (!String(value).startsWith('enc:')) {
    console.log('[DEBUG] decryptSecret: Value does not start with enc:, returning as-is');
    return String(value);
  }
  try {
    const parts = String(value).split(':');
    debugLog(`[DEBUG] decryptSecret: Splitting value into ${parts.length} parts`);
    const [, ivB64, tagB64, dataB64] = parts;
    if (!ivB64 || !tagB64 || !dataB64) {
      console.error('[ERROR] decryptSecret: Missing parts');
      return '';
    }
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const data = Buffer.from(dataB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(data), decipher.final()]);
    const result = dec.toString('utf8');
    debugLog(`[DEBUG] decryptSecret: Decryption successful, result length: ${result.length}`);
    return result;
  } catch (err) {
    console.error('[ERROR] Decryption failed:', err.message);
    return '';
  }
}

function maskSecret(value) {
  const plain = decryptSecret(value);
  if (!plain) return '';
  return plain.length <= 4 ? '****' : `***${plain.slice(-4)}`;
}

function isMasked(value) {
  return typeof value === 'string' && value.startsWith('***');
}

// ==================== SAAS AUTH MIDDLEWARE ====================

// In-memory profile cache (30s TTL) to avoid double DB call on every request
const profileCache = new Map();
const PROFILE_CACHE_TTL = 30000; // 30 seconds

function getCachedProfile(userId) {
  const entry = profileCache.get(userId);
  if (entry && Date.now() - entry.ts < PROFILE_CACHE_TTL) return entry.profile;
  return null;
}
function setCachedProfile(userId, profile) {
  profileCache.set(userId, { profile, ts: Date.now() });
}
// Clean up expired profile cache entries every 60s
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of profileCache) {
    if (now - entry.ts > PROFILE_CACHE_TTL) profileCache.delete(key);
  }
}, 60000);

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No auth header' });

  const token = authHeader.replace('Bearer ', '');
  const { data: { user }, error } = await supabase.auth.getUser(token);

  if (error || !user) return res.status(401).json({ error: 'Invalid session' });

  // Check profile cache first
  let profile = getCachedProfile(user.id);
  if (!profile) {
    const { data: dbProfile } = await supabase.from('profiles').select('*').eq('id', user.id).single();

    if (!dbProfile) {
      const { data: newProfile } = await supabase.from('profiles').insert([{ id: user.id, email: user.email, credits: 50, role: 'FREE' }]).select().single();
      profile = newProfile;
    } else {
      profile = dbProfile;
    }
    setCachedProfile(user.id, profile);
  }

  req.user = { ...user, profile };
  next();
}

// ==================== ROUTES ====================

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public/dashboard.html')));
app.get('/fb-setup-docs.html', (req, res) => res.sendFile(path.join(__dirname, 'public/fb-setup-docs.html')));

// API: Get Current User
app.get('/api/me', requireAuth, (req, res) => res.json(req.user.profile));

// API: Update User PIN (hashed)
app.put('/api/me/pin', requireAuth, async (req, res) => {
  const { pin } = req.body;
  if (!pin || pin.length < 6) return res.status(400).json({ error: 'PIN must be at least 6 digits.' });
  const hashedPin = crypto.createHash('sha256').update(String(pin)).digest('hex');
  const { error } = await supabase.from('profiles').update({ pin_code: hashedPin }).eq('id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// API: Update User Currency
app.put('/api/me/currency', requireAuth, async (req, res) => {
  const { currency } = req.body;
  const { error } = await supabase.from('profiles').update({ currency: currency }).eq('id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// API: Get My Pages
app.get('/api/pages', requireAuth, async (req, res) => {
  const query = supabase.from('fb_pages').select('*').order('created_at', { ascending: false });
  query.eq('profile_id', req.user.id);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  const masked = data.map(p => ({
    ...p,
    access_token: maskSecret(p.access_token),
    verify_token: maskSecret(p.verify_token)
  }));
  res.json(masked);
});

// API: Update Page Theme
app.put('/api/pages/theme', requireAuth, async (req, res) => {
  const { id, theme } = req.body;
  if (!id || !theme) return res.status(400).json({ error: 'Missing id or theme' });

  const { error } = await supabase.from('fb_pages').update({ widget_theme: theme }).eq('id', id).eq('profile_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// API: Add/Update Page
app.post('/api/pages', requireAuth, async (req, res) => {
  try {
    const { id, name, fb_page_id, verify_token, access_token, ai_model, knowledge_base, widget_name } = req.body;

    // Enforce model restrictions for FREE users
    const FREE_MODELS = ['arcee-ai/trinity-large-preview:free', 'stepfun/step-3.5-flash:free'];
    const resolvedModel = (req.user.profile.role === 'FREE' && !FREE_MODELS.includes(ai_model))
      ? 'arcee-ai/trinity-large-preview:free'
      : ai_model;

    if (id) {
      // Update
      const updates = { name, fb_page_id, ai_model: resolvedModel, knowledge_base, widget_name };
      if (verify_token && !isMasked(verify_token)) updates.verify_token = encryptSecret(verify_token);
      if (access_token && !isMasked(access_token)) updates.access_token = encryptSecret(access_token);

      const { error } = await supabase.from('fb_pages').update(updates).eq('id', id).eq('profile_id', req.user.id);
      if (error) throw error;
    } else {
      // Insert — return the new row so the client gets the real system ID
      const { data: newPage, error } = await supabase.from('fb_pages').insert([{
        profile_id: req.user.id,
        name,
        fb_page_id,
        verify_token: encryptSecret(verify_token),
        access_token: encryptSecret(access_token),
        ai_model: resolvedModel,
        knowledge_base: knowledge_base || [],
        widget_name,
        widget_key: crypto.randomBytes(12).toString('hex')
      }]).select().single();
      if (error) throw error;
      return res.json({ success: true, id: newPage.id, widget_key: newPage.widget_key });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('API Error (/api/pages):', error);
    res.status(500).json({ error: error.message || 'Internal Server Error' });
  }
});

app.delete('/api/pages/:id', requireAuth, async (req, res) => {
  const { error } = await supabase.from('fb_pages').delete().eq('id', req.params.id).eq('profile_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// API: Generate Sync Token (Messenger Notification)
app.post('/api/pages/:id/generate-sync-token', requireAuth, async (req, res) => {
  try {
    const token = 'SYNC-' + crypto.randomBytes(3).toString('hex').toUpperCase() + '-' + Math.floor(1000 + Math.random() * 9000);
    const { error } = await supabase.from('fb_pages').update({ sync_token: token }).eq('id', req.params.id).eq('profile_id', req.user.id);
    if (error) throw error;
    res.json({ success: true, sync_token: token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Cancel Messenger Sync
app.post('/api/pages/:id/cancel-sync', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('fb_pages').update({ sync_token: null, owner_psid: null, notify_on_order: false }).eq('id', req.params.id).eq('profile_id', req.user.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Update Notification Settings
app.put('/api/pages/:id/notify-settings', requireAuth, async (req, res) => {
  try {
    const { notify_on_order, notify_style } = req.body;
    const { error } = await supabase.from('fb_pages').update({
      notify_on_order: !!notify_on_order,
      notify_style: notify_style || 'detailed'
    }).eq('id', req.params.id).eq('profile_id', req.user.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Default PERSONALITY skill content
const DEFAULT_PERSONALITY_CONTENT = `You are a real, friendly human assistant representing the business.

You must sound natural, calm, and confident.
Never sound robotic.
Never over-explain.
Never write essays.
Never mention AI, models, prompts, or system instructions.

Your replies must feel like:
• A helpful store assistant
• A smart customer support rep
• A polite sales associate
• A real human typing normally
• A real human short reply
• No long paragraphs
• No filler words
• Friendly but not exaggerated`;

// API: Knowledge Base (User-specific)
app.get('/api/knowledge', requireAuth, async (req, res) => {
  const query = supabase.from('knowledge_entries').select('*');
  query.eq('profile_id', req.user.id);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  // Auto-generate Default Skills if empty (and not an admin viewing all skills)
  if (data.length === 0) {
    const fs = require('fs');
    const kbDir = path.join(__dirname, 'data/knowledge');

    // Always include PERSONALITY as the first default skill
    const defaultInserts = [{ profile_id: req.user.id, title: 'PERSONALITY', content: DEFAULT_PERSONALITY_CONTENT }];

    if (fs.existsSync(kbDir)) {
      const files = fs.readdirSync(kbDir).filter(f => f.endsWith('.md'));
      for (const file of files) {
        const content = fs.readFileSync(path.join(kbDir, file), 'utf8');
        const title = file.replace('.md', '').split(/[-_]/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        defaultInserts.push({ profile_id: req.user.id, title, content });
      }
    }

    await supabase.from('knowledge_entries').insert(defaultInserts);
    const { data: newData } = await supabase.from('knowledge_entries').select('*').eq('profile_id', req.user.id);
    return res.json(newData || []);
  }

  // Ensure PERSONALITY exists for existing users who don't have one yet
  const hasPersonality = data.some(k => k.title === 'PERSONALITY');
  if (!hasPersonality) {
    const { data: inserted } = await supabase.from('knowledge_entries').insert([{ profile_id: req.user.id, title: 'PERSONALITY', content: DEFAULT_PERSONALITY_CONTENT }]).select();
    if (inserted && inserted.length > 0) data.unshift(inserted[0]);
  }

  res.json(data);
});

app.post('/api/knowledge', requireAuth, async (req, res) => {
  const { id, title, content } = req.body;

  // Content size limit: 50KB max
  if (content && content.length > 51200) {
    return res.status(400).json({ error: 'Knowledge base content exceeds maximum size of 50KB.' });
  }
  // Title size limit: 200 chars max
  if (title && title.length > 200) {
    return res.status(400).json({ error: 'Title exceeds maximum length of 200 characters.' });
  }

  let result;

  if (id) {
    result = await supabase.from('knowledge_entries').update({ title, content }).eq('id', id).eq('profile_id', req.user.id);
  } else {
    // Check limits before inserting a new skill
    const roleLimits = {
      'FREE': 3,
      'PREMIUM': 10,
      'ENTERPRISE': 20,
      'ADMIN': 99999
    };

    const userRole = req.user.profile.role || 'FREE';
    const limit = roleLimits[userRole] || 1;

    const { count, error: countErr } = await supabase
      .from('knowledge_entries')
      .select('*', { count: 'exact', head: true })
      .eq('profile_id', req.user.id);

    if (countErr) {
      return res.status(500).json({ error: countErr.message });
    }

    if (count >= limit) {
      return res.status(403).json({ error: `Your current tier (${userRole}) is limited to ${limit} Knowledge Base item(s). Please upgrade to add more.` });
    }

    result = await supabase.from('knowledge_entries').insert([{ profile_id: req.user.id, title, content }]);
  }

  if (result.error) return res.status(500).json({ error: result.error.message });
  res.json({ success: true });
});

app.delete('/api/knowledge/:id', requireAuth, async (req, res) => {
  // Prevent deletion of the PERSONALITY skill
  const { data: entry } = await supabase.from('knowledge_entries').select('title').eq('id', req.params.id).eq('profile_id', req.user.id).single();
  if (entry && entry.title === 'PERSONALITY') {
    return res.status(403).json({ error: 'The PERSONALITY skill cannot be deleted. It defines your chatbot\'s tone and behavior.' });
  }
  const { error } = await supabase.from('knowledge_entries').delete().eq('id', req.params.id).eq('profile_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// API: Orders (User-specific)
app.get('/api/orders', requireAuth, async (req, res) => {
  const query = supabase.from('orders').select('*, fb_pages(fb_page_id)').order('created_at', { ascending: false });
  query.eq('profile_id', req.user.id);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/orders/:id/status', requireAuth, async (req, res) => {
  const { status } = req.body;
  const { error } = await supabase.from('orders').update({ status }).eq('id', req.params.id).eq('profile_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.delete('/api/orders/:id', requireAuth, async (req, res) => {
  const { error } = await supabase.from('orders').delete().eq('id', req.params.id).eq('profile_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// API: Import Skills from Local Files
app.post('/api/kb/scan-files', requireAuth, async (req, res) => {
  try {
    const fs = require('fs');
    const kbDir = path.join(__dirname, 'data/knowledge');
    if (!fs.existsSync(kbDir)) return res.json({ success: true, count: 0 });

    const files = fs.readdirSync(kbDir).filter(f => f.endsWith('.md'));
    let count = 0;

    for (const file of files) {
      const content = fs.readFileSync(path.join(kbDir, file), 'utf8');
      const title = file.replace('.md', '').split(/[-_]/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');

      // Check if already exists
      const { data: existing } = await supabase.from('knowledge_entries').select('id').eq('profile_id', req.user.id).eq('title', title).single();

      if (!existing) {
        await supabase.from('knowledge_entries').insert([{ profile_id: req.user.id, title, content }]);
        count++;
      }
    }
    res.json({ success: true, count });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API: Import KB from uploaded .md files (with prompt injection sanitization)
app.post('/api/kb/import', requireAuth, async (req, res) => {
  try {
    const { entries } = req.body; // [{title, content}, ...]
    if (!Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ error: 'No entries provided' });
    }

    // Check role limits
    const roleLimits = { 'FREE': 3, 'PREMIUM': 10, 'ENTERPRISE': 20, 'ADMIN': 99999 };
    const userRole = req.user.profile.role || 'FREE';
    const limit = roleLimits[userRole] || 3;

    const { count: existing } = await supabase
      .from('knowledge_entries')
      .select('*', { count: 'exact', head: true })
      .eq('profile_id', req.user.id);

    const available = limit - (existing || 0);
    if (available <= 0) {
      return res.status(403).json({ error: `Your ${userRole} tier has reached its limit of ${limit} knowledge entries.` });
    }

    // Sanitize and import (up to available slots)
    const toImport = entries.slice(0, available);
    let imported = 0;

    for (const entry of toImport) {
      let title = String(entry.title || '').trim().substring(0, 200);
      let content = String(entry.content || '').trim();

      if (!title || !content) continue;

      // Prompt injection sanitization
      // Remove lines that try to override system behavior
      const dangerousPatterns = [
        /^\s*(system|assistant|user)\s*:/gim,
        /ignore\s+(all\s+)?previous\s+instructions/gi,
        /ignore\s+(all\s+)?above\s+instructions/gi,
        /you\s+are\s+now\s+(?:a|an|the)\s+(?:new|different)/gi,
        /forget\s+(?:all|your|everything|previous)/gi,
        /override\s+(?:system|your|all)/gi,
        /disregard\s+(?:all|your|previous)/gi,
        /new\s+instructions?\s*:/gi,
        /\[\s*SYSTEM\s*\]/gi,
        /\{\{.*?\}\}/g,
        /<\|.*?\|>/g
      ];

      for (const pattern of dangerousPatterns) {
        content = content.replace(pattern, '[REMOVED]');
      }

      // Check for duplicate title
      const { data: dup } = await supabase.from('knowledge_entries')
        .select('id').eq('profile_id', req.user.id).eq('title', title).single();

      if (!dup) {
        await supabase.from('knowledge_entries').insert([{ profile_id: req.user.id, title, content }]);
        imported++;
      }
    }

    res.json({ success: true, imported, skipped: toImport.length - imported });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== FLEXIBLE INVENTORY SYSTEM ====================

// Helper: role-based spreadsheet limits
const TABLE_LIMITS = { FREE: 1, PREMIUM: 10, ENTERPRISE: 999999, ADMIN: 999999 };

// Helper: currency symbols map
const CURRENCY_SYMBOLS = { USD: '$', PHP: '₱', EUR: '€', GBP: '£', JPY: '¥' };

// Helper: sync an inventory table to its auto-generated KB entry
async function syncInventoryToKb(profileId, tableId) {
  try {
    const { data: table } = await supabase.from('inventory_tables').select('*').eq('id', tableId).single();
    if (!table) return;
    const { data: rows } = await supabase.from('inventory_rows').select('*').eq('table_id', tableId).order('created_at');
    // Fetch user's default currency
    const { data: profile } = await supabase.from('profiles').select('currency').eq('id', profileId).single();
    const userCurrency = profile?.currency || 'PHP';
    const currencySymbol = CURRENCY_SYMBOLS[userCurrency] || userCurrency;
    const columns = table.columns || [];
    const kbTitle = `Inventory: ${table.name}`;
    let md = `# ${table.name}\n\n> All prices in this inventory are in ${userCurrency} (${currencySymbol}).\n\n`;
    if (columns.length > 0) {
      md += '| ' + columns.map(c => c.label).join(' | ') + ' |\n';
      md += '| ' + columns.map(() => '---').join(' | ') + ' |\n';
      (rows || []).forEach(r => {
        md += '| ' + columns.map(c => String(r.data[c.key] ?? '')).join(' | ') + ' |\n';
      });
    }
    md += `\n<!-- DATA_JSON -->\n\`\`\`json\n${JSON.stringify({ columns, rows: (rows || []).map(r => r.data) }, null, 2)}\n\`\`\`\n<!-- /DATA_JSON -->`;
    // Upsert KB entry
    const { data: existing } = await supabase.from('knowledge_entries').select('id').eq('profile_id', profileId).eq('title', kbTitle).single();
    if (existing) {
      await supabase.from('knowledge_entries').update({ content: md }).eq('id', existing.id);
    } else {
      await supabase.from('knowledge_entries').insert([{ profile_id: profileId, title: kbTitle, content: md }]);
    }
  } catch (e) { console.error('syncInventoryToKb error:', e.message); }
}

// API: List user's inventory tables
app.get('/api/inventory/tables', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('inventory_tables').select('*').eq('profile_id', req.user.id).order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// API: Create or update an inventory table
app.post('/api/inventory/tables', requireAuth, async (req, res) => {
  try {
    const { id, name, columns } = req.body;
    if (!name || !columns || !Array.isArray(columns)) return res.status(400).json({ error: 'name and columns required' });
    if (name.length > 100) return res.status(400).json({ error: 'Table name too long (max 100)' });
    if (columns.length > 20) return res.status(400).json({ error: 'Too many columns (max 20)' });

    if (id) {
      // Update existing
      const { data, error } = await supabase.from('inventory_tables').update({ name, columns }).eq('id', id).eq('profile_id', req.user.id).select().single();
      if (error) return res.status(500).json({ error: error.message });
      await syncInventoryToKb(req.user.id, id);
      return res.json(data);
    }

    // Create new — check limits
    const role = req.user.profile.role || 'FREE';
    const limit = TABLE_LIMITS[role] || 1;
    const { count } = await supabase.from('inventory_tables').select('*', { count: 'exact', head: true }).eq('profile_id', req.user.id);
    if (count >= limit) return res.status(403).json({ error: `Your ${role} tier is limited to ${limit} spreadsheet(s). Please upgrade.` });

    const { data, error } = await supabase.from('inventory_tables').insert([{ profile_id: req.user.id, name, columns }]).select().single();
    if (error) return res.status(500).json({ error: error.message });
    // Auto-create KB entry
    await syncInventoryToKb(req.user.id, data.id);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// API: Delete an inventory table (cascades rows, removes KB)
app.delete('/api/inventory/tables/:id', requireAuth, async (req, res) => {
  try {
    const { data: table } = await supabase.from('inventory_tables').select('name').eq('id', req.params.id).eq('profile_id', req.user.id).single();
    if (!table) return res.status(404).json({ error: 'Not found' });
    // Delete the table (CASCADE deletes rows)
    const { error } = await supabase.from('inventory_tables').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    // Delete associated KB entry
    await supabase.from('knowledge_entries').delete().eq('profile_id', req.user.id).eq('title', `Inventory: ${table.name}`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// API: Get rows for a table
app.get('/api/inventory/tables/:id/rows', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('inventory_rows').select('*').eq('table_id', req.params.id).eq('profile_id', req.user.id).order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// API: Create or update a row
app.post('/api/inventory/tables/:id/rows', requireAuth, async (req, res) => {
  try {
    const { rowId, data: rowData } = req.body;
    if (!rowData || typeof rowData !== 'object') return res.status(400).json({ error: 'data required' });
    if (rowId) {
      const { data, error } = await supabase.from('inventory_rows').update({ data: rowData }).eq('id', rowId).eq('profile_id', req.user.id).select().single();
      if (error) return res.status(500).json({ error: error.message });
      await syncInventoryToKb(req.user.id, req.params.id);
      return res.json(data);
    }
    const { data, error } = await supabase.from('inventory_rows').insert([{ table_id: req.params.id, profile_id: req.user.id, data: rowData }]).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await syncInventoryToKb(req.user.id, req.params.id);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// API: Bulk save rows (for inline editing)
app.put('/api/inventory/tables/:id/rows', requireAuth, async (req, res) => {
  try {
    const { rows } = req.body; // [{ id?, data }]
    if (!Array.isArray(rows)) return res.status(400).json({ error: 'rows array required' });
    for (const row of rows) {
      if (row.id) {
        await supabase.from('inventory_rows').update({ data: row.data }).eq('id', row.id).eq('profile_id', req.user.id);
      } else {
        await supabase.from('inventory_rows').insert([{ table_id: req.params.id, profile_id: req.user.id, data: row.data }]);
      }
    }
    await syncInventoryToKb(req.user.id, req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// API: Delete a row
app.delete('/api/inventory/rows/:id', requireAuth, async (req, res) => {
  try {
    const { data: row } = await supabase.from('inventory_rows').select('table_id').eq('id', req.params.id).eq('profile_id', req.user.id).single();
    if (!row) return res.status(404).json({ error: 'Not found' });
    const { error } = await supabase.from('inventory_rows').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    await syncInventoryToKb(req.user.id, row.table_id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// API: Force sync inventory table to KB
app.post('/api/inventory/tables/:id/sync', requireAuth, async (req, res) => {
  await syncInventoryToKb(req.user.id, req.params.id);
  res.json({ success: true });
});

// API: AI-powered import for a specific inventory table
app.post('/api/inventory/tables/:id/import', requireAuth, async (req, res) => {
  try {
    const { fileData } = req.body;
    if (!fileData) return res.status(400).json({ error: 'No file data provided' });
    const resolvedApiKey = process.env.OPENROUTER_API_KEY;
    if (!resolvedApiKey) return res.status(500).json({ error: 'OpenRouter API key not configured.' });

    // Fetch the table's column definitions
    const { data: table } = await supabase.from('inventory_tables').select('columns').eq('id', req.params.id).eq('profile_id', req.user.id).single();
    if (!table) return res.status(404).json({ error: 'Table not found' });
    const colDefs = (table.columns || []).map(c => `"${c.key}" (${c.label}, type: ${c.type})`).join(', ');

    const aiRes = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: 'openai/gpt-5.2',
      messages: [
        {
          role: 'system', content: `You are a data parsing assistant. Extract rows from raw text/CSV and return a STRICT JSON array.

The target table has these columns: ${colDefs}

Return format: [ { "${(table.columns[0] || { key: 'col_1' }).key}": value, ... }, ... ]
Rules:
1. Match data to the closest column by meaning.
2. number types must be numeric. boolean types must be true/false.
3. Do NOT wrap in markdown. Return raw JSON array only.
4. If unreadable, return: {"error": true, "message": "Could not parse the data."}` },
        { role: 'user', content: String(fileData).substring(0, 10000) }
      ]
    }, { headers: { 'Authorization': `Bearer ${resolvedApiKey}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://www.blockscom.xyz', 'X-Title': 'Blockscom AI' } });

    let reply = aiRes.data?.choices?.[0]?.message?.content?.trim() || '';
    if (reply.startsWith('```')) reply = reply.replace(/^```json?/i, '').replace(/```$/, '').trim();
    const parsed = JSON.parse(reply);
    if (parsed.error) return res.status(400).json(parsed);
    if (!Array.isArray(parsed)) throw new Error('AI did not return a valid array.');

    // Insert rows
    const inserts = parsed.map(row => ({ table_id: req.params.id, profile_id: req.user.id, data: row }));
    const { error: insertErr } = await supabase.from('inventory_rows').insert(inserts);
    if (insertErr) throw new Error(insertErr.message);
    await syncInventoryToKb(req.user.id, req.params.id);
    res.json({ success: true, imported: parsed.length });
  } catch (error) {
    console.error('Inventory Import Error:', error.message);
    res.status(500).json({ error: 'Failed to process file.' });
  }
});

// ==================== USER IMAGES ====================

// Helper: role-based image limits
const IMAGE_LIMITS = { FREE: 3, PREMIUM: 50, ENTERPRISE: 999999, ADMIN: 999999 };

// API: List user's images
app.get('/api/images', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('user_images').select('*').eq('profile_id', req.user.id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });

  const role = req.user.profile.role || 'FREE';
  const limit = IMAGE_LIMITS[role] || 3;
  res.json({ images: data || [], limit, used: (data || []).length });
});

// API: Upload image (single)
app.post('/api/images/upload', requireAuth, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image file provided.' });

    // Check mime type
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowed.includes(req.file.mimetype)) return res.status(400).json({ error: 'Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.' });

    // Check limits
    const role = req.user.profile.role || 'FREE';
    const limit = IMAGE_LIMITS[role] || 3;
    const { count, error: countErr } = await supabase.from('user_images').select('*', { count: 'exact', head: true }).eq('profile_id', req.user.id);
    if (countErr) return res.status(500).json({ error: countErr.message });
    if (count >= limit) return res.status(403).json({ error: `Your ${role} tier is limited to ${limit} image(s). Please upgrade to upload more.` });

    // Upload to Supabase Storage
    const ext = req.file.originalname.split('.').pop() || 'jpg';
    const storagePath = `${req.user.id}/${crypto.randomUUID()}.${ext}`;

    const { error: uploadErr } = await supabase.storage.from('user-images').upload(storagePath, req.file.buffer, {
      contentType: req.file.mimetype,
      upsert: false
    });
    if (uploadErr) return res.status(500).json({ error: 'Upload failed: ' + uploadErr.message });

    // Get public URL
    const { data: urlData } = supabase.storage.from('user-images').getPublicUrl(storagePath);
    const publicUrl = urlData?.publicUrl || '';

    // Save metadata
    const { data: img, error: insertErr } = await supabase.from('user_images').insert([{
      profile_id: req.user.id,
      file_name: req.file.originalname,
      file_path: storagePath,
      file_url: publicUrl,
      file_size: req.file.size
    }]).select().single();

    if (insertErr) return res.status(500).json({ error: insertErr.message });
    res.json(img);
  } catch (e) {
    console.error('Image upload error:', e.message);
    res.status(500).json({ error: 'Upload failed.' });
  }
});

// API: Upload multiple images at once
app.post('/api/images/upload-multiple', requireAuth, upload.array('images', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No image files provided.' });

    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    const role = req.user.profile.role || 'FREE';
    const limit = IMAGE_LIMITS[role] || 3;
    const { count, error: countErr } = await supabase.from('user_images').select('*', { count: 'exact', head: true }).eq('profile_id', req.user.id);
    if (countErr) return res.status(500).json({ error: countErr.message });

    const available = limit - (count || 0);
    if (available <= 0) return res.status(403).json({ error: `Your ${role} tier is limited to ${limit} image(s). Please upgrade to upload more.` });

    const filesToUpload = req.files.slice(0, available);
    const uploaded = [];
    const errors = [];

    for (const file of filesToUpload) {
      if (!allowed.includes(file.mimetype)) { errors.push(`${file.originalname}: invalid type`); continue; }
      if (file.size > 5 * 1024 * 1024) { errors.push(`${file.originalname}: too large (max 5MB)`); continue; }

      const ext = file.originalname.split('.').pop() || 'jpg';
      const storagePath = `${req.user.id}/${crypto.randomUUID()}.${ext}`;

      const { error: uploadErr } = await supabase.storage.from('user-images').upload(storagePath, file.buffer, {
        contentType: file.mimetype, upsert: false
      });
      if (uploadErr) { errors.push(`${file.originalname}: ${uploadErr.message}`); continue; }

      const { data: urlData } = supabase.storage.from('user-images').getPublicUrl(storagePath);
      const publicUrl = urlData?.publicUrl || '';

      const { data: img, error: insertErr } = await supabase.from('user_images').insert([{
        profile_id: req.user.id,
        file_name: file.originalname,
        file_path: storagePath,
        file_url: publicUrl,
        file_size: file.size
      }]).select().single();

      if (insertErr) { errors.push(`${file.originalname}: ${insertErr.message}`); continue; }
      uploaded.push(img);
    }

    const skipped = req.files.length - filesToUpload.length;
    res.json({ success: true, uploaded, errors, skipped });
  } catch (e) {
    console.error('Multi-image upload error:', e.message);
    res.status(500).json({ error: 'Upload failed.' });
  }
});

// API: Delete image
app.delete('/api/images/:id', requireAuth, async (req, res) => {
  try {
    const { data: img } = await supabase.from('user_images').select('*').eq('id', req.params.id).eq('profile_id', req.user.id).single();
    if (!img) return res.status(404).json({ error: 'Image not found.' });

    // Delete from storage
    await supabase.storage.from('user-images').remove([img.file_path]);

    // Delete linked trigger photo images from junction table
    await supabase.from('trigger_photo_images').delete().eq('image_id', req.params.id);

    // Delete metadata
    const { error } = await supabase.from('user_images').delete().eq('id', req.params.id).eq('profile_id', req.user.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== TRIGGER PHOTOS ====================

// API: List trigger photos (with image data via junction table)
app.get('/api/trigger-photos', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('trigger_photos').select('*, trigger_photo_images(*, user_images(*))').eq('profile_id', req.user.id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// API: Create or update trigger photo (supports multiple image_ids)
app.post('/api/trigger-photos', requireAuth, async (req, res) => {
  try {
    const { id, image_ids, trigger_words, auto_send_enabled, auto_send_threshold, is_kb_skill } = req.body;
    // Support both old single image_id and new image_ids array
    let imageIdList = image_ids || [];
    if (req.body.image_id && imageIdList.length === 0) imageIdList = [req.body.image_id];
    if (imageIdList.length === 0 || !trigger_words) return res.status(400).json({ error: 'At least one image and trigger_words are required.' });

    // Verify all images belong to user
    const { data: imgs } = await supabase.from('user_images').select('id').in('id', imageIdList).eq('profile_id', req.user.id);
    if (!imgs || imgs.length !== imageIdList.length) return res.status(404).json({ error: 'One or more images not found.' });

    let triggerPhotoId = id;
    if (id) {
      // Update
      const { error } = await supabase.from('trigger_photos').update({
        trigger_words, auto_send_enabled: !!auto_send_enabled,
        auto_send_threshold: auto_send_threshold || null, is_kb_skill: !!is_kb_skill
      }).eq('id', id).eq('profile_id', req.user.id);
      if (error) return res.status(500).json({ error: error.message });
    } else {
      // Insert
      const { data: newTp, error } = await supabase.from('trigger_photos').insert([{
        profile_id: req.user.id, trigger_words,
        auto_send_enabled: !!auto_send_enabled,
        auto_send_threshold: auto_send_threshold || null,
        is_kb_skill: !!is_kb_skill
      }]).select().single();
      if (error) return res.status(500).json({ error: error.message });
      triggerPhotoId = newTp.id;
    }

    // Sync junction table: delete old links, insert new ones
    await supabase.from('trigger_photo_images').delete().eq('trigger_photo_id', triggerPhotoId);
    const junctionInserts = imageIdList.map((imgId, idx) => ({
      trigger_photo_id: triggerPhotoId, image_id: imgId, sort_order: idx
    }));
    const { error: junctionErr } = await supabase.from('trigger_photo_images').insert(junctionInserts);
    if (junctionErr) return res.status(500).json({ error: junctionErr.message });

    // If is_kb_skill, sync to KB
    if (is_kb_skill) {
      const kbTitle = `Trigger Photo: ${trigger_words.split(',')[0].trim()}`;
      const kbContent = `# Trigger Photo\n\nThis is a trigger photo that should be sent when the user says any of the following:\n${trigger_words.split(',').map(w => '- "' + w.trim() + '"').join('\n')}\n\n${imageIdList.length} image(s) attached.\n\n${auto_send_enabled ? `Auto-send is enabled after ${auto_send_threshold || 10} messages.` : ''}`;

      const { data: existing } = await supabase.from('knowledge_entries').select('id').eq('profile_id', req.user.id).eq('title', kbTitle).single();
      if (existing) {
        await supabase.from('knowledge_entries').update({ content: kbContent }).eq('id', existing.id);
      } else {
        await supabase.from('knowledge_entries').insert([{ profile_id: req.user.id, title: kbTitle, content: kbContent }]);
      }
    }

    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// API: Delete trigger photo
app.delete('/api/trigger-photos/:id', requireAuth, async (req, res) => {
  try {
    // Clean up any KB entry
    const { data: tp } = await supabase.from('trigger_photos').select('trigger_words').eq('id', req.params.id).eq('profile_id', req.user.id).single();
    if (tp) {
      const kbTitle = `Trigger Photo: ${tp.trigger_words.split(',')[0].trim()}`;
      await supabase.from('knowledge_entries').delete().eq('profile_id', req.user.id).eq('title', kbTitle);
    }

    const { error } = await supabase.from('trigger_photos').delete().eq('id', req.params.id).eq('profile_id', req.user.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// API: Admin - Get All Users
app.get('/api/admin/users', requireAuth, async (req, res) => {
  if (req.user.profile.role !== 'ADMIN') return res.status(403).json({ error: 'Forbidden' });
  const { data, error } = await supabase.from('profiles').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// API: Admin - Edit User Credits/Role
app.put('/api/admin/users/:id', requireAuth, async (req, res) => {
  if (req.user.profile.role !== 'ADMIN') return res.status(403).json({ error: 'Forbidden' });
  const { credits, role } = req.body;
  const { error } = await supabase.from('profiles').update({ credits, role }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// API: Admin - Get All Activity Logs (with user + page info)
app.get('/api/admin/logs', requireAuth, async (req, res) => {
  if (req.user.profile.role !== 'ADMIN') return res.status(403).json({ error: 'Forbidden' });
  try {
    const { data, error } = await supabase
      .from('activity_logs')
      .select('*, fb_pages(name, fb_page_id, profile_id, is_enabled, profiles:profile_id(email, role))')
      .order('created_at', { ascending: false })
      .limit(200);
    if (error) throw error;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// API: Admin - Get All Pages (webhook status overview)
app.get('/api/admin/pages', requireAuth, async (req, res) => {
  if (req.user.profile.role !== 'ADMIN') return res.status(403).json({ error: 'Forbidden' });
  try {
    const { data, error } = await supabase
      .from('fb_pages')
      .select('id, name, fb_page_id, ai_model, is_enabled, created_at, profiles:profile_id(email, role, credits)')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// API: Logs (filtered at DB level for data isolation)
app.get('/api/logs', requireAuth, async (req, res) => {
  // First get user's page IDs, then filter logs at the DB level
  const { data: userPages } = await supabase.from('fb_pages').select('id').eq('profile_id', req.user.id);
  if (!userPages || userPages.length === 0) return res.json([]);

  const pageIds = userPages.map(p => p.id);
  const { data, error } = await supabase
    .from('activity_logs')
    .select('*, fb_pages(name, profile_id)')
    .in('fb_page_id', pageIds)
    .order('created_at', { ascending: false })
    .limit(100);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// API: Logs Stats
app.get('/api/logs/stats', requireAuth, async (req, res) => {
  try {
    const { data: pages } = await supabase.from('fb_pages').select('id').eq('profile_id', req.user.id);
    if (!pages || pages.length === 0) return res.json({});

    const pageIds = pages.map(p => p.id);
    const { data: logs, error } = await supabase.from('activity_logs')
      .select('fb_page_id, type, payload')
      .in('fb_page_id', pageIds);

    if (error) throw error;

    const stats = {};
    pageIds.forEach(id => {
      stats[id] = { users: new Set(), replies: 0 };
    });

    (logs || []).forEach(log => {
      if (stats[log.fb_page_id]) {
        if (log.payload && log.payload.sender) stats[log.fb_page_id].users.add(log.payload.sender);
        if (log.type === 'AUTO_REPLY' || log.type === 'WIDGET_REPLY') stats[log.fb_page_id].replies++;
      }
    });

    const finalStats = {};
    Object.keys(stats).forEach(id => {
      finalStats[id] = {
        userCount: stats[id].users.size,
        replyCount: stats[id].replies
      };
    });

    res.json(finalStats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API: Analyze Logs
app.post('/api/logs/analyze', requireAuth, async (req, res) => {
  try {
    // Filter logs at DB level for data isolation (admins see all)
    let relevantLogs;
    if (req.user.profile.role === 'ADMIN') {
      const { data, error } = await supabase.from('activity_logs').select('*, fb_pages(name, profile_id)').order('created_at', { ascending: false }).limit(50);
      if (error) throw error;
      relevantLogs = data;
    } else {
      const { data: userPages } = await supabase.from('fb_pages').select('id').eq('profile_id', req.user.id);
      if (!userPages || userPages.length === 0) {
        return res.status(400).json({ error: "No chat logs available to analyze." });
      }
      const pageIds = userPages.map(p => p.id);
      const { data, error } = await supabase.from('activity_logs').select('*, fb_pages(name, profile_id)').in('fb_page_id', pageIds).order('created_at', { ascending: false }).limit(50);
      if (error) throw error;
      relevantLogs = data;
    }
    if (!relevantLogs || relevantLogs.length === 0) {
      return res.status(400).json({ error: "No chat logs available to analyze." });
    }

    const logText = relevantLogs.map(log => {
      let text = `Time: ${new Date(log.created_at).toLocaleString()}`;
      if (log.payload) {
        if (log.payload.sender) text += ` | Sender: ${log.payload.sender}`;
        if (log.payload.in) text += `\nUser: ${log.payload.in}`;
        if (log.payload.out) text += `\nAI: ${log.payload.out}`;
      }
      return text;
    }).join('\n\n---\n\n');

    // Check Credits (cost is 2 credits)
    if (req.user.profile.role !== 'ADMIN') {
      if ((req.user.profile.credits || 0) < 2) {
        return res.status(402).json({ error: "Insufficient credits. Analyzing chatlogs requires 2 credits." });
      }
    }

    const resolvedApiKey = process.env.OPENROUTER_API_KEY;
    if (!resolvedApiKey) return res.status(500).json({ error: 'System OpenRouter API key not configured for analysis.' });

    const aiRes = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: 'openai/gpt-5.2',
      messages: [
        {
          role: 'system',
          content: `You are an expert chatlog analyst. Review the provided customer interaction logs and generate a detailed report in Markdown format.
Include:
1. An overall summary of conversation topics.
2. Customer sentiment analysis.
3. Common questions or issues raised.
4. An assessment of bot performance (quality of answers).
5. Provide actionable tips or practical sample changes for the "prompt.MD" to improve sales and marketing.
Please format nicely with headers and bullet points.`
        },
        { role: 'user', content: logText.substring(0, 50000) }
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${resolvedApiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://www.blockscom.xyz',
        'X-Title': 'Blockscom AI'
      }
    });

    const report = aiRes.data?.choices?.[0]?.message?.content || 'Unable to generate analysis at this time.';

    // Deduct 2 credits atomically (floor at 0)
    if (req.user.profile.role !== 'ADMIN') {
      try {
        await supabase.rpc('deduct_credits', { user_id: req.user.id, amount: 2 }).single();
      } catch (_rpcErr) {
        // Fallback if RPC function not yet created in Supabase
        const newCredits = Math.max(0, (req.user.profile.credits || 0) - 2);
        await supabase.from('profiles').update({ credits: newCredits }).eq('id', req.user.id);
      }
    }

    res.json({ success: true, report });
  } catch (e) {
    console.error('Analyze Logs Error:', e.message);
    if (e.response && e.response.data) {
      console.error('OpenRouter Error Details:', e.response.data);
      return res.status(500).json({ error: 'AI Error: ' + (e.response.data.error?.message || e.message) });
    }
    res.status(500).json({ error: 'Failed to analyze logs.' });
  }
});

// ==================== WEBSITE WIDGET API (Shopify/HTML Plugin) ====================

app.get('/api/widget/config', rateLimit(60000, 30), async (req, res) => {
  const key = String(req.query.key || '');
  if (!key) return res.status(400).json({ error: 'missing key' });

  // Check cache first
  const cached = widgetConfigCache.get(key);
  if (cached && Date.now() - cached.ts < WIDGET_CONFIG_TTL) {
    return res.json(cached.data);
  }

  const { data: page, error } = await supabase
    .from('fb_pages')
    .select('id,name,ai_model,is_enabled,widget_key,allowed_domains,profile_id,widget_theme,widget_name')
    .eq('widget_key', key)
    .single();

  if (error || !page || !page.is_enabled) return res.status(404).json({ error: 'widget not found' });

  const response = { ok: true, pageName: page.name, widgetName: page.widget_name, model: page.ai_model || 'openai/gpt-5.2', theme: page.widget_theme || 'default' };
  widgetConfigCache.set(key, { data: response, ts: Date.now() });
  res.json(response);
});

app.post('/api/widget/message', rateLimit(60000, 20), async (req, res) => {
  try {
    const { key, message } = req.body || {};
    if (!key || !message) return res.status(400).json({ error: 'missing key/message' });

    const { data: page, error } = await supabase
      .from('fb_pages')
      .select('*, profiles:profile_id (*)')
      .eq('widget_key', String(key))
      .single();

    if (error || !page || !page.is_enabled) return res.status(404).json({ error: 'widget not found' });

    const userProfile = page.profiles;
    if (userProfile && userProfile.role !== 'ADMIN' && (userProfile.credits || 0) <= 0) {
      return res.status(402).json({ error: 'out of credits' });
    }

    const canReply = await checkDailyLimit(page.profile_id, userProfile?.role || 'FREE');
    if (!canReply) {
      return res.status(429).json({ error: 'daily reply limit reached for your tier' });
    }

    // Domain allowlist check (strict hostname match)
    const origin = String(req.headers.origin || '');
    if (Array.isArray(page.allowed_domains) && page.allowed_domains.length > 0) {
      let originHostname = '';
      try { originHostname = new URL(origin).hostname; } catch (_) { }
      const allowed = page.allowed_domains.some(d => {
        const domain = String(d).replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
        return originHostname === domain || originHostname.endsWith('.' + domain);
      });
      if (!allowed) return res.status(403).json({ error: 'origin not allowed' });
    }

    // Check KB+Inventory cache first (avoids repeated Supabase calls during burst conversations)
    const cacheKey = `widget:${page.profile_id}`;
    let personalityContent, context, productCatalog = "", widgetProducts = [];
    const cachedKb = kbCache.get(cacheKey);

    if (cachedKb && Date.now() - cachedKb.ts < KB_CACHE_TTL) {
      personalityContent = cachedKb.personalityContent;
      context = cachedKb.context;
      productCatalog = cachedKb.productCatalog;
      widgetProducts = cachedKb.widgetProducts;
    } else {
      // Fetch KB + Inventory in parallel
      const [kbResult, invTablesResult] = await Promise.all([
        supabase.from('knowledge_entries').select('content, title').eq('profile_id', page.profile_id),
        supabase.from('inventory_tables').select('id, name, columns').eq('profile_id', page.profile_id)
      ]);
      const kb = kbResult.data;
      const invTables = invTablesResult.data;

      // Separate PERSONALITY from other KB entries
      const personalityEntry = (kb || []).find(k => k.title === 'PERSONALITY');
      personalityContent = personalityEntry ? personalityEntry.content : '';
      context = (kb || []).filter(k => k.title !== 'PERSONALITY').map(k => k.content).join('\n\n');

      // Fetch all inventory rows in a single query instead of N parallel queries
      if (invTables && invTables.length > 0) {
        const tableIds = invTables.map(t => t.id);
        const { data: allRows } = await supabase.from('inventory_rows').select('data, table_id').in('table_id', tableIds);
        const rowsByTable = {};
        (allRows || []).forEach(r => { (rowsByTable[r.table_id] = rowsByTable[r.table_id] || []).push(r); });
        invTables.forEach(tbl => {
          const invRows = rowsByTable[tbl.id] || [];
          if (invRows.length > 0) {
            const cols = tbl.columns || [];
            productCatalog += `\n\nINVENTORY - ${tbl.name}:\n` + invRows.map(r => {
              return '- ' + cols.map(c => `${c.label}: ${r.data[c.key] ?? 'N/A'}`).join(', ');
            }).join('\n');
            widgetProducts = widgetProducts.concat(invRows.map(r => ({ _table: tbl.name, ...r.data })));
          }
        });
      }

      // Cache the result
      kbCache.set(cacheKey, { personalityContent, context, productCatalog, widgetProducts, ts: Date.now() });
    }

    // Get the user's default currency
    const widgetUserCurrency = userProfile?.currency || 'PHP';
    const widgetCurrencySymbol = CURRENCY_SYMBOLS[widgetUserCurrency] || widgetUserCurrency;

    const resolvedApiKey = process.env.OPENROUTER_API_KEY;
    if (!resolvedApiKey) return res.status(500).json({ error: 'missing OpenRouter key' });

    const aiRes = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: page.ai_model || 'arcee-ai/trinity-large-preview:free',
      messages: [
        {
          role: 'system', content: `You are Blockscom website assistant for ${page.name}. 

PERSONALITY / TONE:
${personalityContent}

DEFAULT CURRENCY: ${widgetUserCurrency} (${widgetCurrencySymbol})
- Always display all prices and monetary values in ${widgetUserCurrency} (${widgetCurrencySymbol}).
- This is the store's default currency. Do not use any other currency unless the customer explicitly asks.

KNOWLEDGE BASE:
${context}
${productCatalog}

INSTRUCTIONS:
- Answer directly based on the knowledge base and product catalog.
- IMPORTANT: When listing products, format them using Markdown (e.g., bullet points and **bold** text) for better readability.
- Add line breaks between distinct items so it does not look like a wall of text.
- If a customer wants to place an order, ask for their name, contact info, and shipping address. Once provided, use the place_order tool.` },
        { role: 'user', content: String(message) }
      ],
      tools: [{
        type: "function",
        function: {
          name: "place_order",
          description: "Places a new order for a customer.",
          parameters: {
            type: "object",
            properties: {
              customer_name: { type: "string" },
              customer_contact: { type: "string", description: "Email or phone number" },
              shipping_address: { type: "string" },
              items: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    quantity: { type: "integer" },
                    price: { type: "number" }
                  },
                  required: ["name", "quantity", "price"]
                }
              },
              total_amount: { type: "number" }
            },
            required: ["customer_name", "customer_contact", "shipping_address", "items", "total_amount"]
          }
        }
      }]
    }, { headers: { 'Authorization': `Bearer ${resolvedApiKey}` } });

    let reply = aiRes.data?.choices?.[0]?.message?.content || '';
    const toolCalls = aiRes.data?.choices?.[0]?.message?.tool_calls;

    if (toolCalls && toolCalls.length > 0) {
      for (const toolCall of toolCalls) {
        if (toolCall.function.name === 'place_order') {
          try {
            const orderArgs = JSON.parse(toolCall.function.arguments);
            const { error: insertError } = await supabase.from('orders').insert([{
              profile_id: page.profile_id,
              fb_page_id: page.id,
              customer_name: orderArgs.customer_name,
              customer_contact: orderArgs.customer_contact,
              shipping_address: orderArgs.shipping_address,
              items: orderArgs.items,
              total_amount: orderArgs.total_amount,
              source: 'widget',
              status: 'PENDING'
            }]);

            if (insertError) {
              console.error("Order Insert Error (Widget):", insertError);
              reply = "Sorry, I encountered an error while placing your order. Please try again.";
            } else {
              reply = `I have successfully placed your order for ${orderArgs.items.map(i => i.quantity + 'x ' + i.name).join(', ')}. Your total is $${orderArgs.total_amount}. We will ship it to ${orderArgs.shipping_address}. Thank you, ${orderArgs.customer_name}!`;
            }
          } catch (e) {
            console.error("Failed to parse tool call or insert order:", e);
            reply = "Sorry, there was a problem processing your order details.";
          }
        }
      }
    } else if (!reply) {
      reply = 'Thanks! Can you share more details?';
    }

    await supabase.from('activity_logs').insert([{ fb_page_id: page.id, type: 'WIDGET_REPLY', payload: { in: message, out: reply } }]);

    // Deduct 1 credit atomically for widget replies
    if (userProfile && userProfile.role !== 'ADMIN') {
      try {
        await supabase.rpc('deduct_credits', { user_id: page.profile_id, amount: 1 }).single();
      } catch (_rpcErr) {
        // Fallback if RPC function not yet created in Supabase
        const newCredits = Math.max(0, (userProfile.credits || 0) - 1);
        await supabase.from('profiles').update({ credits: newCredits }).eq('id', page.profile_id);
      }
    }

    res.json({ ok: true, reply, products: widgetProducts || [] });
  } catch (e) {
    res.status(500).json({ error: e.message || 'internal error' });
  }
});

// ==================== WEBHOOK LOGIC ====================

// Helper to check daily limit — single RPC call instead of 3 sequential queries
async function checkDailyLimit(profileId, role) {
  try {
    const { data, error } = await supabase.rpc('check_daily_limit', {
      p_profile_id: profileId,
      p_role: role || 'FREE'
    });
    if (error) {
      console.error('Daily limit RPC error:', error);
      return true; // fail open
    }
    return data;
  } catch (err) {
    console.error('Daily limit check error:', err.message);
    return true; // fail open
  }
}

// Helper to process a single message event
async function processMessage(event, fbPageId) {
  debugLog('--- START PROCESS MESSAGE ---');
  const senderId = event.sender.id;
  const messageText = event.message.text;
  const targetPageId = String(fbPageId);

  debugLog(`[DEBUG] Processing message from ${senderId} to Page ID ${targetPageId}`);

  try {
    debugLog(`[DEBUG] Fetching config for Page ID: ${targetPageId}`);
    // 1. Get Page Config
    const { data: page, error: pageError } = await supabase
      .from('fb_pages')
      .select('*, profiles:profile_id (*)') // Join profiles
      .eq('fb_page_id', targetPageId)
      .single();

    if (pageError) {
      console.error(`[ERROR] DB query failed for Page ID ${targetPageId}:`, JSON.stringify(pageError));
      return;
    }
    if (!page) {
      console.error(`[ERROR] Page not found in DB for ID ${targetPageId}`);
      return;
    }

    if (!page.is_enabled) {
      debugLog(`[DEBUG] Page ${page.name} (ID: ${targetPageId}) is disabled. Skipping message.`);
      return;
    }

    const userProfile = page.profiles;
    debugLog(`[DEBUG] Found page: ${page.name}. Credits: ${userProfile?.credits}, Role: ${userProfile?.role}`);

    // ----- SYNC TOKEN INTERCEPTION -----
    // Check if the user is sending a sync token to register their owner_psid
    if (page.sync_token && messageText && messageText.trim() === page.sync_token) {
      debugLog(`[DEBUG] SYNC TOKEN MATCHED for Page ID: ${targetPageId}`);

      const { error: syncErr } = await supabase.from('fb_pages').update({
        sync_token: null,
        owner_psid: senderId,
        notify_on_order: true // Auto-enable on successful sync
      }).eq('id', page.id);

      let syncReply = "✅ Sync Successful! You will now receive order notifications for this page.";

      if (!syncErr) {
        try {
          // Use the required model for Sync Confirmation per instructions
          const resolvedApiKey = process.env.OPENROUTER_API_KEY;
          if (resolvedApiKey) {
            const aiRes = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
              model: 'openai/gpt-oss-120b',
              messages: [{
                role: 'system',
                content: `You are the system notification bot for the page "${page.name}". The user just successfully synced their Messenger account to receive order alerts. Write a very brief, friendly, and professional confirmation message acknowledging the sync.`
              }]
            }, { headers: { 'Authorization': `Bearer ${resolvedApiKey}` } });

            if (aiRes.data?.choices?.[0]?.message?.content) {
              syncReply = aiRes.data.choices[0].message.content;
            }
          }
        } catch (aiErr) {
          console.error('[ERROR] Failed to generate AI sync reply:', aiErr.message);
          // Fallback to the default syncReply
        }

        // Send the confirmation
        const pageAccessToken = decryptSecret(page.access_token);
        if (pageAccessToken) {
          await axios.post(
            `https://graph.facebook.com/v22.0/me/messages`,
            { recipient: { id: senderId }, message: { text: syncReply } },
            { params: { access_token: pageAccessToken } }
          );
        }
      }

      return; // Stop further processing, this was a system command.
    }
    // -----------------------------------

    if (userProfile && userProfile.role !== 'ADMIN' && (userProfile.credits || 0) <= 0) {
      debugLog(`[DEBUG] User ${userProfile.email} out of credits.`);
      return;
    }

    const canReply = await checkDailyLimit(page.profile_id, userProfile?.role || 'FREE');
    if (!canReply) {
      debugLog(`[DEBUG] User ${userProfile?.email} reached their daily limit.`);
      return;
    }

    // 3. Build Context (Knowledge Base) + 3b. Fetch Inventory — in parallel
    debugLog(`[DEBUG] Building knowledge base + inventory for user ${page.profile_id}...`);
    let kbQuery = supabase.from('knowledge_entries').select('content, title').eq('profile_id', page.profile_id);

    // Filter by specific files if defined
    if (Array.isArray(page.knowledge_base) && page.knowledge_base.length > 0) {
      const kbTitles = page.knowledge_base.filter(item => typeof item === 'string');
      if (kbTitles.length > 0) {
        debugLog(`[DEBUG] Filtering KB by titles: ${kbTitles.join(', ')}`);
        kbQuery = kbQuery.in('title', kbTitles);
      }
    }

    // Run KB + inventory table fetch in parallel
    const [kbResult, invTablesResult] = await Promise.all([
      kbQuery,
      supabase.from('inventory_tables').select('id, name, columns').eq('profile_id', page.profile_id)
    ]);

    const kb = kbResult.data;
    if (kbResult.error) console.error(`[ERROR] KB Query failed:`, kbResult.error);

    // Always fetch PERSONALITY skill separately (it may not be in the selected KB titles)
    let personalityContent = '';
    const personalityInKb = (kb || []).find(k => k.title === 'PERSONALITY');
    if (personalityInKb) {
      personalityContent = personalityInKb.content;
    } else {
      const { data: personalityEntry } = await supabase.from('knowledge_entries').select('content').eq('profile_id', page.profile_id).eq('title', 'PERSONALITY').single();
      if (personalityEntry) personalityContent = personalityEntry.content;
    }

    const context = (kb || []).filter(k => k.title !== 'PERSONALITY').map(k => k.content).join('\n\n');
    debugLog(`[DEBUG] KB Context length: ${context.length} characters. Personality: ${personalityContent.length} chars`);

    // Fetch all inventory rows in a single query instead of N parallel queries
    let productCatalog = "";
    try {
      const invTables = invTablesResult.data;
      if (invTables && invTables.length > 0) {
        const tableIds = invTables.map(t => t.id);
        const { data: allRows } = await supabase.from('inventory_rows').select('data, table_id').in('table_id', tableIds);
        const rowsByTable = {};
        (allRows || []).forEach(r => { (rowsByTable[r.table_id] = rowsByTable[r.table_id] || []).push(r); });
        invTables.forEach(tbl => {
          const invRows = rowsByTable[tbl.id] || [];
          if (invRows.length > 0) {
            const cols = tbl.columns || [];
            productCatalog += `\n\nINVENTORY - ${tbl.name}:\n` + invRows.map(r => {
              return '- ' + cols.map(c => `${c.label}: ${r.data[c.key] ?? 'N/A'}`).join(', ');
            }).join('\n');
          }
        });
      }
    } catch (invErr) {
      console.warn('[WARN] Inventory query failed:', invErr.message);
    }
    debugLog(`[DEBUG] Inventory catalog length: ${productCatalog.length} chars`);

    // 4. Get AI Response
    debugLog(`[DEBUG] Requesting AI completion from OpenRouter (${page.ai_model || 'default'})...`);
    // Decrypt keys
    const openRouterKey = process.env.OPENROUTER_API_KEY;
    const pageAccessToken = decryptSecret(page.access_token);

    if (!openRouterKey) {
      console.error('[ERROR] No OpenRouter Key available for page:', page.name);
      return;
    }
    if (!pageAccessToken) {
      console.error('[ERROR] No Page Access Token available for page:', page.name);
      return;
    }

    // Get the user's default currency for bot responses
    const fbUserCurrency = userProfile?.currency || 'PHP';
    const fbCurrencySymbol = CURRENCY_SYMBOLS[fbUserCurrency] || fbUserCurrency;

    const aiRes = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: page.ai_model || 'arcee-ai/trinity-large-preview:free', // Fallback model
        messages: [
          {
            role: 'system',
            content: `You are a helpful AI assistant for the Facebook page "${page.name}".
            
            PERSONALITY / TONE:
            ${personalityContent}
            
            DEFAULT CURRENCY: ${fbUserCurrency} (${fbCurrencySymbol})
            - Always display all prices and monetary values in ${fbUserCurrency} (${fbCurrencySymbol}).
            - This is the store's default currency. Do not use any other currency unless the customer explicitly asks.
            
            KNOWLEDGE BASE:
            ${context}
            ${productCatalog}
            
            INSTRUCTIONS:
            - Answer based on the knowledge base and product catalog if relevant.
            - If a user asks about products or pricing, ONLY recommend the specific items listed in the PRODUCT CATALOG above. Do not invent products.
            - IMPORTANT: When listing products, use clear formatting (bullet points, double newlines for spacing, and asterisks for basic bolding) to organize the text neatly.
            - Keep answers concise for chat.
            - If a customer wants to place an order, ask for their name, contact info, and shipping address. Once provided, use the place_order tool.
            `
          },
          { role: 'user', content: messageText }
        ],
        tools: [{
          type: "function",
          function: {
            name: "place_order",
            description: "Places a new order for a customer.",
            parameters: {
              type: "object",
              properties: {
                customer_name: { type: "string" },
                customer_contact: { type: "string", description: "Email or phone number" },
                shipping_address: { type: "string" },
                items: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      name: { type: "string" },
                      quantity: { type: "integer" },
                      price: { type: "number" }
                    },
                    required: ["name", "quantity", "price"]
                  }
                },
                total_amount: { type: "number" }
              },
              required: ["customer_name", "customer_contact", "shipping_address", "items", "total_amount"]
            }
          }
        }]
      },
      {
        headers: {
          'Authorization': `Bearer ${openRouterKey}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://www.blockscom.xyz', // OpenRouter requirements
          'X-Title': 'Blockscom AI'
        }
      }
    );

    let replyText = aiRes.data.choices?.[0]?.message?.content || "";
    const toolCalls = aiRes.data.choices?.[0]?.message?.tool_calls;

    if (toolCalls && toolCalls.length > 0) {
      for (const toolCall of toolCalls) {
        if (toolCall.function.name === 'place_order') {
          try {
            const orderArgs = JSON.parse(toolCall.function.arguments);
            const { error: insertError } = await supabase.from('orders').insert([{
              profile_id: page.profile_id,
              fb_page_id: page.id,
              customer_name: orderArgs.customer_name,
              customer_contact: orderArgs.customer_contact,
              shipping_address: orderArgs.shipping_address,
              items: orderArgs.items,
              total_amount: orderArgs.total_amount,
              sender_id: senderId,
              source: 'webhook',
              status: 'PENDING'
            }]);

            if (insertError) {
              console.error("Order Insert Error (Webhook):", insertError);
              replyText = "Sorry, I encountered an error while placing your order. Please try again.";
            } else {
              replyText = `I have successfully placed your order for ${orderArgs.items.map(i => i.quantity + 'x ' + i.name).join(', ')}. Your total is ${fbCurrencySymbol}${orderArgs.total_amount}. We will ship it to ${orderArgs.shipping_address}. Thank you, ${orderArgs.customer_name}!`;

              // ----- ORDER NOTIFICATION SYSTEM -----
              if (page.owner_psid && page.notify_on_order) {
                try {
                  const resolvedApiKey = process.env.OPENROUTER_API_KEY;
                  if (resolvedApiKey) {
                    const promptText = page.notify_style === 'detailed'
                      ? `Format a detailed order notification message for the store owner. Use this info:\nName: ${orderArgs.customer_name}\nContact: ${orderArgs.customer_contact}\nShipping Details: ${orderArgs.shipping_address}\nItems Ordered: ${orderArgs.items.map(i => i.quantity + 'x ' + i.name).join(', ')}\nAmount: ${fbCurrencySymbol}${orderArgs.total_amount}\nKeep it very professional and cleanly formatted.`
                      : `Format a short, exciting "You have a new order!" alert for the store owner. Order amount is ${fbCurrencySymbol}${orderArgs.total_amount} from ${orderArgs.customer_name}.`;

                    const notifRes = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
                      model: 'openai/gpt-oss-20b',
                      messages: [{ role: 'system', content: promptText }]
                    }, { headers: { 'Authorization': `Bearer ${resolvedApiKey}` } });

                    const notifMsg = notifRes.data?.choices?.[0]?.message?.content || `🚨 New Order Confirmed!\nName: ${orderArgs.customer_name}\nTotal: ${fbCurrencySymbol}${orderArgs.total_amount}`;
                    const pageAccessToken = decryptSecret(page.access_token);

                    if (pageAccessToken) {
                      await axios.post(
                        `https://graph.facebook.com/v22.0/me/messages`,
                        { recipient: { id: page.owner_psid }, message: { text: notifMsg } },
                        { params: { access_token: pageAccessToken } }
                      );
                      debugLog(`[DEBUG] Order notification sent to owner ${page.owner_psid}`);
                    }
                  }
                } catch (notifErr) {
                  console.error('[ERROR] Failed to send order notification to owner:', notifErr.message);
                }
              }
              // -------------------------------------
            }
          } catch (e) {
            console.error("Failed to parse tool call or insert order:", e);
            replyText = "Sorry, there was a problem processing your order details.";
          }
        }
      }
    } else if (!replyText) {
      replyText = "I'm not sure how to respond to that.";
    }
    debugLog(`[DEBUG] AI Reply: ${replyText.substring(0, 50)}...`);

    // 5. Send Reply to Facebook
    debugLog(`[DEBUG] Sending reply to FB recipient ${senderId}...`);
    const fbRes = await axios.post(
      `https://graph.facebook.com/v22.0/me/messages`,
      {
        recipient: { id: senderId },
        message: { text: replyText }
      },
      {
        params: { access_token: pageAccessToken }
      }
    );
    debugLog(`[DEBUG] Facebook API status: ${fbRes.status}`);

    // 5b. Check trigger photos — send matching images
    try {
      const { data: triggerPhotos } = await supabase
        .from('trigger_photos')
        .select('*, trigger_photo_images(*, user_images(*))')
        .eq('profile_id', page.profile_id);

      if (triggerPhotos && triggerPhotos.length > 0 && messageText) {
        const msgLower = messageText.toLowerCase();
        for (const tp of triggerPhotos) {
          const words = (tp.trigger_words || '').split(',').map(w => w.trim().toLowerCase()).filter(Boolean);
          const matched = words.some(w => msgLower.includes(w));
          if (matched && tp.trigger_photo_images && tp.trigger_photo_images.length > 0) {
            debugLog(`[DEBUG] Trigger photo matched: "${tp.trigger_words}"`);
            // Sort by sort_order and send each image
            const sortedImages = tp.trigger_photo_images
              .filter(tpi => tpi.user_images && tpi.user_images.file_url)
              .sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));

            for (const tpi of sortedImages) {
              try {
                await axios.post(
                  `https://graph.facebook.com/v22.0/me/messages`,
                  {
                    recipient: { id: senderId },
                    message: {
                      attachment: {
                        type: 'image',
                        payload: { url: tpi.user_images.file_url, is_reusable: true }
                      }
                    }
                  },
                  { params: { access_token: pageAccessToken } }
                );
                debugLog(`[DEBUG] Sent trigger image: ${tpi.user_images.file_name}`);
              } catch (imgErr) {
                console.error(`[ERROR] Failed to send trigger image ${tpi.user_images.file_name}:`, imgErr.message);
              }
            }
          }
        }
      }
    } catch (triggerErr) {
      console.error('[WARN] Trigger photo check failed:', triggerErr.message);
    }

    // 6. Log & Deduct Credits
    await supabase.from('activity_logs').insert([{
      fb_page_id: page.id,
      type: 'AUTO_REPLY',
      payload: { in: messageText, out: replyText, sender: senderId }
    }]);

    if (userProfile && userProfile.role !== 'ADMIN') {
      try {
        await supabase.rpc('deduct_credits', { user_id: page.profile_id, amount: 1 }).single();
      } catch (_rpcErr) {
        // Fallback if RPC function not yet created in Supabase
        const newCredits = Math.max(0, (userProfile.credits || 0) - 1);
        await supabase.from('profiles').update({ credits: newCredits }).eq('id', page.profile_id);
      }
    }

  } catch (err) {
    console.error('Error processing message:', err.message);
    let errorDetail = err.message;
    if (err.response) {
      console.error('API Response data:', err.response.data);
      errorDetail = JSON.stringify(err.response.data?.error || err.response.data);
    }

    // Log error to DB so user can see it
    if (targetPageId) {
      const { data: errPage } = await supabase.from('fb_pages').select('id, access_token').eq('fb_page_id', targetPageId).single();
      if (errPage) {
        await supabase.from('activity_logs').insert([{
          fb_page_id: errPage.id,
          type: 'ERROR',
          payload: { in: messageText, out: 'Failed to reply: ' + errorDetail.substring(0, 200), sender: senderId }
        }]);

        // Try to send a fallback message so it's not completely dead
        try {
          const token = decryptSecret(errPage.access_token);
          if (token) {
            await axios.post(
              `https://graph.facebook.com/v22.0/me/messages`,
              { recipient: { id: senderId }, message: { text: "Sorry, I am having trouble processing that right now. Please try again later." } },
              { params: { access_token: token } }
            );
          }
        } catch (fbErr) {
          console.error("Failed to send fallback message:", fbErr.message);
        }
      }
    }
  }
}

app.get('/webhook', async (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  const pageId = req.query.page; // system ID — REQUIRED for security

  if (mode === 'subscribe' && token) {
    if (!pageId) {
      console.warn('Webhook verification rejected: missing ?page= parameter');
      return res.sendStatus(400);
    }

    const { data: pages, error } = await supabase
      .from('fb_pages')
      .select('verify_token')
      .eq('id', pageId);

    if (error) {
      console.error('Webhook verification DB error:', error);
      return res.sendStatus(500);
    }

    // Check if the specific page's token matches
    const isValid = pages.some(p => {
      const decrypted = decryptSecret(p.verify_token);
      return decrypted === token;
    });

    if (isValid) {
      console.log(`WEBHOOK_VERIFIED FOR SYS_ID ${pageId}`);
      res.status(200).send(challenge);
    } else {
      console.warn(`Webhook verification failed: Invalid token for sys_id ${pageId}`);
      res.sendStatus(403);
    }
  } else {
    res.sendStatus(403);
  }
});

app.post('/webhook', async (req, res) => {
  // Verify Facebook signature to prevent fake webhook attacks
  if (!verifyFbSignature(req)) {
    console.warn('[WEBHOOK POST] Invalid or missing X-Hub-Signature-256 — rejecting');
    return res.sendStatus(403);
  }

  const body = req.body;
  console.log('[WEBHOOK POST] Received:', JSON.stringify(body?.object), 'entries:', body?.entry?.length || 0);

  if (body.object === 'page') {
    // CRITICAL: Respond to Facebook IMMEDIATELY — they timeout after 5 seconds
    res.status(200).send('EVENT_RECEIVED');

    // Process messages after response (Vercel keeps the function alive briefly after response)
    for (const entry of (body.entry || [])) {
      const fbPageId = entry.id;
      console.log(`[WEBHOOK] Processing entry for FB Page ID: ${fbPageId}`);

      if (entry.messaging) {
        for (const event of entry.messaging) {
          if (event.message && event.message.text) {
            try {
              await processMessage(event, fbPageId);
            } catch (err) {
              console.error(`[WEBHOOK ERROR] processMessage failed for Page ${fbPageId}:`, err.message);
            }
          }
        }
      }
    }
  } else {
    console.warn('[WEBHOOK POST] Unknown object type:', body?.object);
    res.sendStatus(404);
  }
});

// Global multer error handler — catches file-too-large errors and returns JSON
app.use((err, req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large. Maximum size is 5MB per image.' });
  }
  if (err && err.code === 'LIMIT_FILE_COUNT') {
    return res.status(413).json({ error: 'Too many files. Maximum is 10 images per upload.' });
  }
  if (err && err.name === 'MulterError') {
    return res.status(413).json({ error: err.message });
  }
  next(err);
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => console.log(`BLOCKSCOM SAAS live on ${PORT}`));
}

module.exports = app;
