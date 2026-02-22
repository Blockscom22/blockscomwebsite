const express = require('express');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

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

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, path) => {
    if (path.endsWith('.js') || path.endsWith('.css') || path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
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

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No auth header' });

  const token = authHeader.replace('Bearer ', '');
  const { data: { user }, error } = await supabase.auth.getUser(token);

  if (error || !user) return res.status(401).json({ error: 'Invalid session' });

  const { data: profile } = await supabase.from('profiles').select('*').eq('id', user.id).single();

  if (!profile) {
    const { data: newProfile } = await supabase.from('profiles').insert([{ id: user.id, email: user.email, credits: 50, role: 'FREE' }]).select().single();
    req.user = { ...user, profile: newProfile };
  } else {
    req.user = { ...user, profile };
  }

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
    const FREE_MODELS = ['openai/gpt-oss-120b', 'openai/gpt-oss-120b:free'];
    const resolvedModel = (req.user.profile.role === 'FREE' && !FREE_MODELS.includes(ai_model))
      ? 'openai/gpt-oss-120b'
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

    if (fs.existsSync(kbDir)) {
      const files = fs.readdirSync(kbDir).filter(f => f.endsWith('.md'));
      const defaultInserts = [];
      for (const file of files) {
        const content = fs.readFileSync(path.join(kbDir, file), 'utf8');
        const title = file.replace('.md', '').split(/[-_]/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        defaultInserts.push({ profile_id: req.user.id, title, content });
      }
      if (defaultInserts.length > 0) {
        await supabase.from('knowledge_entries').insert(defaultInserts);
        const { data: newData } = await supabase.from('knowledge_entries').select('*').eq('profile_id', req.user.id);
        return res.json(newData || []);
      }
    }

    // Fallback if no files exist
    const defaultSkill = { profile_id: req.user.id, title: 'Default Skill', content: 'I am a helpful AI assistant. I should aim to be concise, friendly, and professional in my responses.' };
    await supabase.from('knowledge_entries').insert([defaultSkill]);
    const { data: newData } = await supabase.from('knowledge_entries').select('*').eq('profile_id', req.user.id);
    return res.json(newData || []);
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
  const { error } = await supabase.from('knowledge_entries').delete().eq('id', req.params.id).eq('profile_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// API: Orders (User-specific)
app.get('/api/orders', requireAuth, async (req, res) => {
  const query = supabase.from('orders').select('*').order('created_at', { ascending: false });
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

// API: Import Products from File via AI
app.post('/api/products/import', requireAuth, async (req, res) => {
  try {
    const { fileData } = req.body;
    if (!fileData) return res.status(400).json({ error: 'No file data provided' });

    // Use default OpenRouter key, fallback if not set
    const resolvedApiKey = process.env.OPENROUTER_API_KEY;
    if (!resolvedApiKey) {
      return res.status(500).json({ error: 'System OpenRouter API key not configured for bulk import.' });
    }

    const aiRes = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: 'openai/gpt-4o', // Use a high-reasoning model for extraction
      messages: [
        {
          role: 'system',
          content: `You are an inventory parsing assistant. The user will provide raw text or CSV content.
Your job is to extract the product data and return a STRICT JSON array of objects.

REQUIRED JSON FORMAT:
[
  {
    "name": "Product Name",
    "category": "Category Name",
    "price": 10.99,
    "stock_quantity": 100,
    "is_sellable": true,
    "is_active": true
  }
]

RULES:
1. "price" must be a number (float/int).
2. "stock_quantity" must be an integer.
3. If "Sell by bot" or similar is mentioned as "SELLING" or true, set "is_sellable": true. If "DEACTIVATE" or false, set "is_sellable": false. Default to true if not specified.
4. "is_active" should default to true.
5. Do NOT wrap the JSON in markdown blocks (no \`\`\`json). Just return the raw JSON array.
6. IF the input is completely unreadable, gibberish, or lacks clear product boundaries, DO NOT return an array. Instead, return exactly this JSON object:
{"error": true, "message": "Invalid file format. Please use a default format like: Product Name, Category, Price, Stock, Sell by bot (SELLING OR DEACTIVATE)"}
`
        },
        { role: 'user', content: String(fileData).substring(0, 10000) } // Prevent massive payloads
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${resolvedApiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://www.blockscom.xyz',
        'X-Title': 'Blockscom AI'
      }
    });

    const reply = aiRes.data?.choices?.[0]?.message?.content?.trim() || '';

    // Clean up potential markdown wrappers just in case the AI disobeys
    let cleanJson = reply;
    if (cleanJson.startsWith('\`\`\`json')) {
      cleanJson = cleanJson.replace(/^\`\`\`json/i, '').replace(/\`\`\`$/, '').trim();
    } else if (cleanJson.startsWith('\`\`\`')) {
      cleanJson = cleanJson.replace(/^\`\`\`/i, '').replace(/\`\`\`$/, '').trim();
    }

    const parsed = JSON.parse(cleanJson);

    if (parsed.error) {
      return res.status(400).json(parsed); // Send the specific AI fallback error
    }

    if (!Array.isArray(parsed)) {
      throw new Error("AI did not return a valid array.");
    }

    res.json({ success: true, products: parsed });

  } catch (error) {
    console.error('Import API Error:', error.message);
    res.status(500).json({ error: 'Failed to process file. Ensure it loosely follows the required format.' });
  }
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
      model: 'openai/gpt-4o',
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

  const { data: page, error } = await supabase
    .from('fb_pages')
    .select('id,name,ai_model,is_enabled,widget_key,allowed_domains,profile_id,widget_theme,widget_name')
    .eq('widget_key', key)
    .single();

  if (error || !page || !page.is_enabled) return res.status(404).json({ error: 'widget not found' });

  res.json({ ok: true, pageName: page.name, widgetName: page.widget_name, model: page.ai_model === 'openai/gpt-5.2' ? 'openai/gpt-4o' : (page.ai_model || 'openai/gpt-4o'), theme: page.widget_theme || 'default' });
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

    const { data: kb } = await supabase
      .from('knowledge_entries')
      .select('content')
      .eq('profile_id', page.profile_id);
    const context = (kb || []).map(k => k.content).join('\n\n');

    // Fetch Products for Widget
    const { data: products } = await supabase
      .from('products')
      .select('*')
      .eq('profile_id', page.profile_id)
      .eq('is_active', true);

    let productCatalog = "";
    if (products && products.length > 0) {
      productCatalog = "\n\nPRODUCT CATALOG:\n" + products.map(p =>
        `- ${p.name}: ${p.description} (Price: $${p.price}, Stock: ${p.stock_quantity})`
      ).join('\n');
    }

    const resolvedApiKey = process.env.OPENROUTER_API_KEY;
    if (!resolvedApiKey) return res.status(500).json({ error: 'missing OpenRouter key' });

    const aiRes = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: page.ai_model === 'openai/gpt-5.2' ? 'openai/gpt-4o' : (page.ai_model || 'openai/gpt-4o'),
      messages: [
        {
          role: 'system', content: `You are Blockscom website assistant for ${page.name}. 

KNOWLEDGE BASE:
${context}
${productCatalog}

INSTRUCTIONS:
- Answer directly based on the knowledge base and product catalog.
- IMPORTANT: When listing products, format them using Markdown (e.g., bullet points and **bold** text) for better readability.
- Add line breaks between distinct items so it does not look like a wall of text.
- Be polite and professional.
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

    res.json({ ok: true, reply, products: products || [] });
  } catch (e) {
    res.status(500).json({ error: e.message || 'internal error' });
  }
});

// ==================== WEBHOOK LOGIC ====================

// Helper to check daily limit
async function checkDailyLimit(profileId, role) {
  if (role === 'ENTERPRISE' || role === 'ADMIN') return true;
  const limit = role === 'PREMIUM' ? 2500 : 200;

  const { data: pages } = await supabase.from('fb_pages').select('id').eq('profile_id', profileId);
  if (!pages || pages.length === 0) return true;
  const pageIds = pages.map(p => p.id);

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const { count, error } = await supabase
    .from('activity_logs')
    .select('*', { count: 'exact', head: true })
    .in('type', ['AUTO_REPLY', 'WIDGET_REPLY'])
    .gte('created_at', today.toISOString())
    .in('fb_page_id', pageIds);

  if (error) {
    console.error("Daily limit check error", error);
    return true; // fail open
  }
  return count < limit;
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

    if (userProfile && userProfile.role !== 'ADMIN' && (userProfile.credits || 0) <= 0) {
      debugLog(`[DEBUG] User ${userProfile.email} out of credits.`);
      return;
    }

    const canReply = await checkDailyLimit(page.profile_id, userProfile?.role || 'FREE');
    if (!canReply) {
      debugLog(`[DEBUG] User ${userProfile?.email} reached their daily limit.`);
      return;
    }

    // 3. Build Context (Knowledge Base)
    debugLog(`[DEBUG] Building knowledge base for user ${page.profile_id}...`);
    let kbQuery = supabase.from('knowledge_entries').select('content, title').eq('profile_id', page.profile_id);

    // Filter by specific files if defined
    let kbTitles = [];
    let selectedProducts = [];
    let selectedCategories = [];

    if (Array.isArray(page.knowledge_base) && page.knowledge_base.length > 0) {
      page.knowledge_base.forEach(item => {
        if (item.startsWith('prod:')) selectedProducts.push(item.substring(5));
        else if (item.startsWith('cat:')) selectedCategories.push(item.substring(4));
        else kbTitles.push(item);
      });

      if (kbTitles.length > 0) {
        debugLog(`[DEBUG] Filtering KB by titles: ${kbTitles.join(', ')}`);
        kbQuery = kbQuery.in('title', kbTitles);
      } else {
        // If they ONLY selected products, we shouldn't fetch all KB, we should fetch none
        kbQuery = kbQuery.eq('id', '00000000-0000-0000-0000-000000000000'); // Force empty
      }
    }

    const { data: kb, error: kbError } = await kbQuery;
    if (kbError) console.error(`[ERROR] KB Query failed:`, kbError);
    const context = (kb || []).map(k => k.content).join('\n\n');
    debugLog(`[DEBUG] KB Context length: ${context.length} characters.`);

    // 3b. Fetch Product Catalog
    debugLog(`[DEBUG] Fetching product catalog for user ${page.profile_id}...`);
    let prodQuery = supabase
      .from('products')
      .select('*')
      .eq('profile_id', page.profile_id)
      .eq('is_active', true)
      .eq('is_sellable', true); // Only fetch sellable products for AI

    if (selectedProducts.length > 0 || selectedCategories.length > 0) {
      debugLog(`[DEBUG] Filtering products: ${selectedProducts.length} specific, ${selectedCategories.length} categories`);
      // We need an OR condition: name in selectedProducts OR category in selectedCategories
      let orConditions = [];
      if (selectedProducts.length > 0) orConditions.push(`name.in.("${selectedProducts.join('","')}")`);
      if (selectedCategories.length > 0) orConditions.push(`category.in.("${selectedCategories.join('","')}")`);
      prodQuery = prodQuery.or(orConditions.join(','));
    }

    const { data: products, error: prodError } = await prodQuery;

    let productCatalog = "";
    if (prodError) {
      console.warn(`[WARN] Products query failed (table might not exist yet):`, prodError.message);
    } else if (products && products.length > 0) {
      productCatalog = "\n\nPRODUCT CATALOG:\n" + products.map(p =>
        `- ${p.name}: ${p.description} (Price: $${p.price}, Stock: ${p.stock_quantity})`
      ).join('\n');
    }
    debugLog(`[DEBUG] Product catalog items found: ${products?.length || 0}`);

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

    const aiRes = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: page.ai_model === 'openai/gpt-5.2' ? 'openai/gpt-4o' : (page.ai_model || 'openai/gpt-4o'), // Fallback model
        messages: [
          {
            role: 'system',
            content: `You are a helpful AI assistant for the Facebook page "${page.name}".
            
            KNOWLEDGE BASE:
            ${context}
            ${productCatalog}
            
            INSTRUCTIONS:
            - Answer based on the knowledge base and product catalog if relevant.
            - If a user asks about products or pricing, ONLY recommend the specific items listed in the PRODUCT CATALOG above. Do not invent products.
            - IMPORTANT: When listing products, use clear formatting (bullet points, double newlines for spacing, and asterisks for basic bolding) to organize the text neatly.
            - Be polite and professional.
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
              status: 'PENDING'
            }]);

            if (insertError) {
              console.error("Order Insert Error (Webhook):", insertError);
              replyText = "Sorry, I encountered an error while placing your order. Please try again.";
            } else {
              replyText = `I have successfully placed your order for ${orderArgs.items.map(i => i.quantity + 'x ' + i.name).join(', ')}. Your total is $${orderArgs.total_amount}. We will ship it to ${orderArgs.shipping_address}. Thank you, ${orderArgs.customer_name}!`;
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

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => console.log(`BLOCKSCOM SAAS live on ${PORT}`));
}

module.exports = app;
