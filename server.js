const express = require('express');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();

// CORS (needed for embeddable widget from Shopify/custom sites/file previews)
app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin === 'null' ? '*' : origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
    console.log(`[DEBUG] decryptSecret: Splitting value into ${parts.length} parts`);
    const [, ivB64, tagB64, dataB64] = parts;
    if (!ivB64 || !tagB64 || !dataB64) {
      console.error('[ERROR] decryptSecret: Missing parts', { iv: !!ivB64, tag: !!tagB64, data: !!dataB64 });
      return '';
    }
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const data = Buffer.from(dataB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(data), decipher.final()]);
    const result = dec.toString('utf8');
    console.log(`[DEBUG] decryptSecret: Decryption successful, result length: ${result.length}`);
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
    const { data: newProfile } = await supabase.from('profiles').insert([{ id: user.id, email: user.email }]).select().single();
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

// API: Get Current User
app.get('/api/me', requireAuth, (req, res) => res.json(req.user.profile));

// API: Update User PIN
app.put('/api/me/pin', requireAuth, async (req, res) => {
  const { pin } = req.body;
  const { error } = await supabase.from('profiles').update({ pin_code: pin }).eq('id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// API: Get My Pages
app.get('/api/pages', requireAuth, async (req, res) => {
  const query = supabase.from('fb_pages').select('*').order('created_at', { ascending: false });
  if (req.user.profile.role !== 'ADMIN') query.eq('profile_id', req.user.id);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  const masked = data.map(p => ({
    ...p,
    access_token: maskSecret(p.access_token),
    verify_token: maskSecret(p.verify_token),
    openrouter_key: maskSecret(p.openrouter_key)
  }));
  res.json(masked);
});

// API: Add/Update Page
app.post('/api/pages', requireAuth, async (req, res) => {
  try {
    const { id, name, fb_page_id, verify_token, access_token, ai_model, knowledge_base, openrouter_key } = req.body;

    if (id) {
      // Update
      const updates = { name, fb_page_id, ai_model, knowledge_base };
      if (verify_token && !isMasked(verify_token)) updates.verify_token = encryptSecret(verify_token);
      if (access_token && !isMasked(access_token)) updates.access_token = encryptSecret(access_token);
      if (openrouter_key && !isMasked(openrouter_key)) updates.openrouter_key = encryptSecret(openrouter_key);

      const { error } = await supabase.from('fb_pages').update(updates).eq('id', id).eq('profile_id', req.user.id);
      if (error) throw error;
    } else {
      // Insert
      const { error } = await supabase.from('fb_pages').insert([{
        profile_id: req.user.id,
        name,
        fb_page_id,
        verify_token: encryptSecret(verify_token),
        access_token: encryptSecret(access_token),
        ai_model,
        knowledge_base: knowledge_base || [],
        openrouter_key: openrouter_key ? encryptSecret(openrouter_key) : null,
        widget_key: crypto.randomBytes(12).toString('hex')
      }]);
      if (error) throw error;
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
  if (req.user.profile.role !== 'ADMIN') query.eq('profile_id', req.user.id);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/knowledge', requireAuth, async (req, res) => {
  const { id, title, content } = req.body;
  let result;

  if (id) {
    result = await supabase.from('knowledge_entries').update({ title, content }).eq('id', id).eq('profile_id', req.user.id);
  } else {
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

// API: Logs
app.get('/api/logs', requireAuth, async (req, res) => {
  const query = supabase.from('activity_logs').select('*, fb_pages(name, profile_id)').order('created_at', { ascending: false }).limit(100);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  const filtered = req.user.profile.role === 'ADMIN' ? data : data.filter(l => l.fb_pages?.profile_id === req.user.id);
  res.json(filtered);
});

// ==================== WEBSITE WIDGET API (Shopify/HTML Plugin) ====================

app.get('/api/widget/config', async (req, res) => {
  const key = String(req.query.key || '');
  if (!key) return res.status(400).json({ error: 'missing key' });

  const { data: page, error } = await supabase
    .from('fb_pages')
    .select('id,name,ai_model,is_enabled,widget_key,allowed_domains,profile_id')
    .eq('widget_key', key)
    .single();

  if (error || !page || !page.is_enabled) return res.status(404).json({ error: 'widget not found' });

  res.json({ ok: true, pageName: page.name, model: page.ai_model || 'openai/gpt-5.2' });
});

app.post('/api/widget/message', async (req, res) => {
  try {
    const { key, message } = req.body || {};
    if (!key || !message) return res.status(400).json({ error: 'missing key/message' });

    const { data: page, error } = await supabase
      .from('fb_pages')
      .select('*')
      .eq('widget_key', String(key))
      .single();

    if (error || !page || !page.is_enabled) return res.status(404).json({ error: 'widget not found' });

    // Optional domain allowlist check
    const origin = String(req.headers.origin || '');
    if (Array.isArray(page.allowed_domains) && page.allowed_domains.length > 0) {
      const allowed = page.allowed_domains.some(d => origin.includes(String(d)));
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

    const resolvedApiKey = decryptSecret(page.openrouter_key) || process.env.OPENROUTER_API_KEY;
    if (!resolvedApiKey) return res.status(500).json({ error: 'missing OpenRouter key' });

    const aiRes = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: page.ai_model || 'openai/gpt-5.2',
      messages: [
        { role: 'system', content: `You are Blockscom website assistant for ${page.name}. Use this knowledge base:\n${context}${productCatalog}` },
        { role: 'user', content: String(message) }
      ]
    }, { headers: { 'Authorization': `Bearer ${resolvedApiKey}` } });

    const reply = aiRes.data?.choices?.[0]?.message?.content || 'Thanks! Can you share more details?';

    await supabase.from('activity_logs').insert([{ fb_page_id: page.id, type: 'WIDGET_REPLY', payload: { in: message, out: reply } }]);

    res.json({ ok: true, reply });
  } catch (e) {
    res.status(500).json({ error: e.message || 'internal error' });
  }
});

// ==================== WEBHOOK LOGIC ====================

// Helper to process a single message event
async function processMessage(event, fbPageId) {
  console.log('--- START PROCESS MESSAGE ---');
  const senderId = event.sender.id;
  const messageText = event.message.text;
  const targetPageId = String(fbPageId);

  console.log(`[DEBUG] Processing message from ${senderId} to Page ID ${targetPageId}`);

  try {
    console.log(`[DEBUG] Fetching config for Page ID: ${targetPageId}`);
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
      console.log(`[DEBUG] Page ${page.name} (ID: ${targetPageId}) is disabled. Skipping message.`);
      return;
    }

    const userProfile = page.profiles;
    console.log(`[DEBUG] Found page: ${page.name}. Credits: ${userProfile?.credits}, Role: ${userProfile?.role}`);

    if (userProfile && userProfile.role !== 'ADMIN' && (userProfile.credits || 0) <= 0) {
      console.log(`[DEBUG] User ${userProfile.email} out of credits.`);
      return;
    }

    // 3. Build Context (Knowledge Base)
    console.log(`[DEBUG] Building knowledge base for user ${page.profile_id}...`);
    let kbQuery = supabase.from('knowledge_entries').select('content, title').eq('profile_id', page.profile_id);

    // Filter by specific files if defined
    if (Array.isArray(page.knowledge_base) && page.knowledge_base.length > 0) {
      console.log(`[DEBUG] Filtering KB by titles: ${page.knowledge_base.join(', ')}`);
      kbQuery = kbQuery.in('title', page.knowledge_base);
    }

    const { data: kb, error: kbError } = await kbQuery;
    if (kbError) console.error(`[ERROR] KB Query failed:`, kbError);
    const context = (kb || []).map(k => k.content).join('\n\n');
    console.log(`[DEBUG] KB Context length: ${context.length} characters.`);

    // 3b. Fetch Product Catalog
    console.log(`[DEBUG] Fetching product catalog for user ${page.profile_id}...`);
    const { data: products, error: prodError } = await supabase
      .from('products')
      .select('*')
      .eq('profile_id', page.profile_id)
      .eq('is_active', true);

    let productCatalog = "";
    if (prodError) {
      console.warn(`[WARN] Products query failed (table might not exist yet):`, prodError.message);
    } else if (products && products.length > 0) {
      productCatalog = "\n\nPRODUCT CATALOG:\n" + products.map(p =>
        `- ${p.name}: ${p.description} (Price: $${p.price}, Stock: ${p.stock_quantity})`
      ).join('\n');
    }
    console.log(`[DEBUG] Product catalog items found: ${products?.length || 0}`);

    // 4. Get AI Response
    console.log(`[DEBUG] Requesting AI completion from OpenRouter (${page.ai_model || 'default'})...`);
    // Decrypt keys
    const openRouterKey = decryptSecret(page.openrouter_key) || process.env.OPENROUTER_API_KEY;
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
        model: page.ai_model || 'openai/gpt-5.2', // Fallback model
        messages: [
          {
            role: 'system',
            content: `You are a helpful AI assistant for the Facebook page "${page.name}".
            
            KNOWLEDGE BASE:
            ${context}
            ${productCatalog}
            
            INSTRUCTIONS:
            - Answer based on the knowledge base and product catalog if relevant.
            - If a user asks about products, recommend items from the catalog.
            - Be polite and professional.
            - Keep answers concise for chat.
            `
          },
          { role: 'user', content: messageText }
        ]
      },
      {
        headers: {
          'Authorization': `Bearer ${openRouterKey}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://blockscom.ai', // OpenRouter requirements
          'X-Title': 'Blockscom AI'
        }
      }
    );

    const replyText = aiRes.data.choices?.[0]?.message?.content || "I'm not sure how to respond to that.";
    console.log(`[DEBUG] AI Reply: ${replyText.substring(0, 50)}...`);

    // 5. Send Reply to Facebook
    console.log(`[DEBUG] Sending reply to FB recipient ${senderId}...`);
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
    console.log(`[DEBUG] Facebook API status: ${fbRes.status}`);

    // 6. Log & Deduct Credits
    await supabase.from('activity_logs').insert([{
      fb_page_id: page.id,
      type: 'AUTO_REPLY',
      payload: { in: messageText, out: replyText }
    }]);

    if (userProfile && userProfile.role !== 'ADMIN') {
      await supabase.from('profiles').update({ credits: (userProfile.credits || 0) - 1 }).eq('id', page.profile_id);
    }

  } catch (err) {
    console.error('Error processing message:', err.message);
    if (err.response) {
      console.error('API Response data:', err.response.data);
    }
    // Attempt to log error if possible
  }
}

app.get('/webhook', async (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token) {
    const { data: pages, error } = await supabase.from('fb_pages').select('verify_token');

    if (error) {
      console.error('Webhook verification DB error:', error);
      return res.sendStatus(500);
    }

    // Check if ANY page matches the verify token
    const isValid = pages.some(p => {
      const decrypted = decryptSecret(p.verify_token);
      return decrypted === token;
    });

    if (isValid) {
      console.log('WEBHOOK_VERIFIED');
      res.status(200).send(challenge);
    } else {
      console.warn('Webhook verification failed: Invalid token');
      res.sendStatus(403);
    }
  } else {
    res.sendStatus(403);
  }
});

app.post('/webhook', async (req, res) => {
  const body = req.body;

  if (body.object === 'page') {
    res.status(200).send('EVENT_RECEIVED'); // Immediate ack to Facebook

    for (const entry of body.entry) {
      // Get the page ID from the entry
      const fbPageId = entry.id;

      // Handle messaging events
      if (entry.messaging) {
        for (const event of entry.messaging) {
          if (event.message && event.message.text) {
            // Process in background (async)
            processMessage(event, fbPageId);
          }
        }
      }
    }
  } else {
    res.sendStatus(404);
  }
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => console.log(`BLOCKSCOM SAAS live on ${PORT}`));
}

module.exports = app;
