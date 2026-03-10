require('dotenv').config();
const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_API_KEY_UNLIMITED = process.env.OPENROUTER_API_KEY_UNLIMITED;
const OPENROUTER_API_KEY_LIMITED = process.env.OPENROUTER_API_KEY_LIMITED;
const OPENROUTER_ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

const KLING_ACCESS_KEY = process.env.KLING_ACCESS_KEY;
const KLING_SECRET_KEY = process.env.KLING_SECRET_KEY;

if (!OPENROUTER_API_KEY && !OPENROUTER_API_KEY_UNLIMITED) {
  console.warn('WARNING: OPENROUTER_API_KEY sets are not fully configured in the .env file.');
}
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('ERROR: SUPABASE_URL and SUPABASE_KEY are required.');
  process.exit(1);
}
if (!KLING_ACCESS_KEY || !KLING_SECRET_KEY) {
  console.warn('WARNING: KLING_ACCESS_KEY and/or KLING_SECRET_KEY are not configured.');
}

let cachedKlingToken = null;
let klingTokenExpiration = 0;

const generateKlingToken = () => {
  const nowStr = Math.floor(Date.now() / 1000);

  // Reuse token if it's still valid for at least 5 more minutes
  if (cachedKlingToken && klingTokenExpiration > nowStr + 300) {
    return cachedKlingToken;
  }

  const payload = {
    iss: KLING_ACCESS_KEY,
    exp: nowStr + (60 * 30), // 30 minutes
    nbf: nowStr - 5          // 5 seconds in the past — just enough for clock skew
  };

  cachedKlingToken = jwt.sign(payload, KLING_SECRET_KEY, {
    algorithm: 'HS256',
    header: { alg: 'HS256', typ: 'JWT' }
  });

  klingTokenExpiration = payload.exp;
  return cachedKlingToken;
};

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const getAuthHeader = (version) => {
  // Always use LIMITED for TEST, UNLIMITED for ADMIN
  const keyToUse = version === 'ADMIN' ? OPENROUTER_API_KEY_UNLIMITED : OPENROUTER_API_KEY_LIMITED;
  return `Bearer ${keyToUse || OPENROUTER_API_KEY}`;
};

// Trust proxy if deployed on Vercel/Render/etc to get real IP
app.set('trust proxy', 1);

const authMiddleware = async (req, res, next) => {
  try {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const version = req.body?.version || req.headers['x-api-version'] || req.query?.version || 'TEST';
    const password = req.body?.password || req.headers['x-admin-password'] || req.query?.password || '';

    // Check if IP is banned
    const { data: bannedData } = await supabase
      .from('bannedip')
      .select('banned_until')
      .eq('ip_address', ip)
      .single();

    if (bannedData && new Date(bannedData.banned_until) > new Date()) {
      return res.status(403).json({ error: { message: `Your IP is temporarily banned until ${new Date(bannedData.banned_until).toLocaleString()}.` } });
    }

    if (version === 'ADMIN') {
      if (!password) {
        return res.status(401).json({ error: { message: 'Admin password is required.' } });
      }

      // Check password
      const { data: dbPassword } = await supabase
        .from('passwordimagegenerator')
        .select('id')
        .eq('password', password)
        .single();

      if (!dbPassword) {
        // Increment failed attempts
        const { data: ipData } = await supabase.from('ip_usage').select('failed_attempts').eq('ip_address', ip).single();
        const attempts = (ipData?.failed_attempts || 0) + 1;

        await supabase.from('ip_usage').upsert([
          { ip_address: ip, failed_attempts: attempts, last_attempt: new Date() }
        ]);

        if (attempts >= 10) {
          // Ban for 5 hours
          const banUntil = new Date(Date.now() + 5 * 60 * 60 * 1000);
          await supabase.from('bannedip').insert([{ ip_address: ip, banned_until: banUntil }]);
          // Reset attempts
          await supabase.from('ip_usage').update({ failed_attempts: 0 }).eq('ip_address', ip);
          return res.status(403).json({ error: { message: 'Too many failed attempts. Your IP has been banned for 5 hours.' } });
        }

        return res.status(401).json({ error: { message: `Invalid admin password. ${10 - attempts} tries remaining.` } });
      }

      // Valid password, reset failed attempts
      await supabase.from('ip_usage').upsert([{ ip_address: ip, failed_attempts: 0 }]);
      return next();
    }

    // TEST Version Logic
    if (version === 'TEST') {
      // Analysis + Kling video endpoints don't consume image-generation tries
      if (
        req.path.startsWith('/api/kling') ||
        req.path === '/api/save-video' ||
        req.path === '/api/analyze'
      ) {
        return next();
      }

      const { data: ipData } = await supabase.from('ip_usage').select('usages').eq('ip_address', ip).single();
      const usages = ipData?.usages || 0;

      if (usages >= 5) {
        return res.status(403).json({ error: { message: 'You have reached the maximum of 5 free image generation tries. Please use the Admin mode with a password.' } });
      }

      // Increment usage
      await supabase.from('ip_usage').upsert([{ ip_address: ip, usages: usages + 1, last_attempt: new Date() }]);

      // Inject usages into req object so endpoint can potentially return it.
      req.remainingTries = 4 - usages;
      return next();
    }

    return res.status(400).json({ error: { message: 'Invalid version specified.' } });
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(500).json({ error: { message: 'Internal server error during authentication.' } });
  }
};

// Parse JSON bodies — increase limit for base64 image payloads
app.use(express.json({ limit: '200mb' }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// ─── Proxy: Image Generation ────────────────────────────────────────────────
app.post('/api/generate', authMiddleware, async (req, res) => {
  try {
    const { model, messages, seed, version } = req.body;

    if (!model || !messages) {
      return res.status(400).json({ error: { message: 'Missing required fields: model, messages' } });
    }

    const payload = { model, messages };
    if (seed !== undefined && seed !== null) {
      payload.seed = seed;
    }

    const response = await fetch(OPENROUTER_ENDPOINT, {
      method: 'POST',
      headers: {
        'Authorization': getAuthHeader(version),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const responseText = await response.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (parseErr) {
      console.error('Failed to parse OpenRouter response:', responseText.slice(0, 500));
      return res.status(502).json({ error: { message: `OpenRouter returned invalid response (HTTP ${response.status}). This may be a timeout or the image payload was too large.` } });
    }

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    if (req.remainingTries !== undefined) {
      data.remainingTries = req.remainingTries;
    }

    return res.json(data);
  } catch (error) {
    console.error('Generate proxy error:', error);
    return res.status(500).json({ error: { message: error.message || 'Internal server error during image generation.' } });
  }
});

// ─── Proxy: Image Analysis (Recreate Feature) ──────────────────────────────
app.post('/api/analyze', authMiddleware, async (req, res) => {
  try {
    const { model, messages, max_tokens, temperature, version } = req.body;

    if (!model || !messages) {
      return res.status(400).json({ error: { message: 'Missing required fields: model, messages' } });
    }

    const payload = { model, messages };
    if (max_tokens !== undefined) payload.max_tokens = max_tokens;
    if (temperature !== undefined) payload.temperature = temperature;

    const response = await fetch(OPENROUTER_ENDPOINT, {
      method: 'POST',
      headers: {
        'Authorization': getAuthHeader(version),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    if (req.remainingTries !== undefined) {
      data.remainingTries = req.remainingTries;
    }

    return res.json(data);
  } catch (error) {
    console.error('Analyze proxy error:', error.message);
    return res.status(500).json({ error: { message: 'Internal server error during analysis.' } });
  }
});

// ─── Proxy: Kling AI Video Generation ──────────────────────────────
app.post('/api/kling/generate', authMiddleware, async (req, res) => {
  try {
    const { model_name, prompt, image, image_tail, duration, mode, aspect_ratio, type = 'image2video' } = req.body;

    if (!model_name) {
      return res.status(400).json({ error: { message: 'Missing model_name' } });
    }

    const token = generateKlingToken();
    let endpoint = `/v1/videos/${type}`;
    const usesOmniEndpoint = model_name === 'kling-v3-omni' || model_name === 'kling-video-o1';
    if (usesOmniEndpoint) {
      endpoint = '/v1/videos/omni-video'; // Use omni endpoint for omni models
    }
    const url = `https://api-singapore.klingai.com${endpoint}`;

    const stripBase64Prefix = (dataStr) => {
      if (!dataStr) return dataStr;
      if (dataStr.includes(',')) {
        return dataStr.split(',')[1];
      }
      return dataStr;
    };

    const payload = { model_name };
    if (prompt) payload.prompt = prompt;
    if (image) payload.image = stripBase64Prefix(image);
    if (image_tail) payload.image_tail = stripBase64Prefix(image_tail);
    if (duration) payload.duration = duration;
    if (mode) payload.mode = mode;
    // If image is present, Kling image2video API automatically adapts aspect ratio.
    // Specifying aspect_ratio causes the API to ignore or crop the original image dimensions
    // which leads to inconsistent characters.
    // Omni models still require aspect_ratio even when an image is supplied.
    if (aspect_ratio && (!image || usesOmniEndpoint)) payload.aspect_ratio = aspect_ratio;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      // If Kling rejects the token as invalid, clear the cache so it regenerates on next request
      if (response.status === 401) {
        cachedKlingToken = null;
        klingTokenExpiration = 0;
      }
      return res.status(response.status).json(data);
    }

    if (req.remainingTries !== undefined) {
      data.remainingTries = req.remainingTries;
    }

    return res.json(data);
  } catch (error) {
    console.error('Kling Generate proxy error:', error);
    return res.status(500).json({ error: { message: error.message || 'Internal server error during video generation.' } });
  }
});

// ─── Proxy: Kling AI Task Status ────────────────────────────────────
app.get('/api/kling/task/:taskId', authMiddleware, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { type = 'image2video', model_name } = req.query; // e.g. type=image2video or text2video

    let endpoint = `/v1/videos/${type}/${taskId}`;
    if (model_name === 'kling-v3-omni' || model_name === 'kling-video-o1') {
      endpoint = `/v1/videos/omni-video/${taskId}`;
    }

    const token = generateKlingToken();
    const url = `https://api-singapore.klingai.com${endpoint}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    return res.json(data);
  } catch (error) {
    console.error('Kling Task proxy error:', error);
    return res.status(500).json({ error: { message: error.message || 'Internal server error fetching task status.' } });
  }
});

// ─── Proxy: Save Video locally ──────────────────────────────────────────────
app.post('/api/save-video', authMiddleware, async (req, res) => {
  try {
    const { videoUrl, taskId } = req.body;

    if (!videoUrl || !taskId) {
      return res.status(400).json({ error: { message: 'Missing videoUrl or taskId' } });
    }

    const downloadsDir = path.join(__dirname, 'public', 'downloads');
    if (!fs.existsSync(downloadsDir)) {
      fs.mkdirSync(downloadsDir, { recursive: true });
    }

    const filePath = path.join(downloadsDir, `${taskId}.mp4`);

    const videoResponse = await fetch(videoUrl);
    if (!videoResponse.ok) {
      throw new Error(`Failed to fetch video from remote server: ${videoResponse.statusText}`);
    }

    const arrayBuffer = await videoResponse.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    fs.writeFileSync(filePath, buffer);

    return res.json({ success: true, filePath: `/downloads/${taskId}.mp4` });
  } catch (error) {
    console.error('Save Video error:', error);
    return res.status(500).json({ error: { message: error.message || 'Internal server error saving video.' } });
  }
});

// ─── Fallback: Serve index.html for SPA-like behavior ──────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const startServer = (port) => {
  const server = app.listen(port, () => {
    console.log(`Nano Banana Studio running at http://localhost:${port}`);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`Port ${port} is in use, trying another port...`);
      setTimeout(() => {
        server.close();
        startServer(port + 1);
      }, 1000);
    } else {
      console.error(err);
    }
  });
};

startServer(typeof PORT === 'string' ? parseInt(PORT, 10) : PORT);

