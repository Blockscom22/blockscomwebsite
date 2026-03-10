const API_ENDPOINT = '/api/studio/generate';
const ANALYZE_ENDPOINT = '/api/studio/analyze';
const ANALYSIS_MODEL = 'openai/gpt-5.4';
// API key is now managed server-side only — never expose secrets in client code.

// ─── Auth token from parent dashboard (iframe mode) ───
const isEmbeddedStudio = window.parent !== window;
let studioProfile = null;
let parentAuthToken = null;
let standaloneSupabase = null;

const postToParent = (payload) => {
  if (!isEmbeddedStudio) return;
  window.parent.postMessage(payload, window.location.origin);
};

window.addEventListener('message', (event) => {
  if (event.origin !== window.location.origin) return;

  if (event.data?.type === 'AUTH_TOKEN') {
    parentAuthToken = event.data.token;
    loadStudioMediaGallery({ force: true }).catch((error) => {
      console.warn('Failed to load studio media after auth sync.', error);
    });
  }

  if (event.data?.type === 'STUDIO_PROFILE' && event.data.profile) {
    studioProfile = { ...(studioProfile || {}), ...event.data.profile };
    const syncedCredits = Number(studioProfile.credits);
    const creditBalanceEl = document.getElementById('credit-balance');
    if (creditBalanceEl && Number.isFinite(syncedCredits)) {
      creditBalanceEl.textContent = `${syncedCredits.toLocaleString()} Credits`;
    }
  }
});

if (isEmbeddedStudio) {
  document.body.classList.add('embedded-dashboard');
  postToParent({ type: 'REQUEST_AUTH' });
}

const form = document.getElementById('generator-form');
const promptInput = document.getElementById('prompt');
const aspectSelect = document.getElementById('aspect');
const countRange = document.getElementById('count');
const countValue = document.getElementById('count-value');
const seedInput = document.getElementById('seed');
const paletteSelect = document.getElementById('palette');
const moodSelect = document.getElementById('mood');
const styleTags = document.getElementById('style-tags');
const modelSelect = document.getElementById('model-select');
const featureTabs = document.querySelectorAll('[data-feature-tab]');
const featurePanels = document.querySelectorAll('[data-feature-panel]');
const generateBar = document.getElementById('generate-bar');
const recreateEditor = document.getElementById('recreate-editor');
const galleryTitle = document.getElementById('gallery-title');
const galleryEmptyText = document.getElementById('gallery-empty-text');

// Local Storage (IndexedDB)
const DB_NAME = 'NanoBananaDB';
const STORE_NAME = 'images';
const DB_VERSION = 2;

let db;

const initDB = () => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = (e) => reject('IndexedDB error: ' + e.target.error);
    request.onsuccess = (e) => {
      db = e.target.result;
      resolve(db);
    };
    request.onupgradeneeded = (e) => {
      db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
      }
      if (!db.objectStoreNames.contains('uploads')) {
        db.createObjectStore('uploads', { keyPath: 'id', autoIncrement: true });
      }
    };
  });
};

const saveGalleryItem = (src) => {
  return new Promise((resolve, reject) => {
    if (!db) return resolve(null);
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.add({ src, timestamp: Date.now() });
    request.onsuccess = (e) => resolve(e.target.result);
    request.onerror = (e) => reject('Save error: ' + e.target.error);
  });
};

const deleteGalleryItem = (id) => {
  return new Promise((resolve, reject) => {
    if (!db) return resolve();
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.delete(id);
    request.onsuccess = () => resolve();
    request.onerror = (e) => reject('Delete error: ' + e.target.error);
  });
};

const loadGallery = () => {
  return new Promise((resolve, reject) => {
    if (!db) return resolve([]);
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.getAll();
    request.onsuccess = (e) => {
      const items = e.target.result;
      items.sort((a, b) => b.timestamp - a.timestamp); // newest first
      resolve(items);
    };
    request.onerror = (e) => reject('Load error: ' + e.target.error);
  });
};

const UPLOADS_STORE = 'uploads';

const saveUploadedImage = (src) => {
  return new Promise((resolve, reject) => {
    if (!db) return resolve(null);
    const transaction = db.transaction([UPLOADS_STORE], 'readwrite');
    const store = transaction.objectStore(UPLOADS_STORE);

    // Check if it already exists to avoid duplicates taking up space
    const indexRequest = store.getAll();
    indexRequest.onsuccess = (e) => {
      const existing = e.target.result.find(item => item.src === src);
      if (existing) {
        // Just update timestamp
        existing.timestamp = Date.now();
        store.put(existing).onsuccess = () => resolve(existing.id);
      } else {
        // Add new
        const request = store.add({ src, timestamp: Date.now() });
        request.onsuccess = (e) => {
          // Keep only latest 50
          const countReq = store.count();
          countReq.onsuccess = () => {
            if (countReq.result > 50) {
              const allReq = store.getAll();
              allReq.onsuccess = (ev) => {
                const items = ev.target.result;
                items.sort((a, b) => a.timestamp - b.timestamp); // oldest first
                const toDelete = items.length - 50;
                for (let i = 0; i < toDelete; i++) {
                  store.delete(items[i].id);
                }
              };
            }
          };
          resolve(e.target.result);
        };
        request.onerror = (e) => reject('Save upload error: ' + e.target.error);
      }
    };
    indexRequest.onerror = (e) => reject('Check upload error: ' + e.target.error);
  });
};

const loadUploadedImages = () => {
  return new Promise((resolve, reject) => {
    if (!db) return resolve([]);
    const transaction = db.transaction([UPLOADS_STORE], 'readonly');
    const store = transaction.objectStore(UPLOADS_STORE);
    const request = store.getAll();
    request.onsuccess = (e) => {
      const items = e.target.result;
      items.sort((a, b) => b.timestamp - a.timestamp); // newest first
      resolve(items);
    };
    request.onerror = (e) => reject('Load uploads error: ' + e.target.error);
  });
};

let studioMediaLoaded = false;

const normalizeStudioMediaItem = (item) => ({
  id: item?.id,
  taskId: item?.taskId || '',
  mediaType: item?.mediaType || (/\.mp4($|\?)/i.test(item?.src || '') ? 'video' : 'image'),
  src: item?.src || '',
  promptText: item?.promptText || '',
  modelName: item?.modelName || '',
  aspectRatio: item?.aspectRatio || '',
  createdAt: item?.createdAt || ''
});

const saveGeneratedMediaToSupabase = async (payload) => {
  const response = await fetch('/api/studio/media', {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const message = data?.error?.message || data?.message || 'Failed to save generated media.';
    throw new Error(message);
  }

  return normalizeStudioMediaItem(data?.media || {});
};

const deleteGeneratedMediaFromSupabase = async (mediaId) => {
  const response = await fetch(`/api/studio/media/${mediaId}`, {
    method: 'DELETE',
    headers: buildHeaders()
  });

  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const message = data?.error?.message || data?.message || 'Failed to delete generated media.';
    throw new Error(message);
  }
};

const fetchGeneratedMediaFromSupabase = async () => {
  const response = await fetch('/api/studio/media', {
    headers: buildHeaders()
  });

  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const message = data?.error?.message || data?.message || 'Failed to load generated media.';
    throw new Error(message);
  }

  return Array.isArray(data?.media) ? data.media.map(normalizeStudioMediaItem) : [];
};

const loadStudioMediaGallery = async ({ force = false } = {}) => {
  if (!parentAuthToken) return;
  if (studioMediaLoaded && !force) return;

  const items = await fetchGeneratedMediaFromSupabase();
  galleryGrid.innerHTML = '';

  if (!items.length) {
    imageCount.textContent = '0';
    galleryEmpty.style.display = 'flex';
    studioMediaLoaded = true;
    return;
  }

  galleryEmpty.style.display = 'none';

  items.forEach((item, idx) => {
    const card = document.createElement('div');
    card.className = 'card bg-white/5 border border-white/10 rounded-2xl p-4 flex flex-col gap-3 min-h-[300px] mt-4 fade-in';
    galleryGrid.appendChild(card);
    if (item.mediaType === 'video') {
      replaceSkeletonWithVideo(card, item.src, idx, item).catch(console.warn);
    } else {
      replaceSkeletonWithImage(card, item.src, idx, { savedMedia: item }).catch(console.warn);
    }
  });

  imageCount.textContent = String(items.length);
  studioMediaLoaded = true;
};

// Drop Zones & Inputs
const dropReference = document.getElementById('drop-reference');
const referenceInput = document.getElementById('reference-images');
const referencePreview = document.getElementById('reference-preview');

const dropCharacter = document.getElementById('drop-character');
const characterInput = document.getElementById('character-images');
const characterPreview = document.getElementById('character-preview');

const dropScene = document.getElementById('drop-scene');
const sceneInput = document.getElementById('scene-image');
const scenePreview = document.getElementById('scene-preview');

const dropStyle = document.getElementById('drop-style');
const styleInput = document.getElementById('style-image');
const stylePreview = document.getElementById('style-preview');

const dropRecreateReference = document.getElementById('drop-recreate-reference');
const recreateReferenceInput = document.getElementById('recreate-reference');
const recreateReferencePreview = document.getElementById('recreate-reference-preview');
const recreateAnalyzeBtn = document.getElementById('recreate-analyze');
const recreateStatus = document.getElementById('recreate-status');
const recreateModelSelect = document.getElementById('recreate-model-select');
const recreateNotes = document.getElementById('recreate-notes');
const recreateSummary = document.getElementById('recreate-summary');
const recreateElements = document.getElementById('recreate-elements');
const recreateElementsCount = document.getElementById('recreate-elements-count');
const recreateRunBtn = document.getElementById('recreate-run');

// Product Feature Elements
const dropProductReference = document.getElementById('drop-product-reference');
const productReferenceInput = document.getElementById('product-reference');
const productReferencePreview = document.getElementById('product-reference-preview');
const dropProductCharacter = document.getElementById('drop-product-character');
const productCharacterInput = document.getElementById('product-character');
const productCharacterPreview = document.getElementById('product-character-preview');
const productAnalyzeBtn = document.getElementById('product-analyze');
const productAnalysisSummary = document.getElementById('product-analysis-summary');
const productAnalysisText = document.getElementById('product-analysis-text');
const productSuggestionsContainer = document.getElementById('product-suggestions-container');
const productViewPromptsBtn = document.getElementById('product-view-prompts');
const productGenerateBtn = document.getElementById('product-generate');
const productSelectedPromptEl = document.getElementById('product-selected-prompt');
const productSelectedTextEl = document.getElementById('product-selected-text');

// Product Modal Elements
const productPromptsModal = document.getElementById('product-prompts-modal');
const productModalBackdrop = document.getElementById('product-modal-backdrop');
const productModalClose = document.getElementById('product-modal-close');
const productModalLoading = document.getElementById('product-modal-loading');
const productModalResults = document.getElementById('product-modal-results');
const productModalList = document.getElementById('product-modal-list');
const productModalSelected = document.getElementById('product-modal-selected');
const productModalSelectedText = document.getElementById('product-modal-selected-text');
const productModalModel = document.getElementById('product-modal-model');
const productModalGenerate = document.getElementById('product-modal-generate');
const productModalError = document.getElementById('product-modal-error');
const productModalErrorText = document.getElementById('product-modal-error-text');
const productModalRetry = document.getElementById('product-modal-retry');

// Video Elements
const dropVideoStart = document.getElementById('drop-video-start');
const videoStartInput = document.getElementById('video-start');
const videoStartPreview = document.getElementById('video-start-preview');
const dropVideoEnd = document.getElementById('drop-video-end');
const videoEndInput = document.getElementById('video-end');
const videoEndPreview = document.getElementById('video-end-preview');
const videoModelSelect = document.getElementById('video-model');
const videoAspectSelect = document.getElementById('video-aspect');
const videoDurationSelect = document.getElementById('video-duration');
const videoPrompt = document.getElementById('video-prompt');
const videoAiGenerateBtn = document.getElementById('video-ai-generate');
const videoAiPlan = document.getElementById('video-ai-plan');
const videoAiSummary = document.getElementById('video-ai-summary');
const videoAiEffects = document.getElementById('video-ai-effects');
const videoCopyAiJsonBtn = document.getElementById('video-copy-ai-json');
const videoGenerateBtn = document.getElementById('video-generate');
const videoStatus = document.getElementById('video-status');

// Image Editor Elements
const editorModal = document.getElementById('editor-modal');
const editorCanvas = document.getElementById('editor-canvas');
const editorLoading = document.getElementById('editor-loading');
const editorTextInput = document.getElementById('editor-text-input');
const editorSave = document.getElementById('editor-save');
const editorCancel = document.getElementById('editor-cancel');
const editorReset = document.getElementById('editor-reset');
const editorColorButtons = document.querySelectorAll('.editor-color-btn');
const toolDraw = document.getElementById('tool-draw');
const toolText = document.getElementById('tool-text');
const editorBrushSize = document.getElementById('editor-brush-size');
const editorBrushLabel = document.getElementById('editor-brush-label');


const galleryGrid = document.getElementById('gallery-grid');
const galleryEmpty = document.getElementById('gallery-empty');
// const loadingOverlay = document.getElementById('loading-overlay'); // Removed global loader
const imageCount = document.getElementById('image-count');
const statusEl = document.getElementById('status');
const creditBalanceEl = document.getElementById('credit-balance');
const studioBackLink = document.getElementById('studio-back-link');
const errorEl = document.getElementById('error');
const surpriseBtn = document.getElementById('surprise-btn');
const clearBtn = document.getElementById('clear');
const generateBtn = document.getElementById('generate');

const aspectHints = {
  '1:1': 'Aspect ratio 1:1 (square).',
  '16:9': 'Aspect ratio 16:9 (landscape).',
  '9:16': 'Aspect ratio 9:16 (portrait).'
};

const surprisePrompts = [
  'A candlelit watchmaker studio, warm glow, macro lens, ultra detailed',
  'A futuristic botanical lab, teal and ember palette, cinematic lighting',
  'A misty cliffside cafe, soft grain, moody and atmospheric',
  'A vintage bicycle shop in golden hour, high contrast, close up',
  'Cyberpunk street food stall, neon rain, isometric view'
];

const state = {
  referenceImages: [],
  characterImages: [],
  sceneImage: null,
  styleImage: null,
  activeRequests: 0,
  queueLimit: 3
};

let activeFeature = 'generate';

const recreateState = {
  referenceImage: null,
  analysis: null,
  elements: [],
  overrides: {},
  isAnalyzing: false,
  isRecreating: false
};

const MAX_PRODUCT_REFERENCES = 6;

const productState = {
  referenceImages: [],
  characterImage: null,
  isAnalyzing: false,
  selectedPrompt: null,
  analysis: null
};

const videoState = {
  startFrame: null,
  endFrame: null,
  isGenerating: false,
  isPromptGenerating: false,
  taskId: null,
  promptPlan: null,
  promptSource: null
};

const editorCtx = editorCanvas ? editorCanvas.getContext('2d') : null;

const editorState = {
  isOpen: false,
  tool: 'draw',
  color: '#ff4d4d',
  brushSize: 6,
  isDrawing: false,
  baseDataUrl: null,
  onSave: null
};

let lastPrompt = '';

const setStatus = (text) => {
  if (statusEl) statusEl.textContent = text;
};

const setError = (text) => {
  if (errorEl) errorEl.textContent = text || '';
};

const setLoading = (isLoading) => {
  if (!generateBtn) return;
  generateBtn.setAttribute('aria-busy', isLoading ? 'true' : 'false');
  generateBtn.classList.toggle('opacity-70', isLoading);
};

const setActiveFeature = (feature) => {
  activeFeature = feature;
  featureTabs.forEach((tab) => {
    const isActive = tab.dataset.featureTab === feature;
    tab.classList.toggle('active', isActive);
    tab.setAttribute('aria-pressed', isActive ? 'true' : 'false');
  });
  featurePanels.forEach((panel) => {
    const isActive = panel.dataset.featurePanel === feature;
    panel.classList.toggle('hidden', !isActive);
  });

  // Close any open dropdowns visually
  document.querySelectorAll('[data-dropdown-toggle][aria-expanded="true"]').forEach(btn => {
    btn.setAttribute('aria-expanded', 'false');
    const targetId = btn.getAttribute('data-dropdown-toggle');
    const targetMenu = document.getElementById(targetId);
    if (targetMenu) {
      targetMenu.classList.add('hidden');
    }
  });

  if (generateBar) {
    if (feature === 'generate') {
      generateBar.classList.remove('hidden');
    } else {
      generateBar.classList.add('hidden');
    }
  }

  if (recreateEditor) recreateEditor.classList.toggle('hidden', feature !== 'recreate');

  if (galleryTitle) {
    if (feature === 'recreate') galleryTitle.textContent = 'Recreate Results';
    else if (feature === 'product') galleryTitle.textContent = 'Product Results';
    else galleryTitle.textContent = 'Gallery';
  }

  if (galleryEmptyText) {
    if (feature === 'recreate') {
      galleryEmptyText.textContent = 'Recreated images will appear here. Analyze a reference image to begin.';
    } else if (feature === 'product') {
      galleryEmptyText.textContent = 'High-quality product images will appear here. First, upload a product reference and generate prompts.';
    } else {
      galleryEmptyText.textContent = 'Results will appear here. Try a sample prompt to get started.';
    }
  }
};

const setRecreateStatus = (text) => {
  if (recreateStatus) recreateStatus.textContent = text || '';
};

const setRecreateAnalyzing = (isLoading) => {
  recreateState.isAnalyzing = isLoading;
  if (!recreateAnalyzeBtn) return;
  recreateAnalyzeBtn.disabled = isLoading;
  recreateAnalyzeBtn.classList.toggle('opacity-60', isLoading);
  recreateAnalyzeBtn.textContent = isLoading ? 'Analyzing...' : 'Analyze Image';
};

const setRecreateRunning = (isLoading) => {
  recreateState.isRecreating = isLoading;
  if (!recreateRunBtn) return;
  recreateRunBtn.disabled = isLoading;
  recreateRunBtn.classList.toggle('opacity-60', isLoading);
  recreateRunBtn.textContent = isLoading ? 'Recreating...' : 'Recreate Image';
};

const setProductAnalyzing = (isLoading) => {
  productState.isAnalyzing = isLoading;
  if (!productAnalyzeBtn) return;
  const isDisabled = isLoading || productState.referenceImages.length === 0;
  productAnalyzeBtn.disabled = isDisabled;
  productAnalyzeBtn.classList.toggle('opacity-60', isDisabled);
  productAnalyzeBtn.innerHTML = isLoading ? '<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Analyzing...' : '<i data-lucide="wand-2" class="w-4 h-4"></i> Generate Prompts';
  if (window.lucide) window.lucide.createIcons({ root: productAnalyzeBtn });
};

const setVideoGenerating = (isLoading) => {
  videoState.isGenerating = isLoading;
  if (!videoGenerateBtn) return;
  const isDisabled = isLoading || videoState.isPromptGenerating || !videoState.startFrame;
  videoGenerateBtn.disabled = isDisabled;
  videoGenerateBtn.classList.toggle('opacity-50', isDisabled);
  videoGenerateBtn.innerHTML = isLoading ? '<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Generating...' : '<i data-lucide="clapperboard" class="w-4 h-4"></i> Generate Video';
  if (videoStatus && isLoading) videoStatus.textContent = 'Starting video generation...';
  if (window.lucide) window.lucide.createIcons({ root: videoGenerateBtn });
  if (videoAiGenerateBtn) {
    const promptBtnDisabled = isLoading || videoState.isPromptGenerating || !videoState.startFrame;
    videoAiGenerateBtn.disabled = promptBtnDisabled;
    videoAiGenerateBtn.classList.toggle('opacity-50', promptBtnDisabled);
  }
};

const setVideoPromptGenerating = (isLoading) => {
  videoState.isPromptGenerating = isLoading;
  if (videoAiGenerateBtn) {
    const isDisabled = isLoading || videoState.isGenerating || !videoState.startFrame;
    videoAiGenerateBtn.disabled = isDisabled;
    videoAiGenerateBtn.classList.toggle('opacity-50', isDisabled);
    videoAiGenerateBtn.innerHTML = isLoading
      ? '<i data-lucide="loader-2" class="w-3 h-3 animate-spin"></i> Generating...'
      : '<i data-lucide="sparkles" class="w-3 h-3"></i> Generate Prompt Using AI';
    if (window.lucide) window.lucide.createIcons({ root: videoAiGenerateBtn });
  }
  if (videoGenerateBtn) {
    const videoDisabled = videoState.isGenerating || isLoading || !videoState.startFrame;
    videoGenerateBtn.disabled = videoDisabled;
    videoGenerateBtn.classList.toggle('opacity-50', videoDisabled);
  }
  if (videoStatus && isLoading) {
    videoStatus.innerHTML = '<i data-lucide="loader-2" class="w-3 h-3 animate-spin inline-block mr-1"></i> Analyzing frames and writing motion prompt...';
    if (window.lucide) window.lucide.createIcons({ root: videoStatus });
  }
};

const resetVideoPromptPlan = ({ clearPrompt = false } = {}) => {
  videoState.promptPlan = null;
  if (videoAiPlan) videoAiPlan.classList.add('hidden');
  if (videoAiSummary) videoAiSummary.textContent = '';
  if (videoAiEffects) videoAiEffects.textContent = '';
  if (videoCopyAiJsonBtn) {
    videoCopyAiJsonBtn.classList.add('hidden');
    videoCopyAiJsonBtn.classList.remove('inline-flex');
  }
  if (clearPrompt || videoState.promptSource === 'ai') {
    if (videoPrompt) videoPrompt.value = '';
    videoState.promptSource = null;
  }
};

const getElementOverride = (elementId) => {
  if (!recreateState.overrides[elementId]) {
    recreateState.overrides[elementId] = { text: '', image: null };
  }
  return recreateState.overrides[elementId];
};

// --- Image Editor Logic ---
const setEditorLoading = (isLoading) => {
  if (!editorLoading) return;
  editorLoading.classList.toggle('hidden', !isLoading);
};

const setEditorTool = (tool) => {
  editorState.tool = tool;
  if (toolDraw) toolDraw.classList.toggle('active', tool === 'draw');
  if (toolText) toolText.classList.toggle('active', tool === 'text');
  if (editorCanvas) {
    editorCanvas.style.cursor = tool === 'text' ? 'text' : 'crosshair';
  }
  if (editorTextInput && !editorTextInput.classList.contains('hidden')) {
    commitTextInput();
  }
};

const setEditorColor = (color) => {
  editorState.color = color;
  editorColorButtons.forEach((button) => {
    button.classList.toggle('active', button.dataset.color === color);
  });
};

const setBrushSize = (value) => {
  const size = Number(value) || editorState.brushSize;
  editorState.brushSize = size;
  if (editorBrushSize) editorBrushSize.value = size;
  if (editorBrushLabel) editorBrushLabel.textContent = `${size}`;
};

const closeEditor = () => {
  if (!editorModal) return;
  editorState.isOpen = false;
  editorState.isDrawing = false;
  editorState.baseDataUrl = null;
  editorState.onSave = null;
  if (editorTextInput) {
    editorTextInput.classList.add('hidden');
    editorTextInput.value = '';
  }
  editorModal.classList.add('hidden');
  editorModal.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('editor-open');
};

const loadImageForEditor = async (source) => {
  if (!source) throw new Error('Missing image source.');
  if (source.startsWith('data:') || source.startsWith('blob:')) return source;

  const response = await fetch(source, { mode: 'cors' });
  if (!response.ok) throw new Error('Image fetch failed.');
  const blob = await response.blob();

  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error('Image read failed.'));
    reader.readAsDataURL(blob);
  });
};

const drawImageToCanvas = (dataUrl) => {
  if (!editorCanvas || !editorCtx) return Promise.reject(new Error('Canvas not ready.'));

  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      editorCanvas.width = img.naturalWidth || img.width;
      editorCanvas.height = img.naturalHeight || img.height;
      editorCtx.clearRect(0, 0, editorCanvas.width, editorCanvas.height);
      editorCtx.drawImage(img, 0, 0, editorCanvas.width, editorCanvas.height);
      resolve();
    };
    img.onerror = () => reject(new Error('Image load failed.'));
    img.src = dataUrl;
  });
};

const openEditor = async (sourceUrl, onSave) => {
  if (!editorModal || !editorCanvas || !editorCtx) return;
  editorState.isOpen = true;
  editorState.onSave = onSave;
  setError('');
  editorModal.classList.remove('hidden');
  editorModal.setAttribute('aria-hidden', 'false');
  document.body.classList.add('editor-open');
  if (editorTextInput) editorTextInput.classList.add('hidden');

  setEditorTool('draw');
  setEditorColor(editorState.color);
  setBrushSize(editorState.brushSize);
  setEditorLoading(true);

  try {
    const dataUrl = await loadImageForEditor(sourceUrl);
    editorState.baseDataUrl = dataUrl;
    await drawImageToCanvas(dataUrl);
  } catch (error) {
    console.error(error);
    setError('Unable to load image for editing.');
    closeEditor();
  } finally {
    setEditorLoading(false);
  }
};

const getCanvasPoint = (event) => {
  const rect = editorCanvas.getBoundingClientRect();
  const wrapRect = editorCanvas.parentElement
    ? editorCanvas.parentElement.getBoundingClientRect()
    : rect;
  const scaleX = editorCanvas.width / rect.width;
  const scaleY = editorCanvas.height / rect.height;
  return {
    x: (event.clientX - rect.left) * scaleX,
    y: (event.clientY - rect.top) * scaleY,
    offsetX: event.clientX - rect.left,
    offsetY: event.clientY - rect.top,
    wrapOffsetX: event.clientX - wrapRect.left,
    wrapOffsetY: event.clientY - wrapRect.top,
    canvasOffsetX: rect.left - wrapRect.left,
    canvasOffsetY: rect.top - wrapRect.top,
    rect,
    wrapRect
  };
};

const beginDrawing = (event) => {
  if (!editorCtx || editorState.tool !== 'draw') return;
  const { x, y } = getCanvasPoint(event);
  editorState.isDrawing = true;
  editorCtx.strokeStyle = editorState.color;
  editorCtx.lineWidth = editorState.brushSize;
  editorCtx.lineJoin = 'round';
  editorCtx.lineCap = 'round';
  editorCtx.beginPath();
  editorCtx.moveTo(x, y);
};

const continueDrawing = (event) => {
  if (!editorCtx || !editorState.isDrawing) return;
  const { x, y } = getCanvasPoint(event);
  editorCtx.lineTo(x, y);
  editorCtx.stroke();
};

const stopDrawing = () => {
  if (!editorCtx) return;
  if (editorState.isDrawing) {
    editorState.isDrawing = false;
    editorCtx.closePath();
  }
};

const showTextInput = (event) => {
  if (!editorTextInput || editorState.tool !== 'text') return;
  if (!editorTextInput.classList.contains('hidden')) {
    commitTextInput();
  }
  const { x, y, wrapOffsetX, wrapOffsetY, rect, canvasOffsetX, canvasOffsetY } = getCanvasPoint(event);
  const minLeft = canvasOffsetX + 10;
  const minTop = canvasOffsetY + 10;
  const maxLeft = canvasOffsetX + rect.width - 180;
  const maxTop = canvasOffsetY + rect.height - 40;
  editorTextInput.style.left = `${Math.min(Math.max(wrapOffsetX, minLeft), Math.max(minLeft, maxLeft))}px`;
  editorTextInput.style.top = `${Math.min(Math.max(wrapOffsetY, minTop), Math.max(minTop, maxTop))}px`;
  editorTextInput.dataset.canvasX = x.toString();
  editorTextInput.dataset.canvasY = y.toString();
  editorTextInput.value = '';
  editorTextInput.classList.remove('hidden');
  requestAnimationFrame(() => editorTextInput.focus());
};

const commitTextInput = () => {
  if (!editorTextInput || editorTextInput.classList.contains('hidden')) return;
  const value = editorTextInput.value.trim();
  const x = Number(editorTextInput.dataset.canvasX || 0);
  const y = Number(editorTextInput.dataset.canvasY || 0);
  editorTextInput.classList.add('hidden');
  if (!value || !editorCtx) return;
  editorCtx.fillStyle = editorState.color;
  editorCtx.font = "600 28px 'Space Grotesk', sans-serif";
  editorCtx.textBaseline = 'top';
  editorCtx.fillText(value, x, y);
};

// Queue Limiter Logic
const updateQueueStatus = () => {
  const remaining = state.queueLimit - state.activeRequests;
  if (remaining <= 0) {
    generateBtn.disabled = true;
    generateBtn.textContent = 'Queue Full (3/3)';
    setStatus('Max 3 concurrent requests');
  } else {
    generateBtn.disabled = false;
    generateBtn.textContent = 'Generate';
    setStatus(state.activeRequests > 0 ? `Generating (${state.activeRequests} active)...` : 'Ready');
  }
};

const updateCount = () => {
  countValue.textContent = countRange.value;
};

const readFileAsDataUrl = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error('File read failed.'));
    reader.readAsDataURL(file);
  });

const getImageSize = (dataUrl) =>
  new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      resolve({
        width: img.naturalWidth || img.width,
        height: img.naturalHeight || img.height
      });
    };
    img.onerror = () => reject(new Error('Image load failed.'));
    img.src = dataUrl;
  });

const loadImageElement = (dataUrl) =>
  new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('Image load failed.'));
    img.src = dataUrl;
  });

const optimizeDataUrlForModel = async (dataUrl, { maxDimension = 1400, quality = 0.8 } = {}) => {
  if (!dataUrl || typeof dataUrl !== 'string' || !dataUrl.startsWith('data:image/')) {
    return dataUrl;
  }

  const image = await loadImageElement(dataUrl);
  const sourceWidth = image.naturalWidth || image.width;
  const sourceHeight = image.naturalHeight || image.height;

  if (!sourceWidth || !sourceHeight) {
    return dataUrl;
  }

  const longestSide = Math.max(sourceWidth, sourceHeight);
  const scale = longestSide > maxDimension ? maxDimension / longestSide : 1;
  const targetWidth = Math.max(1, Math.round(sourceWidth * scale));
  const targetHeight = Math.max(1, Math.round(sourceHeight * scale));

  const canvas = document.createElement('canvas');
  canvas.width = targetWidth;
  canvas.height = targetHeight;

  const ctx = canvas.getContext('2d');
  if (!ctx) return dataUrl;

  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, targetWidth, targetHeight);
  ctx.drawImage(image, 0, 0, targetWidth, targetHeight);

  const optimized = canvas.toDataURL('image/jpeg', quality);
  return optimized.length < dataUrl.length ? optimized : dataUrl;
};

const getOptimizedModelDataUrl = async (item, variant = 'generate') => {
  if (!item?.dataUrl) return null;

  const cacheKey = variant === 'analysis' ? 'analysisDataUrl' : 'modelDataUrl';
  if (item[cacheKey]) return item[cacheKey];

  item[cacheKey] = await optimizeDataUrlForModel(item.dataUrl, variant === 'analysis'
    ? { maxDimension: 1280, quality: 0.72 }
    : { maxDimension: 1536, quality: 0.82 });

  return item[cacheKey];
};

const readFileWithMeta = async (file) => {
  const dataUrl = await readFileAsDataUrl(file);
  let size = null;
  try {
    size = await getImageSize(dataUrl);
  } catch (error) {
    console.warn('Unable to read image size.', error);
  }

  // Save to History Database
  saveUploadedImage(dataUrl).catch(e => console.warn('Failed to save to history', e));

  return {
    dataUrl,
    name: file.name,
    width: size?.width || null,
    height: size?.height || null,
    analysisDataUrl: null,
    modelDataUrl: null
  };
};

const updateImageMeta = async (target, dataUrl) => {
  if (!target) return;
  target.dataUrl = dataUrl;
  target.analysisDataUrl = null;
  target.modelDataUrl = null;
  try {
    const size = await getImageSize(dataUrl);
    target.width = size.width;
    target.height = size.height;
  } catch (error) {
    target.width = null;
    target.height = null;
  }
};

const gcd = (a, b) => (b ? gcd(b, a % b) : a);

const simplifyAspectRatio = (width, height) => {
  const safeWidth = Math.max(1, Math.round(width));
  const safeHeight = Math.max(1, Math.round(height));
  const divisor = gcd(safeWidth, safeHeight) || 1;
  return `${Math.round(safeWidth / divisor)}:${Math.round(safeHeight / divisor)}`;
};

const getReferenceImageForAspect = () => {
  if (activeFeature === 'recreate' && recreateState.referenceImage) {
    return recreateState.referenceImage;
  }
  if (state.referenceImages.length) return state.referenceImages[0];
  if (state.characterImages.length) return state.characterImages[0];
  if (state.sceneImage) return state.sceneImage;
  if (state.styleImage) return state.styleImage;
  return null;
};

const getAspectHint = () => {
  if (aspectSelect.value === 'reference') {
    const ref = getReferenceImageForAspect();
    if (!ref?.width || !ref?.height) return '';
    const ratio = simplifyAspectRatio(ref.width, ref.height);
    return `Use the same size as the reference image (${ref.width}x${ref.height}). Aspect ratio ${ratio}.`;
  }
  return aspectHints[aspectSelect.value];
};

// --- Preview Rendering ---

const renderReferencePreview = () => {
  if (state.referenceImages.length === 0) {
    referencePreview.innerHTML = '';
    referencePreview.classList.add('hidden');
    return;
  }

  referencePreview.classList.remove('hidden');
  referencePreview.innerHTML = '';

  state.referenceImages.forEach((item, index) => {
    const wrapper = document.createElement('div');
    wrapper.className = 'preview-item aspect-square rounded overflow-hidden relative border border-white/20';

    const img = document.createElement('img');
    img.src = item.dataUrl;
    img.className = 'w-full h-full object-cover';
    img.title = 'Click to edit';
    img.addEventListener('click', (e) => {
      e.stopPropagation();
      openEditor(item.dataUrl, (updatedUrl) => {
        updateImageMeta(state.referenceImages[index], updatedUrl).then(renderReferencePreview);
      });
    });

    const removeBtn = document.createElement('button');
    removeBtn.className = 'absolute top-1 right-1 bg-black/50 hover:bg-black/80 text-white rounded-full p-0.5 transition-colors pointer-events-auto';
    removeBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
    removeBtn.type = 'button';
    removeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      state.referenceImages.splice(index, 1);
      renderReferencePreview();
    });

    const downloadBtn = document.createElement('a');
    downloadBtn.className = 'absolute top-1 left-1 bg-black/50 hover:bg-black/80 text-white rounded-full p-0.5 transition-colors pointer-events-auto';
    downloadBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
    downloadBtn.href = item.dataUrl;
    downloadBtn.download = item.name || `reference-${index + 1}.png`;
    downloadBtn.title = 'Download';
    downloadBtn.setAttribute('aria-label', 'Download');
    downloadBtn.addEventListener('click', (e) => e.stopPropagation());

    wrapper.appendChild(img);
    wrapper.appendChild(downloadBtn);
    wrapper.appendChild(removeBtn);
    referencePreview.appendChild(wrapper);
  });
};

const renderCharacterPreview = () => {
  if (state.characterImages.length === 0) {
    characterPreview.innerHTML = '';
    characterPreview.classList.add('hidden');
    return;
  }

  characterPreview.classList.remove('hidden');
  characterPreview.innerHTML = '';

  state.characterImages.forEach((item, index) => {
    const wrapper = document.createElement('div');
    wrapper.className = 'flex flex-col gap-1';

    const imageWrap = document.createElement('div');
    imageWrap.className = 'preview-item aspect-square rounded overflow-hidden relative border border-white/20';

    const img = document.createElement('img');
    img.src = item.dataUrl;
    img.className = 'w-full h-full object-cover';
    img.title = 'Click to edit';
    img.addEventListener('click', (e) => {
      e.stopPropagation();
      openEditor(item.dataUrl, (updatedUrl) => {
        updateImageMeta(state.characterImages[index], updatedUrl).then(renderCharacterPreview);
      });
    });

    const removeBtn = document.createElement('button');
    removeBtn.className = 'absolute top-1 right-1 bg-black/50 hover:bg-black/80 text-white rounded-full p-0.5 transition-colors pointer-events-auto';
    removeBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
    removeBtn.type = 'button';
    removeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      state.characterImages.splice(index, 1);
      renderCharacterPreview();
    });

    const downloadBtn = document.createElement('a');
    downloadBtn.className = 'absolute top-1 left-1 bg-black/50 hover:bg-black/80 text-white rounded-full p-0.5 transition-colors pointer-events-auto';
    downloadBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
    downloadBtn.href = item.dataUrl;
    downloadBtn.download = item.name || `character-${index + 1}.png`;
    downloadBtn.title = 'Download';
    downloadBtn.setAttribute('aria-label', 'Download');
    downloadBtn.addEventListener('click', (e) => e.stopPropagation());

    const specInput = document.createElement('textarea');
    specInput.rows = 2;
    specInput.placeholder = 'Character details...';
    specInput.value = item.spec || '';
    specInput.className =
      'w-full bg-black/30 border border-white/10 rounded-md px-2 py-1 text-[10px] focus:outline-none text-gray-300 placeholder-gray-600 resize-none text-left';
    specInput.addEventListener('input', (event) => {
      state.characterImages[index].spec = event.target.value;
    });

    imageWrap.appendChild(img);
    imageWrap.appendChild(downloadBtn);
    imageWrap.appendChild(removeBtn);
    wrapper.appendChild(imageWrap);
    wrapper.appendChild(specInput);
    characterPreview.appendChild(wrapper);
  });
};

const renderSinglePreview = (container, item, onRemove, onEdit) => {
  if (!item) {
    container.innerHTML = '';
    container.classList.add('hidden');
    return;
  }

  container.classList.remove('hidden');
  container.innerHTML = '';

  const img = document.createElement('img');
  img.src = item.dataUrl;
  img.className = 'w-full h-full object-cover';
  img.title = 'Click to edit';
  if (onEdit) {
    img.addEventListener('click', (e) => {
      e.stopPropagation();
      onEdit();
    });
  }

  const removeBtn = document.createElement('button');
  removeBtn.className = 'absolute top-2 right-2 bg-black/50 hover:bg-black/80 text-white rounded-full p-1 transition-colors z-20 pointer-events-auto';
  removeBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
  removeBtn.type = 'button';
  removeBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    onRemove();
  });

  const downloadBtn = document.createElement('a');
  downloadBtn.className = 'absolute top-2 left-2 bg-black/50 hover:bg-black/80 text-white rounded-full p-1 transition-colors z-20 pointer-events-auto';
  downloadBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
  downloadBtn.href = item.dataUrl;
  downloadBtn.download = item.name || 'input-image.png';
  downloadBtn.title = 'Download';
  downloadBtn.setAttribute('aria-label', 'Download');
  downloadBtn.addEventListener('click', (e) => e.stopPropagation());

  container.appendChild(img);
  container.appendChild(downloadBtn);
  container.appendChild(removeBtn);
};

const refreshScenePreview = () => {
  renderSinglePreview(scenePreview, state.sceneImage, () => {
    state.sceneImage = null;
    refreshScenePreview();
  }, () => {
    if (!state.sceneImage) return;
    openEditor(state.sceneImage.dataUrl, (updatedUrl) => {
      updateImageMeta(state.sceneImage, updatedUrl).then(refreshScenePreview);
    });
  });
};

const refreshStylePreview = () => {
  renderSinglePreview(stylePreview, state.styleImage, () => {
    state.styleImage = null;
    refreshStylePreview();
  }, () => {
    if (!state.styleImage) return;
    openEditor(state.styleImage.dataUrl, (updatedUrl) => {
      updateImageMeta(state.styleImage, updatedUrl).then(refreshStylePreview);
    });
  });
};

const refreshRecreateReferencePreview = () => {
  renderSinglePreview(recreateReferencePreview, recreateState.referenceImage, () => {
    recreateState.referenceImage = null;
    refreshRecreateReferencePreview();
    setRecreateStatus('');
  }, () => {
    if (!recreateState.referenceImage) return;
    openEditor(recreateState.referenceImage.dataUrl, (updatedUrl) => {
      updateImageMeta(recreateState.referenceImage, updatedUrl).then(refreshRecreateReferencePreview);
    });
  });
};

// --- Product Reference UI ---
const resetProductResults = () => {
  productState.analysis = null;
  productState.selectedPrompt = null;

  if (productPromptsModal && !productPromptsModal.classList.contains('hidden')) {
    closeProductModal();
  }

  if (productSuggestionsContainer) productSuggestionsContainer.classList.add('hidden');
  if (productGenerateBtn) productGenerateBtn.disabled = true;
  if (productSelectedPromptEl) productSelectedPromptEl.classList.add('hidden');
  if (productSelectedTextEl) productSelectedTextEl.textContent = '';

  const sidebarVideoContainer = document.getElementById('product-selected-video-container');
  const sidebarVideoEl = document.getElementById('product-selected-video');
  if (sidebarVideoContainer) sidebarVideoContainer.classList.add('hidden');
  if (sidebarVideoEl) sidebarVideoEl.textContent = '';

  if (productModalGenerate) productModalGenerate.disabled = true;
  if (productModalSelected) productModalSelected.classList.add('hidden');
  if (productModalSelectedText) productModalSelectedText.textContent = '';
  if (productModalErrorText) productModalErrorText.textContent = '';
  if (productModalList) productModalList.innerHTML = '';

  const modalVideoContainer = document.getElementById('product-modal-video-container');
  const modalVideoEl = document.getElementById('product-modal-selected-video');
  if (modalVideoContainer) modalVideoContainer.classList.add('hidden');
  if (modalVideoEl) modalVideoEl.textContent = '';

  const sidebarCopyJsonBtn = document.getElementById('product-copy-json-sidebar');
  if (sidebarCopyJsonBtn) {
    sidebarCopyJsonBtn.classList.add('hidden');
    sidebarCopyJsonBtn.classList.remove('flex');
  }
};

const renderProductAnalysisSummary = () => {
  if (!productAnalysisSummary || !productAnalysisText) return;

  const analysis = productState.analysis;
  const products = Array.isArray(analysis?.products) ? analysis.products : [];
  const constraints = Array.isArray(analysis?.bundleRules?.accuracy_constraints)
    ? analysis.bundleRules.accuracy_constraints
    : [];

  if (!analysis?.summary && products.length === 0) {
    productAnalysisSummary.classList.add('hidden');
    productAnalysisText.textContent = '';
    return;
  }

  const productSummary = products.map((product, index) => {
    const title = product.product_label || product.category || `Product ${index + 1}`;
    const details = Array.isArray(product.signature_details) ? product.signature_details.slice(0, 3) : [];
    return details.length ? `${title}: ${details.join(', ')}` : title;
  });

  const parts = [];
  if (analysis?.summary) parts.push(analysis.summary);
  if (productSummary.length) parts.push(`Products: ${productSummary.join(' | ')}.`);
  if (constraints.length) parts.push(`Accuracy rules: ${constraints.slice(0, 3).join(' | ')}.`);

  productAnalysisText.textContent = parts.join(' ');
  productAnalysisSummary.classList.remove('hidden');
};

const renderProductReferencePreview = () => {
  if (!productReferencePreview) return;
  productReferencePreview.innerHTML = '';
  if (productState.referenceImages.length === 0) {
    productReferencePreview.classList.add('hidden');
    productReferencePreview.style.display = '';
    if (dropProductReference) dropProductReference.classList.remove('border-white', 'bg-white/10');
    setProductAnalyzing(false);
    return;
  }
  productReferencePreview.classList.remove('hidden');
  productReferencePreview.style.display = 'grid';
  if (dropProductReference) dropProductReference.classList.add('border-white', 'bg-white/10');
  setProductAnalyzing(productState.isAnalyzing);

  productState.referenceImages.forEach((item, index) => {
    const wrapper = document.createElement('div');
    wrapper.className = 'relative aspect-square rounded-lg overflow-hidden border border-white/10 bg-black/30';

    const img = document.createElement('img');
    img.src = item.dataUrl;
    img.className = 'w-full h-full object-cover';
    img.title = 'Click to edit';
    img.addEventListener('click', (event) => {
      event.stopPropagation();
      openEditor(item.dataUrl, (updatedUrl) => {
        updateImageMeta(productState.referenceImages[index], updatedUrl).then(() => {
          resetProductResults();
          renderProductAnalysisSummary();
          renderProductReferencePreview();
        });
      });
    });

    const badge = document.createElement('span');
    badge.className = 'absolute bottom-1 left-1 px-1.5 py-0.5 rounded bg-black/70 text-[9px] text-white font-mono z-20';
    badge.textContent = `P${index + 1}`;

    const downloadBtn = document.createElement('a');
    downloadBtn.className = 'absolute top-1 left-1 bg-black/50 hover:bg-black/80 text-white rounded-full p-0.5 transition-colors z-20';
    downloadBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
    downloadBtn.href = item.dataUrl;
    downloadBtn.download = item.name || `product-reference-${index + 1}.png`;
    downloadBtn.title = 'Download';
    downloadBtn.setAttribute('aria-label', 'Download');
    downloadBtn.addEventListener('click', (event) => event.stopPropagation());

    const rmBtn = document.createElement('button');
    rmBtn.className = 'absolute top-1 right-1 p-0.5 bg-black/60 rounded-full text-white hover:bg-red-500 transition-colors z-20';
    rmBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
    rmBtn.type = 'button';
    rmBtn.addEventListener('click', (event) => {
      event.stopPropagation();
      productState.referenceImages.splice(index, 1);
      resetProductResults();
      renderProductAnalysisSummary();
      renderProductReferencePreview();
    });

    wrapper.appendChild(img);
    wrapper.appendChild(downloadBtn);
    wrapper.appendChild(rmBtn);
    wrapper.appendChild(badge);
    productReferencePreview.appendChild(wrapper);
  });
};

const renderProductCharacterPreview = () => {
  if (!productCharacterPreview) return;
  productCharacterPreview.innerHTML = '';
  if (!productState.characterImage) {
    productCharacterPreview.classList.add('hidden');
    if (dropProductCharacter) dropProductCharacter.classList.remove('border-white', 'bg-white/10');
    return;
  }
  productCharacterPreview.classList.remove('hidden');
  if (dropProductCharacter) dropProductCharacter.classList.add('border-white', 'bg-white/10');

  const img = document.createElement('img');
  img.src = productState.characterImage.dataUrl;
  img.className = 'w-full h-full object-cover';
  const rmBtn = document.createElement('button');
  rmBtn.className = 'absolute top-2 right-2 p-1.5 bg-black/60 rounded-full text-white hover:bg-red-500 transition-colors z-30';
  rmBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
  rmBtn.onclick = (e) => {
    e.stopPropagation();
    productState.characterImage = null;
    resetProductResults();
    renderProductAnalysisSummary();
    renderProductCharacterPreview();
  };
  productCharacterPreview.appendChild(img);
  productCharacterPreview.appendChild(rmBtn);
};

const renderVideoStartPreview = () => {
  if (!videoStartPreview) return;
  videoStartPreview.innerHTML = '';
  if (!videoState.startFrame) {
    videoStartPreview.classList.add('hidden');
    if (dropVideoStart) dropVideoStart.classList.remove('border-purple-400', 'bg-purple-500/20');
    resetVideoPromptPlan({ clearPrompt: true });
    setVideoGenerating(false);
    setVideoPromptGenerating(false);
    return;
  }
  videoStartPreview.classList.remove('hidden');
  if (dropVideoStart) dropVideoStart.classList.add('border-purple-400', 'bg-purple-500/20');
  setVideoGenerating(false); // updates button state
  setVideoPromptGenerating(false);

  const img = document.createElement('img');
  img.src = videoState.startFrame.dataUrl;
  img.className = 'w-full h-full object-cover';
  const rmBtn = document.createElement('button');
  rmBtn.className = 'absolute top-2 right-2 p-1.5 bg-black/60 rounded-full text-white hover:bg-red-500 transition-colors z-30';
  rmBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
  rmBtn.onclick = (e) => {
    e.stopPropagation();
    videoState.startFrame = null;
    resetVideoPromptPlan({ clearPrompt: true });
    renderVideoStartPreview();
  };
  videoStartPreview.appendChild(img);
  videoStartPreview.appendChild(rmBtn);
};

const renderVideoEndPreview = () => {
  if (!videoEndPreview) return;
  videoEndPreview.innerHTML = '';
  if (!videoState.endFrame) {
    videoEndPreview.classList.add('hidden');
    if (dropVideoEnd) dropVideoEnd.classList.remove('border-purple-400', 'bg-purple-500/20');
    resetVideoPromptPlan();
    return;
  }
  videoEndPreview.classList.remove('hidden');
  if (dropVideoEnd) dropVideoEnd.classList.add('border-purple-400', 'bg-purple-500/20');

  const img = document.createElement('img');
  img.src = videoState.endFrame.dataUrl;
  img.className = 'w-full h-full object-cover';
  const rmBtn = document.createElement('button');
  rmBtn.className = 'absolute top-2 right-2 p-1.5 bg-black/60 rounded-full text-white hover:bg-red-500 transition-colors z-30';
  rmBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
  rmBtn.onclick = (e) => {
    e.stopPropagation();
    videoState.endFrame = null;
    resetVideoPromptPlan();
    renderVideoEndPreview();
  };
  videoEndPreview.appendChild(img);
  videoEndPreview.appendChild(rmBtn);
};

const normalizeElementId = (value, index) => {
  const base = value || `element_${index + 1}`;
  return String(base).toLowerCase().replace(/[^a-z0-9_-]+/g, '_');
};

const renderElementPreview = (elementId) => {
  if (!recreateElements) return;
  const container = recreateElements.querySelector(`[data-element-preview="${elementId}"]`);
  if (!container) return;
  const override = getElementOverride(elementId);
  renderSinglePreview(container, override.image, () => {
    override.image = null;
    renderElementPreview(elementId);
  }, () => {
    if (!override.image) return;
    openEditor(override.image.dataUrl, (updatedUrl) => {
      updateImageMeta(override.image, updatedUrl).then(() => renderElementPreview(elementId));
    });
  });
};

const renderRecreateEditor = () => {
  if (!recreateElements || !recreateSummary || !recreateElementsCount) return;
  recreateElements.innerHTML = '';
  const analysis = recreateState.analysis;
  const summaryParts = [];
  if (analysis?.summary) summaryParts.push(analysis.summary);
  if (analysis?.style) summaryParts.push(`Style: ${analysis.style}`);
  if (analysis?.background) summaryParts.push(`Background: ${analysis.background}`);
  if (analysis?.composition) summaryParts.push(`Composition: ${analysis.composition}`);
  recreateSummary.textContent =
    summaryParts.length ? summaryParts.join(' • ') : 'Analyze a reference image to list every element.';

  const items = recreateState.elements;
  recreateElementsCount.textContent = `${items.length}`;

  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'text-xs font-mono text-gray-500';
    empty.textContent = 'No elements detected yet.';
    recreateElements.appendChild(empty);
    if (recreateRunBtn) {
      recreateRunBtn.disabled = true;
      recreateRunBtn.classList.add('opacity-60');
    }
    return;
  }

  if (recreateRunBtn) {
    recreateRunBtn.disabled = false;
    recreateRunBtn.classList.remove('opacity-60');
  }

  items.forEach((item) => {
    const override = getElementOverride(item.id);

    const card = document.createElement('div');
    card.className = 'recreate-card border border-white/10 rounded-2xl p-4 bg-white/5 flex flex-col gap-3';

    const header = document.createElement('div');
    header.className = 'flex items-start justify-between gap-3';

    const titleWrap = document.createElement('div');
    const title = document.createElement('h4');
    title.className = 'text-sm font-semibold';
    title.textContent = item.label;

    const type = document.createElement('p');
    type.className = 'text-[10px] font-mono text-gray-500 uppercase tracking-widest mt-1';
    type.textContent = item.type || 'Element';

    titleWrap.append(title, type);

    const description = document.createElement('p');
    description.className = 'text-xs text-gray-400';
    description.textContent = item.description || 'No description provided.';

    header.append(titleWrap);
    card.append(header, description);

    if (item.details && item.details.length) {
      const detailWrap = document.createElement('div');
      detailWrap.className = 'flex flex-wrap gap-2';
      item.details.forEach((detail) => {
        const pill = document.createElement('span');
        pill.className = 'px-2 py-0.5 rounded-full border border-white/10 text-[9px] font-mono text-gray-500';
        pill.textContent = detail;
        detailWrap.appendChild(pill);
      });
      card.appendChild(detailWrap);
    }

    const textArea = document.createElement('textarea');
    textArea.rows = 2;
    textArea.placeholder = 'Describe the change or replacement...';
    textArea.value = override.text;
    textArea.className =
      'w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-[11px] focus:outline-none text-gray-300 resize-none';
    textArea.addEventListener('input', (event) => {
      override.text = event.target.value;
    });
    card.appendChild(textArea);

    const dropZoneLabel = document.createElement('div');
    dropZoneLabel.className = 'flex justify-between items-center w-full mb-1 border-t border-white/5 pt-2 mt-1';

    const labelText = document.createElement('span');
    labelText.className = 'text-[10px] font-mono text-gray-500 uppercase';
    labelText.textContent = 'Replacement Image';

    const recentBtn = document.createElement('button');
    recentBtn.type = 'button';
    recentBtn.className = 'text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1 normal-case tracking-normal text-[10px]';
    recentBtn.dataset.target = `recreate-element-${item.id}`;
    recentBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-clock w-3 h-3"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Recent';
    recentBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (typeof openHistoryModal === 'function') {
        openHistoryModal(`recreate-element-${item.id}`);
      }
    });

    dropZoneLabel.append(labelText, recentBtn);

    const dropZone = document.createElement('div');
    dropZone.className =
      'drop-zone relative border border-dashed border-white/10 rounded-xl bg-white/5 hover:bg-white/10 transition-colors p-3 min-h-[110px] flex flex-col items-center justify-center gap-1.5 text-center group cursor-pointer';

    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.className = 'absolute inset-0 opacity-0 cursor-pointer z-10';

    const label = document.createElement('span');
    label.className = 'text-[10px] text-gray-500 group-hover:text-gray-300';
    label.textContent = 'Drop replacement image';

    const preview = document.createElement('div');
    preview.className = 'preview-single absolute inset-0 rounded-xl overflow-hidden hidden z-20';
    preview.dataset.elementPreview = item.id;

    dropZone.append(input, label, preview);
    card.append(dropZoneLabel, dropZone);

    recreateElements.appendChild(card);

    setupDragDrop(dropZone, input, 'recreate-element', { elementId: item.id });
    renderElementPreview(item.id);
  });
};


// --- File Handling Logic ---

const handleFiles = async (files, type, meta = {}) => {
  if (!files.length) return;

  if (type === 'reference') {
    const remainingSlots = 4 - state.referenceImages.length;
    if (remainingSlots <= 0) {
      setError('Max 4 reference images allowed.');
      return;
    }

    const selected = Array.from(files).slice(0, remainingSlots);
    const items = await Promise.all(selected.map(readFileWithMeta));
    items.forEach((item) => state.referenceImages.push(item));
    renderReferencePreview();
  }
  else if (type === 'character') {
    const remainingSlots = 6 - state.characterImages.length;
    if (remainingSlots <= 0) {
      setError('Max 6 character images allowed.');
      return;
    }

    const selected = Array.from(files).slice(0, remainingSlots);
    const items = await Promise.all(selected.map(readFileWithMeta));
    items.forEach((item) => state.characterImages.push({ ...item, spec: '' }));
    renderCharacterPreview();
  }
  else if (type === 'scene') {
    const file = files[0];
    state.sceneImage = await readFileWithMeta(file);
    refreshScenePreview();
  }
  else if (type === 'style') {
    const file = files[0];
    state.styleImage = await readFileWithMeta(file);
    refreshStylePreview();
  }
  else if (type === 'recreate-reference') {
    const file = files[0];
    recreateState.referenceImage = await readFileWithMeta(file);
    recreateState.analysis = null;
    recreateState.elements = [];
    recreateState.overrides = {};
    refreshRecreateReferencePreview();
    renderRecreateEditor();
    setRecreateStatus('Reference loaded. Ready to analyze.');
  }
  else if (type === 'recreate-element') {
    const elementId = meta.elementId;
    if (!elementId) return;
    const file = files[0];
    const override = getElementOverride(elementId);
    override.image = await readFileWithMeta(file);
    renderElementPreview(elementId);
  }
  else if (type === 'product-reference') {
    const remainingSlots = MAX_PRODUCT_REFERENCES - productState.referenceImages.length;
    if (remainingSlots <= 0) {
      setError(`Max ${MAX_PRODUCT_REFERENCES} product reference images allowed.`);
      return;
    }

    const selected = Array.from(files).slice(0, remainingSlots);
    const items = await Promise.all(selected.map(readFileWithMeta));
    items.forEach((item) => productState.referenceImages.push(item));
    if (selected.length < files.length) {
      setError(`Only the first ${remainingSlots} product image(s) were added. Max ${MAX_PRODUCT_REFERENCES} allowed.`);
    }
    resetProductResults();
    renderProductAnalysisSummary();
    renderProductReferencePreview();
  }
  else if (type === 'product-character') {
    const file = files[0];
    productState.characterImage = await readFileWithMeta(file);
    resetProductResults();
    renderProductAnalysisSummary();
    renderProductCharacterPreview();
  }
  else if (type === 'video-start') {
    const file = files[0];
    videoState.startFrame = await readFileWithMeta(file);
    resetVideoPromptPlan({ clearPrompt: true });
    renderVideoStartPreview();
  }
  else if (type === 'video-end') {
    const file = files[0];
    videoState.endFrame = await readFileWithMeta(file);
    resetVideoPromptPlan();
    renderVideoEndPreview();
  }
};

// --- Drag and Drop Setup ---

const setupDragDrop = (zone, input, type, meta = {}) => {
  if (!zone || !input) return;
  // Basic Input Change
  input.addEventListener('change', (e) => {
    handleFiles(e.target.files, type, meta);
    input.value = ''; // Reset to allow same file selection
  });

  // Drag Events
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    zone.addEventListener(eventName, preventDefaults, false);
  });

  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  ['dragenter', 'dragover'].forEach(eventName => {
    zone.addEventListener(eventName, () => zone.classList.add('drag-over'), false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    zone.addEventListener(eventName, () => zone.classList.remove('drag-over'), false);
  });

  zone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    handleFiles(files, type, meta);
  }, false);

  // Make wrapper click trigger input provided it wasn't a remove button click
  // and didn't already hit the file input itself (which is layered on top)
  zone.addEventListener('click', (e) => {
    if (e.target === input) return; // Input already handles its own click
    if (e.target.tagName !== 'BUTTON' && !e.target.closest('button')) {
      input.click();
    }
  });
};

setupDragDrop(dropReference, referenceInput, 'reference');
setupDragDrop(dropCharacter, characterInput, 'character');
setupDragDrop(dropScene, sceneInput, 'scene');
setupDragDrop(dropStyle, styleInput, 'style');
setupDragDrop(dropRecreateReference, recreateReferenceInput, 'recreate-reference');
setupDragDrop(dropProductReference, productReferenceInput, 'product-reference');
setupDragDrop(dropProductCharacter, productCharacterInput, 'product-character');
setupDragDrop(dropVideoStart, videoStartInput, 'video-start');
setupDragDrop(dropVideoEnd, videoEndInput, 'video-end');

// --- Editor Events ---
if (editorCanvas) {
  editorCanvas.addEventListener('pointerdown', (event) => {
    if (!editorState.isOpen) return;
    if (editorState.tool === 'draw') {
      beginDrawing(event);
    }
  });

  editorCanvas.addEventListener('pointermove', (event) => {
    if (!editorState.isOpen) return;
    continueDrawing(event);
  });

  editorCanvas.addEventListener('click', (event) => {
    if (!editorState.isOpen) return;
    if (editorState.tool === 'text') {
      showTextInput(event);
    }
  });

  editorCanvas.addEventListener('pointerup', stopDrawing);
  editorCanvas.addEventListener('pointerleave', stopDrawing);
}

if (editorTextInput) {
  editorTextInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      commitTextInput();
    }
    if (event.key === 'Escape') {
      editorTextInput.classList.add('hidden');
    }
  });

  editorTextInput.addEventListener('blur', commitTextInput);
}

if (editorSave) {
  editorSave.addEventListener('click', () => {
    if (!editorCanvas) return;
    try {
      commitTextInput();
      const merged = editorCanvas.toDataURL('image/png');
      if (editorState.onSave) editorState.onSave(merged);
      closeEditor();
    } catch (error) {
      console.error(error);
      setError('Unable to export edited image.');
    }
  });
}

if (editorCancel) {
  editorCancel.addEventListener('click', closeEditor);
}

if (editorReset) {
  editorReset.addEventListener('click', async () => {
    if (!editorState.baseDataUrl) return;
    setEditorLoading(true);
    try {
      await drawImageToCanvas(editorState.baseDataUrl);
    } catch (error) {
      console.error(error);
      setError('Unable to reset image.');
    } finally {
      setEditorLoading(false);
    }
  });
}

editorColorButtons.forEach((button) => {
  if (button.dataset.color) {
    button.style.backgroundColor = button.dataset.color;
  }
  button.addEventListener('click', () => {
    if (button.dataset.color) setEditorColor(button.dataset.color);
  });
});

if (editorBrushSize) {
  editorBrushSize.addEventListener('input', () => {
    setBrushSize(editorBrushSize.value);
  });
}

if (toolDraw) {
  toolDraw.addEventListener('click', () => setEditorTool('draw'));
}

if (toolText) {
  toolText.addEventListener('click', () => setEditorTool('text'));
}

if (editorModal) {
  editorModal.addEventListener('click', (event) => {
    if (event.target.matches('[data-editor-close]')) {
      closeEditor();
    }
  });
}

window.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && editorState.isOpen) {
    closeEditor();
  }
});


// --- Generation Logic ---

const buildPrompt = () => {
  const base = promptInput.value.trim();
  const tags = Array.from(styleTags.querySelectorAll('input:checked')).map(
    (input) => input.value
  );

  const selectedPalette = paletteSelect.options[paletteSelect.selectedIndex]?.text;
  const selectedMood = moodSelect.options[moodSelect.selectedIndex]?.text;

  const selectors = [];
  if (paletteSelect.value) selectors.push(selectedPalette);
  if (moodSelect.value) selectors.push(selectedMood);

  const extras = [...tags, ...selectors];
  let prompt = base;

  if (extras.length) {
    prompt = `${prompt}. ${extras.join(', ')}`;
  }

  const aspectHint = getAspectHint();
  if (aspectHint) {
    prompt = `${prompt}\n${aspectHint}`;
  }

  return prompt;
};

const buildContentParts = () => {
  const prompt = buildPrompt();
  const notes = [];

  if (state.referenceImages.length) {
    notes.push('Edit the reference images with the prompt.');
  }
  if (state.characterImages.length) {
    notes.push('Use the character images for subject identity, pose, and wardrobe.');
  }
  if (state.sceneImage) {
    notes.push('Use the scene image for location and environment.');
  }
  if (state.styleImage) {
    notes.push('Use the style image for art direction and material cues.');
  }

  const fullPrompt = notes.length ? `${prompt}\n${notes.join(' ')}` : prompt;
  const parts = [{ type: 'text', text: fullPrompt }];

  if (state.referenceImages.length) {
    parts.push({ type: 'text', text: 'Reference images:' });
    state.referenceImages.forEach((item) => {
      parts.push({ type: 'image_url', image_url: { url: item.dataUrl } });
    });
  }

  if (state.characterImages.length) {
    parts.push({ type: 'text', text: 'Character reference images:' });
    state.characterImages.forEach((item, index) => {
      const spec = item.spec ? `: ${item.spec}` : '';
      parts.push({ type: 'text', text: `Character reference ${index + 1}${spec}` });
      parts.push({ type: 'image_url', image_url: { url: item.dataUrl } });
    });
  }

  if (state.sceneImage) {
    parts.push({ type: 'text', text: 'Scene reference:' });
    parts.push({ type: 'image_url', image_url: { url: state.sceneImage.dataUrl } });
  }

  if (state.styleImage) {
    parts.push({ type: 'text', text: 'Style reference:' });
    parts.push({ type: 'image_url', image_url: { url: state.styleImage.dataUrl } });
  }

  return parts;
};

const buildRecreatePrompt = () => {
  const analysis = recreateState.analysis || {};
  const globalNotes = recreateNotes ? recreateNotes.value.trim() : '';
  const replacements = [];

  recreateState.elements.forEach((element) => {
    const override = recreateState.overrides[element.id];
    const text = override?.text?.trim();
    const hasImage = Boolean(override?.image?.dataUrl);
    if (!text && !hasImage) return;

    const detailParts = [];
    if (text) detailParts.push(text);
    if (hasImage) detailParts.push('Use the provided replacement image for this element only.');
    if (element.description) detailParts.push(`Original: ${element.description}`);
    if (element.details && element.details.length) {
      detailParts.push(`Details: ${element.details.join(', ')}`);
    }
    replacements.push(`${element.label}: ${detailParts.join(' ')}`);
  });

  let prompt =
    'Recreate the provided reference image as faithfully as possible. Preserve composition, camera angle, lighting, color, and background elements. Only change the elements listed below.';

  if (analysis.summary) prompt += `\nReference summary: ${analysis.summary}`;
  if (analysis.style) prompt += `\nStyle: ${analysis.style}`;
  if (analysis.background) prompt += `\nBackground: ${analysis.background}`;
  if (analysis.composition) prompt += `\nComposition: ${analysis.composition}`;

  if (replacements.length) {
    prompt += `\nElement replacements:\n- ${replacements.join('\n- ')}`;
  } else {
    prompt += '\nNo element overrides were provided. Recreate the reference exactly.';
  }

  if (globalNotes) {
    prompt += `\nGlobal edits: ${globalNotes}`;
  }

  const aspectHint = getAspectHint();
  if (aspectHint) {
    prompt += `\n${aspectHint}`;
  }

  return prompt;
};

const buildRecreateContentParts = () => {
  const parts = [{ type: 'text', text: buildRecreatePrompt() }];

  if (recreateState.referenceImage) {
    parts.push({ type: 'text', text: 'Reference image:' });
    parts.push({ type: 'image_url', image_url: { url: recreateState.referenceImage.dataUrl } });
  }

  recreateState.elements.forEach((element) => {
    const override = recreateState.overrides[element.id];
    if (!override?.image?.dataUrl) return;
    const detail = override.text ? `: ${override.text}` : '';
    parts.push({ type: 'text', text: `Replacement reference for ${element.label}${detail}` });
    parts.push({ type: 'image_url', image_url: { url: override.image.dataUrl } });
  });

  return parts;
};

const extractImages = (data) => {
  const urls = [];

  const pushUrl = (value) => {
    if (value && !urls.includes(value)) {
      urls.push(value);
    }
  };

  const collect = (item) => {
    if (!item) return;
    if (item?.image_url?.url) {
      pushUrl(item.image_url.url);
    } else if (typeof item?.image_url === 'string') {
      pushUrl(item.image_url);
    } else if (item?.url) {
      pushUrl(item.url);
    } else if (item?.b64_json) {
      pushUrl(`data:image/png;base64,${item.b64_json}`);
    } else if (item?.type === 'image' && item?.source?.data) {
      pushUrl(`data:image/png;base64,${item.source.data}`);
    } else if (item?.source?.url) {
      pushUrl(item.source.url);
    }
  };

  const message = data?.choices?.[0]?.message;
  const images = Array.isArray(message?.images) ? message.images : [];
  images.forEach(collect);

  const content = message?.content;
  if (Array.isArray(content)) {
    content.forEach(collect);
  }

  if (Array.isArray(data?.data)) {
    data.data.forEach(collect);
  }

  if (Array.isArray(data?.output)) {
    data.output.forEach((item) => {
      if (Array.isArray(item?.content)) {
        item.content.forEach(collect);
      }
    });
  }

  if (!urls.length && typeof content === 'string') {
    const matches = content.match(/(https?:\/\/\S+|data:image\/\w+;base64,\S+)/g);
    if (matches) {
      matches.forEach(pushUrl);
    }
  }

  return urls;
};

const buildHeaders = () => {
  const headers = { 'Content-Type': 'application/json' };
  if (parentAuthToken) {
    headers['Authorization'] = `Bearer ${parentAuthToken}`;
    return headers;
  }
  if (isEmbeddedStudio) {
    throw new Error('Blockscom session is still syncing. Wait a second and try again.');
  }
  throw new Error('Your Blockscom session is missing. Sign in again and reload the studio page.');
};

const updateCreditBalance = (credits) => {
  if (!creditBalanceEl) return;

  const numericCredits = Number(credits);
  if (!Number.isFinite(numericCredits)) {
    creditBalanceEl.textContent = isEmbeddedStudio ? 'Syncing...' : 'Loading...';
    return;
  }

  creditBalanceEl.textContent = `${numericCredits.toLocaleString()} Credits`;
};

const applyStudioResponseMeta = (data) => {
  const numericCredits = Number(data?.creditsRemaining);
  if (!Number.isFinite(numericCredits)) return;

  studioProfile = { ...(studioProfile || {}), credits: numericCredits };
  updateCreditBalance(numericCredits);
  postToParent({ type: 'STUDIO_CREDITS_UPDATED', credits: numericCredits });
};

const applyStudioProfile = (profile) => {
  if (!profile) return;
  studioProfile = { ...(studioProfile || {}), ...profile };
  updateCreditBalance(studioProfile.credits);
};

const loadStandaloneStudioContext = async () => {
  if (isEmbeddedStudio) return;
  if (!window.supabase?.createClient || !window.SUPABASE_URL || !window.SUPABASE_ANON_KEY) {
    if (creditBalanceEl) creditBalanceEl.textContent = 'Auth Error';
    throw new Error('Supabase client config is missing on the studio page.');
  }

  if (!standaloneSupabase) {
    standaloneSupabase = window.supabase.createClient(window.SUPABASE_URL, window.SUPABASE_ANON_KEY);
  }

  const syncSession = async (session) => {
    if (!session?.access_token) {
      window.location.href = '/login';
      return;
    }

    parentAuthToken = session.access_token;
    const meResponse = await fetch('/api/me', {
      headers: { 'Authorization': `Bearer ${parentAuthToken}` }
    });

    if (!meResponse.ok) {
      window.location.href = '/login';
      return;
    }

    const profile = await meResponse.json();
    applyStudioProfile(profile);
    await loadStudioMediaGallery({ force: true });
  };

  const { data } = await standaloneSupabase.auth.getSession();
  await syncSession(data?.session || null);

  standaloneSupabase.auth.onAuthStateChange((_event, session) => {
    syncSession(session).catch((error) => {
      console.error('Failed to sync standalone studio session.', error);
    });
  });
};

const extractTextContent = (content) => {
  if (!content) return '';
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === 'string') return part;
        if (part?.text) return part.text;
        return '';
      })
      .join('\n')
      .trim();
  }
  return '';
};

const extractJsonBlock = (text) => {
  let cleaned = text.trim();
  if (cleaned.startsWith('```')) {
    cleaned = cleaned.replace(/^```[a-z]*\n?/i, '').replace(/```$/i, '').trim();
  }
  const firstBrace = cleaned.indexOf('{');
  const firstBracket = cleaned.indexOf('[');
  if (firstBrace === -1 && firstBracket === -1) {
    return cleaned;
  }
  const startsWithArray = firstBracket !== -1 && (firstBrace === -1 || firstBracket < firstBrace);
  const start = startsWithArray ? firstBracket : firstBrace;
  const end = startsWithArray ? cleaned.lastIndexOf(']') : cleaned.lastIndexOf('}');
  if (start !== -1 && end !== -1 && end > start) {
    cleaned = cleaned.slice(start, end + 1);
  }
  return cleaned.trim();
};

const repairJsonText = (text) => {
  let cleaned = text.trim();
  cleaned = cleaned.replace(/[\u201c\u201d]/g, '"').replace(/[\u2018\u2019]/g, "'");
  cleaned = cleaned.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  cleaned = cleaned.replace(/,\s*([}\]])/g, '$1');
  cleaned = cleaned.replace(/}\s*{/g, '},{');
  cleaned = cleaned.replace(/]\s*{/g, '],{');
  cleaned = cleaned.replace(/"\s+"/g, '","');
  cleaned = cleaned.replace(/"\s*{/g, '",{');
  cleaned = cleaned.replace(/}\s*"/g, '},"');
  return cleaned.trim();
};

const parseAnalysisJson = (text) => {
  if (!text) throw new Error('Analyzer returned an empty response.');
  const cleaned = extractJsonBlock(text);
  const parseValue = (value) => {
    if (value.startsWith('[')) {
      return JSON.parse(value);
    }
    return JSON.parse(value);
  };
  try {
    return parseValue(cleaned);
  } catch (error) {
    const repaired = repairJsonText(cleaned);
    if (repaired !== cleaned) {
      try {
        return parseValue(repaired);
      } catch (repairError) {
        console.warn('Analysis JSON repair failed.', repairError);
      }
    }
    console.warn('Analysis JSON parse failed.', error, cleaned);
    const detail = error?.message ? ` (${error.message})` : '';
    throw new Error(`Analyzer returned invalid JSON${detail}. Try analyzing again or switch the analysis model.`);
  }
};

const normalizeAnalysis = (analysis) => {
  const rawElements = Array.isArray(analysis?.elements)
    ? analysis.elements
    : Array.isArray(analysis?.items)
      ? analysis.items
      : Array.isArray(analysis?.objects)
        ? analysis.objects
        : [];

  const usedIds = new Set();
  const elements = rawElements.map((item, index) => {
    const isTextItem = typeof item === 'string';
    const label = isTextItem ? item : item?.label || item?.name || item?.title || `Element ${index + 1}`;
    let id = normalizeElementId(item?.id || item?.key || label, index);
    if (usedIds.has(id)) {
      id = `${id}_${index + 1}`;
    }
    usedIds.add(id);
    const type = isTextItem ? 'object' : item?.type || item?.category || item?.kind || 'object';
    const description = isTextItem ? '' : item?.description || item?.summary || item?.notes || '';
    let details = isTextItem ? [] : item?.details || item?.attributes || item?.key_details || item?.features || [];
    if (!Array.isArray(details)) details = details ? [String(details)] : [];
    details = details.map((detail) => String(detail)).filter(Boolean);

    return {
      id,
      label,
      type,
      description,
      details
    };
  });

  return {
    summary: analysis?.summary || analysis?.scene || analysis?.overview || '',
    style: analysis?.style || analysis?.aesthetic || '',
    background: analysis?.background || analysis?.environment || '',
    composition: analysis?.composition || analysis?.layout || '',
    elements
  };
};

const requestAnalysis = async (imageUrl) => {
  const instructions =
    'Analyze the image and return ONLY valid JSON (no markdown, no commentary). ' +
    'Use double quotes for all keys/strings, escape newlines as \\n, and do not include trailing commas. ' +
    'Include every visible element, even minor details. ' +
    'Split people into individual entries. Capture clothing, accessories, text, signage, props, lighting, and background objects. ' +
    'Return this schema: {"summary": "...","style":"...","background":"...","composition":"...","elements":[{"id":"person_1","label":"Male 1","type":"person","description":"...","details":["...","..."]}]}';

  const payload = {
    model: ANALYSIS_MODEL,
    max_tokens: 2000,
    temperature: 0,
    messages: [
      {
        role: 'system',
        content: 'You are a meticulous visual analyst that outputs strict JSON only.'
      },
      {
        role: 'user',
        content: [
          { type: 'text', text: instructions },
          { type: 'image_url', image_url: { url: imageUrl } }
        ]
      }
    ]
  };

  const response = await fetch(ANALYZE_ENDPOINT, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    const message = data?.error?.message || data?.message || 'OpenRouter request failed.';
    throw new Error(message);
  }

  applyStudioResponseMeta(data);
  const text = extractTextContent(data?.choices?.[0]?.message?.content);
  const parsed = parseAnalysisJson(text);

  return normalizeAnalysis(parsed);
};

const requestLegacyProductAnalysis = async (imageUrl, characterImageUrl) => {
  let characterInstructions = '';
  if (characterImageUrl) {
    characterInstructions = 'Because a second image (a character/person) was provided, the advertisement MUST represent a User-Generated Content (UGC) style promotion featuring that specific person. If the product is wearable, the prompt MUST describe the character wearing the product. If it is NOT wearable, the prompt MUST describe the character holding and promoting the product. Every concept MUST have a strong visual or narrative HOOK designed for maximum virality. ';
  }

  const instructions =
    'You are a VIRAL MARKETING genius and world-class advertising creative director. ' +
    'Analyze this product image carefully. Identify the product type, its key visual features, materials, colors, and branding elements. ' +
    'Then generate EXACTLY 10 highly detailed, premium advertising product photoshoot concepts. ' +
    'The first 5 concepts MUST be tailored for AI video generation transitions (Video Ad Hooks). ' +
    'The next 5 concepts MUST be for high-quality static photoshoot ads (Photoshoot Ads). ' +
    characterInstructions +
    'Crucially, you must optimize these for MAXIMUM SOCIAL MEDIA VIRALITY and engagement. ' +
    'Return ONLY a raw JSON array of 10 objects strictly following this schema:\n' +
    '[{\n' +
    '  "campaign_details": {\n' +
    '    "brand": "[Brand name if visible, else inferred]",\n' +
    '    "product": "[Product name]",\n' +
    '    "asset_type": "Video Ad Hook | Photoshoot Ad",\n' +
    '    "style_concept": "[Short catchy name for the concept]"\n' +
    '  },\n' +
    '  "generation_payload": {\n' +
    '    "start_frame_prompt": "[Start frame description (Video) or Main prompt (Photoshoot) establishing the scene, product, lighting, background, camera angle, and mood]",\n' +
    '    "end_frame_prompt": "[Post-transition state description (Video) or leave empty string]",\n' +
    '    "negative_prompt": "[List of negative features separated by commas — MUST always include: text, words, letters, numbers, labels, watermarks, overlays, captions, typography, logos, writing, signatures]",\n' +
    '    "video_motion_cues": {\n' +
    '      "camera_movement": "[Cinematic camera instructions (Video) or leave empty string]",\n' +
    '      "scene_dynamics": "[Effects and motion happening in the scene (Video) or leave empty string]"\n' +
    '    },\n' +
    '    "technical_specs": {\n' +
    '      "camera_angle": "...",\n' +
    '      "lighting": "...",\n' +
    '      "color_palette": ["...", "..."]\n' +
    '    }\n' +
    '  }\n' +
    '}]';

  const payload = {
    model: ANALYSIS_MODEL,
    max_tokens: 6000,
    temperature: 0.8,
    messages: [
      {
        role: 'system',
        content: 'You are a social media viral marketing AI genius. You understand what drives engagement, likes, and shares. You output only strict JSON arrays of detailed, production-ready photoshoot concept objects.'
      },
      {
        role: 'user',
        content: [
          { type: 'text', text: instructions },
          { type: 'image_url', image_url: { url: imageUrl } }
        ]
      }
    ]
  };

  if (characterImageUrl) {
    payload.messages[1].content.push({ type: 'image_url', image_url: { url: characterImageUrl } });
  }

  const response = await fetch(ANALYZE_ENDPOINT, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    if (response.status === 413) {
      throw new Error('The analysis payload is still too large for the current server. Deploy the latest server update and try again.');
    }
    const message = data?.error?.message || data?.message || `HTTP ${response.status} Error fetching product analysis`;
    throw new Error(message);
  }

  applyStudioResponseMeta(data);
  const text = extractTextContent(data?.choices?.[0]?.message?.content);
  const parsed = parseAnalysisJson(text);

  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error('Analyzer failed to return a list of concepts.');
  }

  // Ensure returning structured JSON concept objects
  return parsed.slice(0, 10).map(item => {
    // In case AI failed to nest them perfectly, wrap gracefully
    if (!item.generation_payload) {
      return {
        campaign_details: {
          brand: 'Unknown',
          product: 'Product',
          asset_type: 'Video Ad Hook',
          style_concept: item.concept_name || 'Product Concept'
        },
        generation_payload: {
          start_frame_prompt: item.start_frame_prompt || '',
          end_frame_prompt: item.end_frame_prompt || '',
          video_motion_cues: {
            camera_movement: item.video_prompt || '',
            scene_dynamics: ''
          }
        }
      };
    }
    return item;
  });
};

const normalizeStringArray = (value) => {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  if (value === null || value === undefined || value === false) {
    return [];
  }
  if (typeof value === 'string') {
    return value
      .split(/\r?\n|[|,]+/g)
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [String(value).trim()].filter(Boolean);
};

const getUniqueStrings = (values) => {
  const seen = new Set();
  return values
    .map((value) => String(value || '').trim())
    .filter((value) => {
      if (!value) return false;
      const key = value.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
};

const getProductDescriptorText = (product) =>
  [product?.product_label, product?.category, product?.wearability].filter(Boolean).join(' ').toLowerCase();

const inferProductPlacement = (product, hasCharacter, conceptTheme, index) => {
  const descriptor = getProductDescriptorText(product);
  const isClothing = /(shirt|t-shirt|tee|hoodie|sweater|jacket|dress|pants|shorts|uniform|jersey)/.test(descriptor);
  const isFootwear = /(slipper|slippers|shoe|shoes|sneaker|sandals|footwear)/.test(descriptor);
  const isBag = /(bag|backpack|pouch|wallet|tote|sling)/.test(descriptor);
  const isWatch = /(watch|bracelet|wrist)/.test(descriptor);

  if (hasCharacter) {
    if (isClothing) return 'worn naturally by the character with the front design, fit, sleeves, and hem clearly visible';
    if (isFootwear) return 'worn on the character with the pair angle showing the top view, side profile, and sole shape accurately';
    if (isBag) return 'carried naturally by the character with the full silhouette, handles, strap, and hardware visible';
    if (isWatch) return 'worn on the wrist closest to camera with the dial, strap, lugs, and finish kept accurate';
    return index === 0
      ? `held or featured closest to the camera as the main ${conceptTheme} hero product`
      : `held or styled near the character so its full silhouette remains readable`;
  }

  if (isClothing) return 'styled on a clean invisible form or folded hero layout with the full front panel visible';
  if (isFootwear) return 'arranged as a matched pair with the straps, sole shape, and side profile readable';
  if (isBag) return 'standing upright in a hero pose with the full bag structure, handles, strap, and hardware visible';
  if (isWatch) return 'placed in a premium macro hero setup with the dial, case shape, and strap fully visible';
  return index === 0
    ? `placed as the central ${conceptTheme} hero product with maximum focus`
    : 'positioned clearly in-frame with full shape and material visibility';
};

const buildProductUsagePlan = (products, hasCharacter, conceptTheme) =>
  products.map((product, index) => ({
    reference_index: product.reference_index,
    product_label: product.product_label,
    placement: inferProductPlacement(product, hasCharacter, conceptTheme, index),
    visibility_goal: index === 0
      ? 'hero focus with brand, silhouette, materials, and small design details readable'
      : 'clear secondary visibility with the full product still easy to identify',
    accuracy_notes: getUniqueStrings([
      ...normalizeStringArray(product.accuracy_notes),
      ...normalizeStringArray(product.signature_details),
      ...normalizeStringArray(product.brand_text_visible).map((text) => `visible text/logo "${text}"`)
    ]).slice(0, 6)
  }));

const buildFallbackProductConcepts = ({ products, bundleRules, summary, hasCharacter }) => {
  const productNames = products.map((product) => product.product_label).filter(Boolean);
  const bundleLabel = productNames.join(', ') || 'product bundle';
  const brandList = getUniqueStrings(products.flatMap((product) => normalizeStringArray(product.brand_text_visible)));
  const brand = brandList[0] || 'Unknown';
  const accuracyRules = getUniqueStrings([
    ...normalizeStringArray(bundleRules?.accuracy_constraints),
    ...products.flatMap((product) => normalizeStringArray(product.accuracy_notes)),
    ...products.flatMap((product) => normalizeStringArray(product.signature_details)),
    ...brandList.map((text) => `keep visible brand text/logo exactly as "${text}"`)
  ]).slice(0, 10);

  const blueprints = [
    {
      asset_type: 'Video Ad Hook',
      style_concept: 'Street Stop Hook',
      theme: 'streetwear',
      scene: 'a scroll-stopping urban lifestyle scene with quick energy and premium social-media framing',
      styling: 'confident lifestyle composition with clean negative space and crisp product separation',
      camera: 'fast push-in from medium framing to a tight product-led hero frame',
      motion: 'a quick body turn and hand movement that resolves into a clean hero hold',
      angle: 'three-quarter medium shot',
      lighting: 'bright natural daylight with soft bounce fill',
      palette: ['graphite', 'stone', 'warm skin tones']
    },
    {
      asset_type: 'Video Ad Hook',
      style_concept: 'Unbox To Wear Reveal',
      theme: 'unboxing reveal',
      scene: 'a premium unboxing moment that transitions into a fully styled reveal of the entire bundle',
      styling: 'clean tabletop opening into polished lifestyle composition',
      camera: 'top-down intro shifting into a front-facing hero angle',
      motion: 'the products are revealed one by one before locking into a final bundle display',
      angle: 'top-down to eye-level transition',
      lighting: 'soft studio daylight with glossy highlights',
      palette: ['ivory', 'silver', 'soft black']
    },
    {
      asset_type: 'Video Ad Hook',
      style_concept: 'Mirror Fit Check',
      theme: 'mirror fit-check',
      scene: 'a premium mirror-check moment designed for short-form fashion content',
      styling: 'modern editorial fashion framing with authentic UGC energy',
      camera: 'handheld-style start resolving into a clean centered hero frame',
      motion: 'subtle subject movement and reflective transition into sharp product visibility',
      angle: 'mirror medium shot',
      lighting: 'window light with soft indoor practical highlights',
      palette: ['charcoal', 'cream', 'cool gray']
    },
    {
      asset_type: 'Video Ad Hook',
      style_concept: 'Detail Snap Sequence',
      theme: 'detail showcase',
      scene: 'a sequence of premium close-up product moments that opens into a complete bundle composition',
      styling: 'high-detail macro advertising with cinematic product transitions',
      camera: 'macro detail shots ending in a clean wide hero composition',
      motion: 'snap cuts between materials and hardware resolving into a locked final scene',
      angle: 'macro to wide transition',
      lighting: 'controlled studio highlights with clean specular detail',
      palette: ['obsidian', 'steel', 'warm beige']
    },
    {
      asset_type: 'Video Ad Hook',
      style_concept: 'Carry And Turn Hook',
      theme: 'movement-driven lifestyle',
      scene: 'a movement-led social ad where the full bundle is introduced through confident motion',
      styling: 'premium candid lifestyle scene with precise product visibility',
      camera: 'tracking shot that settles into a balanced hero composition',
      motion: 'walking motion, slight turn, then crisp stop with all products readable',
      angle: 'tracking medium-wide shot',
      lighting: 'golden-hour edge light with clean fill',
      palette: ['sand', 'black', 'warm gold']
    },
    {
      asset_type: 'Photoshoot Ad',
      style_concept: 'Premium Catalog Hero',
      theme: 'catalog hero',
      scene: 'a polished ecommerce hero shot built for maximum product clarity and conversion',
      styling: 'premium catalog styling with zero clutter and perfect product readability',
      camera: '',
      motion: '',
      angle: 'front-facing hero composition',
      lighting: 'clean studio softbox lighting with controlled shadow detail',
      palette: ['white', 'soft gray', 'black']
    },
    {
      asset_type: 'Photoshoot Ad',
      style_concept: 'Lifestyle Bundle Cover',
      theme: 'lifestyle cover',
      scene: 'a premium campaign cover image that makes the full product bundle feel aspirational and wearable',
      styling: 'editorial lifestyle composition with strong hierarchy and premium depth',
      camera: '',
      motion: '',
      angle: 'three-quarter campaign cover framing',
      lighting: 'directional daylight with subtle rim light',
      palette: ['earth tones', 'soft white', 'graphite']
    },
    {
      asset_type: 'Photoshoot Ad',
      style_concept: 'Clean Flat Lay Story',
      theme: 'flat-lay bundle',
      scene: 'a clean flat-lay advertisement showcasing the full product bundle with perfect organization',
      styling: 'orderly premium layout with all hero details facing camera',
      camera: '',
      motion: '',
      angle: 'top-down flat lay',
      lighting: 'soft overhead studio lighting with crisp shadow control',
      palette: ['stone', 'white', 'soft black']
    },
    {
      asset_type: 'Photoshoot Ad',
      style_concept: 'Luxury Detail Poster',
      theme: 'luxury detail',
      scene: 'a luxury detail-driven ad that still keeps every product visible in one premium frame',
      styling: 'macro-rich premium composition with tactile materials and strong contrast',
      camera: '',
      motion: '',
      angle: 'close hero angle with layered depth',
      lighting: 'dramatic controlled highlights with deep soft shadows',
      palette: ['black', 'bronze', 'cream']
    },
    {
      asset_type: 'Photoshoot Ad',
      style_concept: 'Social Carousel Opener',
      theme: 'social cover',
      scene: 'a thumbnail-optimized social cover image with strong product hierarchy and instant readability',
      styling: 'bold social-first composition that still feels premium and accurate',
      camera: '',
      motion: '',
      angle: 'center-weighted cover composition',
      lighting: 'bright even key light with crisp separation',
      palette: ['white', 'blue-gray', 'charcoal']
    }
  ];

  return blueprints.map((blueprint) => {
    const productUsagePlan = buildProductUsagePlan(products, hasCharacter, blueprint.theme);
    const usageText = productUsagePlan
      .map((entry) => {
        const noteText = entry.accuracy_notes.length ? ` Accuracy requirements: ${entry.accuracy_notes.join(', ')}.` : '';
        return `${entry.product_label}: ${entry.placement}. Visibility goal: ${entry.visibility_goal}.${noteText}`;
      })
      .join(' ');

    const characterLine = hasCharacter
      ? 'Use the uploaded character reference exactly. Keep the same face, body type, and overall appearance, and style the products naturally on or around that person.'
      : 'No person is required unless it helps the concept; if no person is used, create a premium product-only composition.';

    const sharedBrief =
      `Feature this complete bundle in one frame: ${bundleLabel}. Every uploaded product must be present at the same time. ` +
      `${characterLine} ` +
      `Scene direction: ${blueprint.scene}. Styling direction: ${blueprint.styling}. ` +
      `Product layout instructions: ${usageText} ` +
      `Reference analysis summary: ${summary || 'Match the uploaded references exactly.'} ` +
      `Critical accuracy rules: ${accuracyRules.join('; ')}. ` +
      `Camera angle: ${blueprint.angle}. Lighting: ${blueprint.lighting}.`;

    const isVideo = blueprint.asset_type !== 'Photoshoot Ad';

    return {
      campaign_details: {
        brand,
        product: bundleLabel,
        asset_type: blueprint.asset_type,
        style_concept: blueprint.style_concept
      },
      generation_payload: {
        start_frame_prompt: `${sharedBrief} Start frame mood: establish the full bundle immediately with premium clarity, realistic proportions, accurate text/logo placement, and a strong social hook.`,
        end_frame_prompt: isVideo
          ? `${sharedBrief} End frame mood: resolve into the cleanest hero composition where every product is fully readable and perfectly faithful to the references.`
          : '',
        negative_prompt: 'watermarks, captions, interface elements, extra products, missing products, duplicated items, wrong text, incorrect branding, altered logos, wrong colors, distorted proportions, unreadable product details',
        video_motion_cues: {
          camera_movement: blueprint.camera,
          scene_dynamics: blueprint.motion
        },
        technical_specs: {
          camera_angle: blueprint.angle,
          lighting: blueprint.lighting,
          color_palette: blueprint.palette
        },
        product_usage_plan: productUsagePlan,
        reference_accuracy_notes: accuracyRules
      }
    };
  });
};

const normalizeProductAnalysisResult = (parsed, referenceCount = 0, options = {}) => {
  const hasCharacter = Boolean(options?.hasCharacter);
  let summary = '';
  let products = [];
  let bundleRules = {};
  let concepts = [];

  if (Array.isArray(parsed)) {
    concepts = parsed;
  } else if (parsed && typeof parsed === 'object') {
    summary = String(parsed.analysis_summary || parsed.summary || parsed.bundle_summary || '').trim();
    products = Array.isArray(parsed.products)
      ? parsed.products
      : Array.isArray(parsed.product_analysis)
        ? parsed.product_analysis
        : [];
    bundleRules = parsed.bundle_rules && typeof parsed.bundle_rules === 'object' ? parsed.bundle_rules : {};
    concepts = Array.isArray(parsed.concepts)
      ? parsed.concepts
      : Array.isArray(parsed.prompt_concepts)
        ? parsed.prompt_concepts
        : Array.isArray(parsed.ideas)
          ? parsed.ideas
          : [];
  }

  const fallbackProducts = products.length
    ? products
    : Array.from({ length: referenceCount }, (_, index) => ({
      reference_index: index + 1,
      product_label: `Product ${index + 1}`
    }));

  const normalizedProducts = fallbackProducts.slice(0, referenceCount || undefined).map((item, index) => ({
    reference_index: Number(item?.reference_index) || index + 1,
    product_label: String(item?.product_label || item?.name || item?.product || item?.category || `Product ${index + 1}`).trim(),
    category: String(item?.category || item?.product_type || item?.type || '').trim(),
    brand_text_visible: normalizeStringArray(item?.brand_text_visible || item?.visible_text || item?.text_visible),
    colors: normalizeStringArray(item?.colors || item?.color_palette),
    materials: normalizeStringArray(item?.materials || item?.material),
    signature_details: normalizeStringArray(item?.signature_details || item?.must_match_details || item?.details || item?.features),
    wearability: String(item?.wearability || item?.wearable || item?.placement_type || '').trim(),
    accuracy_notes: normalizeStringArray(item?.accuracy_notes || item?.must_match || item?.key_details)
  }));

  const defaultAccuracyRules = [
    'Every uploaded product reference must appear in every concept.',
    'Keep visible product text, logos, colors, materials, hardware, stitching, print placement, proportions, and finishes faithful to the references.',
    'Do not invent hidden details that are not visible in the reference images.'
  ];

  const normalizedBundleRules = {
    must_include_all_products: bundleRules?.must_include_all_products !== false,
    styling_rules: normalizeStringArray(bundleRules?.styling_rules || bundleRules?.visual_rules || bundleRules?.notes),
    accuracy_constraints: normalizeStringArray(bundleRules?.accuracy_constraints || bundleRules?.rules || bundleRules?.must_match)
  };

  if (!normalizedBundleRules.accuracy_constraints.length) {
    normalizedBundleRules.accuracy_constraints = defaultAccuracyRules;
  }

  let normalizedConcepts = concepts.slice(0, 10).map((item, index) => {
    const generationPayload = item?.generation_payload && typeof item.generation_payload === 'object'
      ? item.generation_payload
      : {};
    const motionCues = generationPayload.video_motion_cues && typeof generationPayload.video_motion_cues === 'object'
      ? generationPayload.video_motion_cues
      : {};
    const technicalSpecs = generationPayload.technical_specs && typeof generationPayload.technical_specs === 'object'
      ? generationPayload.technical_specs
      : {};

    const rawUsagePlan = Array.isArray(generationPayload.product_usage_plan)
      ? generationPayload.product_usage_plan
      : Array.isArray(item?.product_usage_plan)
        ? item.product_usage_plan
        : [];

    const productUsagePlan = (rawUsagePlan.length ? rawUsagePlan : normalizedProducts.map((product) => ({
      reference_index: product.reference_index,
      product_label: product.product_label,
      placement: '',
      visibility_goal: '',
      accuracy_notes: product.accuracy_notes.length ? product.accuracy_notes : product.signature_details
    }))).map((entry, usageIndex) => {
      const matchedProduct = normalizedProducts.find((product) => product.reference_index === (Number(entry?.reference_index) || usageIndex + 1))
        || normalizedProducts[usageIndex]
        || null;

      return {
        reference_index: Number(entry?.reference_index) || matchedProduct?.reference_index || usageIndex + 1,
        product_label: String(entry?.product_label || entry?.label || matchedProduct?.product_label || `Product ${usageIndex + 1}`).trim(),
        placement: String(entry?.placement || entry?.styling || entry?.display || '').trim(),
        visibility_goal: String(entry?.visibility_goal || entry?.role || entry?.focus || '').trim(),
        accuracy_notes: normalizeStringArray(entry?.accuracy_notes || entry?.must_match || entry?.details || matchedProduct?.accuracy_notes || matchedProduct?.signature_details)
      };
    });

    return {
      campaign_details: {
        brand: item?.campaign_details?.brand || item?.brand || 'Unknown',
        product: item?.campaign_details?.product || item?.product || (normalizedProducts.map((product) => product.product_label).join(', ') || 'Product bundle'),
        asset_type: item?.campaign_details?.asset_type || item?.asset_type || (index < 5 ? 'Video Ad Hook' : 'Photoshoot Ad'),
        style_concept: item?.campaign_details?.style_concept || item?.style_concept || item?.concept_name || `Product Bundle Concept ${index + 1}`
      },
      generation_payload: {
        start_frame_prompt: generationPayload.start_frame_prompt || item?.start_frame_prompt || item?.prompt || '',
        end_frame_prompt: generationPayload.end_frame_prompt || item?.end_frame_prompt || '',
        negative_prompt: generationPayload.negative_prompt || item?.negative_prompt || '',
        video_motion_cues: {
          camera_movement: motionCues.camera_movement || item?.video_prompt || '',
          scene_dynamics: motionCues.scene_dynamics || item?.scene_dynamics || ''
        },
        technical_specs: {
          camera_angle: technicalSpecs.camera_angle || '',
          lighting: technicalSpecs.lighting || '',
          color_palette: normalizeStringArray(technicalSpecs.color_palette || technicalSpecs.palette)
        },
        product_usage_plan: productUsagePlan,
        reference_accuracy_notes: normalizeStringArray(
          generationPayload.reference_accuracy_notes
          || generationPayload.accuracy_notes
          || item?.reference_accuracy_notes
          || item?.accuracy_notes
        )
      }
    };
  });

  if (!summary && normalizedProducts.length) {
    summary = `Analyzed ${normalizedProducts.length} product reference${normalizedProducts.length === 1 ? '' : 's'} and prepared bundle-safe prompts that keep every uploaded product visible and consistent.`;
  }

  if (!normalizedConcepts.length) {
    normalizedConcepts = buildFallbackProductConcepts({
      products: normalizedProducts,
      bundleRules: normalizedBundleRules,
      summary,
      hasCharacter
    });
  } else if (normalizedConcepts.length < 10) {
    const fallbackConcepts = buildFallbackProductConcepts({
      products: normalizedProducts,
      bundleRules: normalizedBundleRules,
      summary,
      hasCharacter
    });
    normalizedConcepts = [...normalizedConcepts, ...fallbackConcepts.slice(normalizedConcepts.length, 10)];
  }

  return {
    summary,
    products: normalizedProducts,
    bundleRules: normalizedBundleRules,
    concepts: normalizedConcepts
  };
};

const requestProductAnalysis = async (referenceImages, characterImageUrl) => {
  if (!Array.isArray(referenceImages) || referenceImages.length === 0) {
    throw new Error('Upload at least one product reference image.');
  }

  const optimizedReferenceImages = await Promise.all(
    referenceImages.map((item) => getOptimizedModelDataUrl(item, 'analysis'))
  );
  const optimizedCharacterImageUrl = productState.characterImage
    ? await getOptimizedModelDataUrl(productState.characterImage, 'analysis')
    : characterImageUrl;

  let characterInstructions = '';
  if (optimizedCharacterImageUrl) {
    characterInstructions =
      'A separate character reference is provided. Every concept must use that exact person in a UGC-style promotional setup. ' +
      'Wearable products should be worn by the character when physically possible. Non-wearable products should be held, carried, or displayed naturally by that same character. ';
  }

  const instructions =
    'You are a premium product-reference analyst. ' +
    `You will receive ${referenceImages.length} product reference image(s) that belong to the same campaign bundle. ` +
    'Analyze each uploaded product image separately. ' +
    'For each product, identify the exact category, silhouette, colors, materials, visible hardware, stitching, print placement, shape, texture, closures, and any legible brand text or logos. ' +
    'If text or branding is visible and readable, transcribe it exactly. If it is only partially visible, state that clearly instead of guessing. ' +
    'Do not drop products, merge products together, or invent alternate versions. ' +
    'Keep all visible product details faithful to the references, especially text, logos, watch faces, straps, buckles, bag handles, zipper pulls, slipper soles, shirt graphics, seams, trims, and finish details. ' +
    characterInstructions +
    'Return ONLY valid minified raw JSON in a single object. No markdown. No code fences. No commentary. ' +
    'Use double quotes for every key and string, and do not include trailing commas. ' +
    'Return ONLY this schema:\n' +
    '{\n' +
    '  "analysis_summary": "...",\n' +
    '  "products": [\n' +
    '    {\n' +
    '      "reference_index": 1,\n' +
    '      "product_label": "...",\n' +
    '      "category": "...",\n' +
    '      "brand_text_visible": ["..."],\n' +
    '      "colors": ["..."],\n' +
    '      "materials": ["..."],\n' +
    '      "signature_details": ["..."],\n' +
    '      "wearability": "wearable | accessory | handheld | display",\n' +
    '      "accuracy_notes": ["..."]\n' +
    '    }\n' +
    '  ],\n' +
    '  "bundle_rules": {\n' +
    '    "must_include_all_products": true,\n' +
    '    "styling_rules": ["..."],\n' +
    '    "accuracy_constraints": ["..."]\n' +
    '  }\n' +
    '}';

  const userContent = [{ type: 'text', text: instructions }];

  optimizedReferenceImages.forEach((dataUrl, index) => {
    userContent.push({
      type: 'text',
      text: `Product reference ${index + 1} of ${referenceImages.length}. Analyze this exact product and preserve its visible details precisely.`
    });
    userContent.push({ type: 'image_url', image_url: { url: dataUrl } });
  });

  if (optimizedCharacterImageUrl) {
    userContent.push({
      type: 'text',
      text: 'Character reference. Use this exact person for UGC-style concepts and keep their appearance consistent.'
    });
    userContent.push({ type: 'image_url', image_url: { url: optimizedCharacterImageUrl } });
  }

  const payload = {
    model: ANALYSIS_MODEL,
    max_tokens: 2200,
    temperature: 0.1,
    messages: [
      {
        role: 'system',
        content: 'You are a strict product-reference analyst. Inspect every image carefully, preserve product fidelity, and output strict raw JSON only.'
      },
      {
        role: 'user',
        content: userContent
      }
    ]
  };

  const response = await fetch(ANALYZE_ENDPOINT, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    const message = data?.error?.message || data?.message || `HTTP ${response.status} Error fetching product analysis`;
    throw new Error(message);
  }

  applyStudioResponseMeta(data);
  const text = extractTextContent(data?.choices?.[0]?.message?.content);
  window.__lastProductAnalysisRaw = text;
  const parsed = parseAnalysisJson(text);

  return normalizeProductAnalysisResult(parsed, referenceImages.length, {
    hasCharacter: Boolean(optimizedCharacterImageUrl)
  });
};

const VIDEO_EFFECT_LIBRARY = {
  speed_time: ['Slow Motion', 'Super Slow Motion', 'Fast Motion', 'Time-Lapse', 'Hyperlapse', 'Reverse Motion', 'Freeze Frame', 'Speed Ramping'],
  motion_camera: ['Zoom In', 'Zoom Out', 'Digital Pan', 'Shake Effect', 'Whip Pan Transition', 'Dolly Zoom', 'Parallax Effect', 'Motion Tracking'],
  distortion: ['Glitch Effect', 'VHS Distortion', 'Fisheye Lens', 'Warp', 'Kaleidoscope', 'Ripple Effect', 'Pixelate'],
  lighting_color: ['Color Grading', 'Color Filter', 'HDR Effect', 'Glow', 'Neon Effect', 'Light Leaks', 'Lens Flare', 'Shadow Highlight Boost'],
  stylization: ['Cartoon Effect', 'Anime Effect', 'Sketch', 'Oil Painting', 'Comic Book Style', 'Posterize', 'Halftone'],
  cinematic: ['Depth of Field', 'Bokeh', '3D Camera Movement', 'Particle Effects', 'Explosion Effects', 'Fire Effects', 'Lightning Effects'],
  transitions: ['Fade In', 'Fade Out', 'Cross Dissolve', 'Slide', 'Wipe', 'Spin Transition', 'Zoom Transition', 'Flash Transition'],
  overlays: ['Rain Overlay', 'Snow Overlay', 'Fog', 'Film Grain', 'Dust Particles', 'Light Rays']
};

const buildFallbackVideoMotionPrompt = (plan, hasEndFrame) => {
  const hook = plan?.viral_hook || 'Create a premium viral product hook.';
  const cameraMovement = plan?.direction?.camera_movement || 'Use smooth cinematic camera movement.';
  const subjectMotion = plan?.direction?.subject_motion || 'Add natural subject and product motion with strong readability.';
  const pacing = plan?.direction?.pacing || 'Keep pacing dynamic and scroll-stopping.';
  const transition = plan?.direction?.transition_type || (hasEndFrame ? 'Use a clean start-to-end transformation.' : 'Build one satisfying motion arc from the start frame.');
  const effects = normalizeStringArray(plan?.direction?.effects).join(', ');
  const focus = normalizeStringArray(plan?.direction?.product_focus).join(', ');
  const mood = plan?.direction?.lighting_mood || 'premium commercial lighting';

  return [
    hook,
    hasEndFrame
      ? 'Animate from the provided start frame toward the provided end frame while preserving the exact subject, product, styling, and composition logic.'
      : 'Animate the provided start frame into a premium motion ad without breaking subject consistency.',
    cameraMovement,
    subjectMotion,
    pacing,
    `Transition approach: ${transition}.`,
    `Lighting and finish: ${mood}.`,
    effects ? `Use these effects only when they strengthen the story: ${effects}.` : '',
    focus ? `Keep these details readable and protected: ${focus}.` : '',
    'Make it feel premium, viral, natural, and polished with no random artifacts or broken anatomy.'
  ].filter(Boolean).join(' ');
};

const normalizeVideoPromptPlan = (parsed, hasEndFrame) => {
  const direction = parsed?.direction && typeof parsed.direction === 'object' ? parsed.direction : {};

  const normalized = {
    analysis_summary: String(parsed?.analysis_summary || parsed?.summary || '').trim(),
    viral_hook: String(parsed?.viral_hook || parsed?.hook || '').trim(),
    motion_prompt: String(parsed?.motion_prompt || parsed?.prompt || '').trim(),
    direction: {
      transition_type: String(direction.transition_type || parsed?.transition_type || '').trim(),
      camera_movement: String(direction.camera_movement || parsed?.camera_movement || '').trim(),
      subject_motion: String(direction.subject_motion || parsed?.subject_motion || '').trim(),
      pacing: String(direction.pacing || parsed?.pacing || '').trim(),
      lighting_mood: String(direction.lighting_mood || parsed?.lighting_mood || '').trim(),
      effects: getUniqueStrings(normalizeStringArray(direction.effects || parsed?.effects)).slice(0, 6),
      product_focus: getUniqueStrings(normalizeStringArray(direction.product_focus || parsed?.product_focus)).slice(0, 6)
    }
  };

  if (!normalized.analysis_summary) {
    normalized.analysis_summary = hasEndFrame
      ? 'AI analyzed both start and end frames to build a transition-aware product motion direction.'
      : 'AI analyzed the start frame to build a self-contained viral motion direction.';
  }

  if (!normalized.viral_hook) {
    normalized.viral_hook = hasEndFrame
      ? 'Reveal the destination frame through a premium high-retention transition.'
      : 'Use the start frame as a scroll-stopping viral product hook.';
  }

  if (!normalized.motion_prompt) {
    normalized.motion_prompt = buildFallbackVideoMotionPrompt(normalized, hasEndFrame);
  }

  return normalized;
};

const renderVideoPromptPlan = (plan) => {
  if (!videoAiPlan || !videoAiSummary || !videoAiEffects) return;
  if (!plan) {
    videoAiPlan.classList.add('hidden');
    videoAiSummary.textContent = '';
    videoAiEffects.textContent = '';
    if (videoCopyAiJsonBtn) {
      videoCopyAiJsonBtn.classList.add('hidden');
      videoCopyAiJsonBtn.classList.remove('inline-flex');
    }
    return;
  }

  const effects = normalizeStringArray(plan?.direction?.effects);
  const focus = normalizeStringArray(plan?.direction?.product_focus);
  videoAiSummary.textContent = [plan.viral_hook, plan.analysis_summary].filter(Boolean).join(' ');
  videoAiEffects.textContent = [
    plan?.direction?.camera_movement ? `Camera: ${plan.direction.camera_movement}` : '',
    plan?.direction?.transition_type ? `Transition: ${plan.direction.transition_type}` : '',
    effects.length ? `Effects: ${effects.join(', ')}` : '',
    focus.length ? `Protect: ${focus.join(', ')}` : ''
  ].filter(Boolean).join(' | ');
  videoAiPlan.classList.remove('hidden');
  if (videoCopyAiJsonBtn) {
    videoCopyAiJsonBtn.classList.remove('hidden');
    videoCopyAiJsonBtn.classList.add('inline-flex');
  }
};

const requestVideoPromptPlan = async () => {
  if (!videoState.startFrame) {
    throw new Error('Start Frame is required before AI can build a motion prompt.');
  }

  const optimizedStartFrame = await getOptimizedModelDataUrl(videoState.startFrame, 'analysis');
  const optimizedEndFrame = videoState.endFrame
    ? await getOptimizedModelDataUrl(videoState.endFrame, 'analysis')
    : null;

  const effectLibraryText = Object.entries(VIDEO_EFFECT_LIBRARY)
    .map(([group, values]) => `${group}: ${values.join(', ')}`)
    .join('\n');

  const instructions =
    'You are a viral marketing genius, luxury ad director, and high-retention short-form video strategist. ' +
    'Analyze the provided video frame references and write one elite motion plan for Kling-style image-to-video generation. ' +
    'Protect the product, person, text, logo, and visual identity visible in the frame references. ' +
    'Use camera logic, motion logic, and effects only when they make the ad more premium, unique, and scroll-stopping. ' +
    'If both start and end frames are provided, build a believable transition path from start to end. ' +
    'If only a start frame is provided, invent a high-performing viral motion arc that keeps the same subject and product consistent. ' +
    'Choose only the most useful effect methods from this library and avoid random gimmicks:\n' +
    `${effectLibraryText}\n` +
    'Return ONLY valid minified raw JSON. No markdown. No commentary. Use double quotes for all keys and strings. ' +
    'Schema:\n' +
    '{' +
    '"analysis_summary":"...",' +
    '"viral_hook":"...",' +
    '"motion_prompt":"...",' +
    '"direction":{' +
    '"transition_type":"...",' +
    '"camera_movement":"...",' +
    '"subject_motion":"...",' +
    '"pacing":"...",' +
    '"lighting_mood":"...",' +
    '"effects":["..."],' +
    '"product_focus":["..."]' +
    '}' +
    '}';

  const userContent = [
    {
      type: 'text',
      text: instructions
    },
    {
      type: 'text',
      text: optimizedEndFrame
        ? 'Start frame reference. Understand the subject, product, styling, hook potential, and what should be preserved at the beginning of the shot.'
        : 'Start frame reference. Understand the subject, product, styling, hook potential, and build a strong viral motion concept from this frame.'
    },
    { type: 'image_url', image_url: { url: optimizedStartFrame } }
  ];

  if (optimizedEndFrame) {
    userContent.push({
      type: 'text',
      text: 'End frame reference. Transition toward this destination faithfully while preserving product identity, consistency, and premium commercial quality.'
    });
    userContent.push({ type: 'image_url', image_url: { url: optimizedEndFrame } });
  }

  const payload = {
    model: ANALYSIS_MODEL,
    max_tokens: 1400,
    temperature: 0.25,
    messages: [
      {
        role: 'system',
        content: 'You are an elite commercial motion prompt strategist. You analyze frame references and output strict JSON only.'
      },
      {
        role: 'user',
        content: userContent
      }
    ]
  };

  const response = await fetch(ANALYZE_ENDPOINT, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    if (response.status === 413) {
      throw new Error('The AI prompt request is too large for the current server. Deploy the latest server update and try again.');
    }
    const message = data?.error?.message || data?.message || `HTTP ${response.status} Error fetching video prompt analysis`;
    throw new Error(message);
  }

  applyStudioResponseMeta(data);
  const text = extractTextContent(data?.choices?.[0]?.message?.content);
  window.__lastVideoPromptRaw = text;
  const parsed = parseAnalysisJson(text);

  return normalizeVideoPromptPlan(parsed, Boolean(optimizedEndFrame));
};

const requestImages = async (contentParts, seedValue, model) => {
  const payload = {
    model: model,
    messages: [{ role: 'user', content: contentParts }]
  };

  if (Number.isFinite(seedValue)) {
    payload.seed = seedValue;
  }

  const response = await fetch(API_ENDPOINT, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    if (response.status === 413) {
      throw new Error('The generation payload is too large for the current server. Deploy the latest server update and try again.');
    }
    const message = data?.error?.message || data?.message || 'OpenRouter request failed.';
    throw new Error(message);
  }

  applyStudioResponseMeta(data);

  return extractImages(data);
};

// Returns an array of animated progress DOM elements to be filled later
const createSkeletons = (count) => {
  const skeletons = [];
  for (let i = 0; i < count; i += 1) {
    const card = document.createElement('div');
    card.className = 'card skeleton bg-white/5 border border-white/10 rounded-2xl p-4 flex flex-col gap-3 min-h-[300px] mt-4 opacity-0 slide-in';

    // Generates the same premium ring as the video loader
    card.innerHTML = `
      <div class="video-progress-ring">
        <svg viewBox="0 0 100 100">
          <circle class="ring-bg" cx="50" cy="50" r="44"></circle>
          <circle class="ring-fill" cx="50" cy="50" r="44" stroke-dasharray="276.46" stroke-dashoffset="276.46"></circle>
          <defs>
            <linearGradient id="productGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#3b82f6" />
              <stop offset="100%" stop-color="#10b981" />
            </linearGradient>
          </defs>
        </svg>
        <div class="video-progress-text">
          <span class="video-progress-percent">0%</span>
          <span class="video-progress-label">Generating</span>
        </div>
      </div>
      <div class="video-loading-status" style="color: #10b981;">IMAGING...</div>
      <div class="video-loading-eta">Estimated time: ~10-15 secs</div>
      <div class="video-loading-dots">
        <span></span><span></span><span></span>
      </div>
    `;

    // Apply specific gradient to this fill
    const fill = card.querySelector('.ring-fill');
    if (fill) fill.style.stroke = 'url(#productGradient)';

    // Simulate progress animation over ~15 seconds
    let progress = 0;
    const progressInterval = setInterval(() => {
      progress += Math.random() * 5 + 2; // Add 2-7% per tick
      if (progress > 99) progress = 99; // Cap at 99% until final image arrives

      const offset = 276.46 - ((progress / 100) * 276.46);
      if (fill) fill.style.strokeDashoffset = offset;

      const pctText = card.querySelector('.video-progress-percent');
      if (pctText) pctText.textContent = Math.round(progress) + '%';

    }, 600);

    // Store interval to clear it if needed, though replaceSkeletonWithImage wipes the DOM
    card.dataset.intervalId = progressInterval;

    setTimeout(() => card.classList.remove('opacity-0'), 50);

    galleryGrid.prepend(card); // Add new items to TOP
    skeletons.push(card);
  }
  return skeletons;
};

// Returns a premium loading card specifically for video generation
const createVideoLoadingCard = (durationStr) => {
  const card = document.createElement('div');
  card.className = 'video-loading-card mt-4 opacity-0 slide-in';

  const dur = parseInt(durationStr, 10) || 5;
  const estimatedSeconds = dur >= 15 ? '6-8 mins' : dur >= 10 ? '4-5 mins' : dur >= 5 ? '2-3 mins' : '1-2 mins';

  card.innerHTML = `
    <div class="video-progress-ring">
      <svg viewBox="0 0 100 100">
        <circle class="ring-bg" cx="50" cy="50" r="44"></circle>
        <circle class="ring-fill" cx="50" cy="50" r="44" stroke-dasharray="276.46" stroke-dashoffset="276.46"></circle>
        <defs>
          <linearGradient id="progressGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#a855f7" />
            <stop offset="100%" stop-color="#3b82f6" />
          </linearGradient>
        </defs>
      </svg>
      <div class="video-progress-text">
        <span class="video-progress-percent">0%</span>
        <span class="video-progress-label">Generating</span>
      </div>
    </div>
    <div class="video-loading-status">INITIALIZING...</div>
    <div class="video-loading-eta">Estimated time: ~${estimatedSeconds}</div>
    <div class="video-loading-dots">
      <span></span><span></span><span></span>
    </div>
  `;

  setTimeout(() => card.classList.remove('opacity-0'), 50);
  galleryGrid.prepend(card);
  return card;
};

const updateVideoProgress = (card, progressNum, statusText) => {
  if (!card) return;
  const fill = card.querySelector('.ring-fill');
  const pctText = card.querySelector('.video-progress-percent');
  const statusEl = card.querySelector('.video-loading-status');

  if (fill) {
    const offset = 276.46 - ((progressNum / 100) * 276.46);
    fill.style.strokeDashoffset = offset;
  }
  if (pctText) {
    pctText.textContent = Math.round(progressNum) + '%';
  }
  if (statusEl && statusText) {
    let displayStatus = statusText.toUpperCase();
    if (displayStatus === '99' || displayStatus === '100') displayStatus = 'FINALIZING...';
    statusEl.textContent = displayStatus;
  }
};

const replaceSkeletonWithImage = async (card, src, index, options = {}) => {
  let savedMedia = options?.savedMedia ? normalizeStudioMediaItem(options.savedMedia) : null;
  let finalSrc = src;

  if (!savedMedia && typeof src === 'string' && src.startsWith('data:image/')) {
    try {
      savedMedia = await saveGeneratedMediaToSupabase({
        mediaType: 'image',
        dataUrl: src,
        promptText: options?.promptText || lastPrompt || '',
        modelName: options?.modelName || '',
        aspectRatio: options?.aspectRatio || '',
        sourceFeature: options?.sourceFeature || activeFeature
      });
      finalSrc = savedMedia.src;
    } catch (e) {
      console.warn('Failed to save generated image to Supabase', e);
    }
  }

  // Clear progress animation interval if it exists
  if (card.dataset.intervalId) {
    clearInterval(parseInt(card.dataset.intervalId));
  }

  card.classList.remove('skeleton', 'animate-pulse');
  card.innerHTML = ''; // Clear skeleton structure

  // Build real card
  const img = document.createElement('img');
  img.src = finalSrc;
  img.alt = `Generated image`;
  img.loading = 'lazy';
  img.className = 'w-full rounded-xl fade-in';
  img.title = 'Click to edit';

  card.dataset.mediaId = savedMedia?.id || '';
  card.dataset.mediaType = 'image';

  const actions = document.createElement('div');
  actions.className = 'flex gap-2 mt-auto';

  const open = document.createElement('a');
  open.href = finalSrc;
  open.target = '_blank';
  open.className = 'text-xs text-gray-400 hover:text-white px-3 py-2 border border-white/10 rounded-full hover:bg-white/10 transition-colors cursor-pointer';
  open.textContent = 'View';

  const download = document.createElement('a');
  download.href = finalSrc;
  download.textContent = 'Download';
  download.setAttribute('download', `nano - banana - ${Date.now()} -${index}.png`);
  download.className = 'text-xs text-gray-400 hover:text-white px-3 py-2 border border-white/10 rounded-full hover:bg-white/10 transition-colors cursor-pointer';

  const copy = document.createElement('button');
  copy.type = 'button';
  copy.textContent = 'Copy Prompt';
  copy.className = 'text-xs text-gray-400 hover:text-white px-3 py-2 border border-white/10 rounded-full hover:bg-white/10 transition-colors ml-auto';
  copy.addEventListener('click', () => {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(savedMedia?.promptText || options?.promptText || lastPrompt || '').then(() => {
      copy.textContent = 'Copied!';
      setTimeout(() => copy.textContent = 'Copy Prompt', 2000);
    });
  });

  const delBtn = document.createElement('button');
  delBtn.type = 'button';
  delBtn.innerHTML = '<i data-lucide="trash-2" class="w-4 h-4"></i>';
  delBtn.className = 'text-gray-400 hover:text-red-400 px-3 py-2 border border-white/10 rounded-full hover:bg-white/10 transition-colors ml-1';
  delBtn.title = 'Delete';
  delBtn.addEventListener('click', async () => {
    if (savedMedia?.id) {
      await deleteGeneratedMediaFromSupabase(savedMedia.id).catch(console.warn);
    }
    card.remove();
    imageCount.textContent = galleryGrid.children.length;
    if (galleryGrid.children.length === 0) {
      galleryEmpty.style.display = 'flex';
    }
  });

  actions.append(open, download, copy, delBtn);
  card.append(img, actions);

  if (window.lucide) {
    window.lucide.createIcons({ root: actions });
  }

  img.addEventListener('click', () => {
    openEditor(img.src, (updatedUrl) => {
      img.src = updatedUrl;
      open.href = updatedUrl;
      download.href = updatedUrl;
    });
  });
};

const replaceSkeletonWithVideo = async (card, src, index, existingMedia = null) => {
  const savedMedia = existingMedia ? normalizeStudioMediaItem(existingMedia) : null;
  const finalSrc = savedMedia?.src || src;

  card.className = 'card bg-white/5 border border-white/10 rounded-2xl p-4 flex flex-col gap-3 min-h-[300px] mt-4 slide-in';
  card.innerHTML = ''; // Clear skeleton structure

  const video = document.createElement('video');
  video.src = finalSrc;
  video.autoplay = true;
  video.loop = true;
  video.muted = true;
  video.controls = true;
  video.className = 'w-full rounded-xl fade-in';
  video.style.outline = 'none';

  card.dataset.mediaId = savedMedia?.id || '';
  card.dataset.mediaType = 'video';

  const actions = document.createElement('div');
  actions.className = 'flex gap-2 mt-auto';

  const download = document.createElement('a');
  download.href = finalSrc;
  download.textContent = 'Download';
  download.setAttribute('download', `kling - video - ${Date.now()} -${index}.mp4`);
  download.className = 'text-xs text-purple-400 hover:text-white px-3 py-2 border border-purple-500/30 rounded-full hover:bg-purple-500/20 transition-colors cursor-pointer w-full text-center flex items-center justify-center gap-2';
  download.innerHTML = '<i data-lucide="download" class="w-3 h-3"></i> Download Video';

  const delBtn = document.createElement('button');
  delBtn.type = 'button';
  delBtn.innerHTML = '<i data-lucide="trash-2" class="w-4 h-4"></i>';
  delBtn.className = 'text-gray-400 hover:text-red-400 px-3 py-2 border border-white/10 rounded-full hover:bg-white/10 transition-colors ml-1 shrink-0';
  delBtn.title = 'Delete';
  delBtn.addEventListener('click', async () => {
    if (savedMedia?.id) {
      await deleteGeneratedMediaFromSupabase(savedMedia.id).catch(console.warn);
    }
    card.remove();
    imageCount.textContent = galleryGrid.children.length;
    if (galleryGrid.children.length === 0) {
      galleryEmpty.style.display = 'flex';
    }
  });

  actions.append(download, delBtn);
  card.append(video, actions);

  if (window.lucide) {
    window.lucide.createIcons({ root: actions });
  }
};

const analyzeRecreateReference = async () => {
  setError('');

  if (!recreateState.referenceImage) {
    setRecreateStatus('Add a reference image first.');
    return;
  }

  if (recreateState.isAnalyzing) return;

  setRecreateAnalyzing(true);
  setRecreateStatus('Analyzing image...');

  try {
    const analysis = await requestAnalysis(recreateState.referenceImage.dataUrl);
    recreateState.analysis = analysis;
    recreateState.elements = analysis.elements;
    recreateState.overrides = {};
    renderRecreateEditor();
    setRecreateStatus(`Detected ${analysis.elements.length} elements.`);
  } catch (error) {
    console.error(error);
    setRecreateStatus('Analysis failed.');
    setError(error.message || 'Analysis failed.');
  } finally {
    setRecreateAnalyzing(false);
  }
};

const handleRecreate = async () => {
  setError('');

  if (state.activeRequests >= state.queueLimit) {
    setRecreateStatus('Queue is full. Wait for a batch to finish.');
    return;
  }

  if (!recreateState.referenceImage) {
    setRecreateStatus('Add a reference image first.');
    return;
  }

  if (!recreateState.analysis) {
    setRecreateStatus('Analyze the reference image first.');
    return;
  }

  if (!recreateState.elements.length) {
    setRecreateStatus('No elements found to recreate.');
    return;
  }

  if (aspectSelect.value === 'reference') {
    const ref = getReferenceImageForAspect();
    if (!ref?.width || !ref?.height) {
      setRecreateStatus('Add a reference image to use Reference aspect ratio.');
      return;
    }
  }

  const desiredCount = Math.max(1, Math.min(Number(countRange.value) || 1, 4));
  const seedValue = seedInput && seedInput.value.trim() !== '' ? Number(seedInput.value) : null;
  const selectedModel = recreateModelSelect?.value || modelSelect.value || 'google/gemini-2.0-flash-exp';

  lastPrompt = buildRecreatePrompt();
  const contentParts = buildRecreateContentParts();

  setRecreateRunning(true);
  setRecreateStatus('Recreating image...');
  state.activeRequests++;
  updateQueueStatus();
  galleryEmpty.style.display = 'none';

  const skeletons = createSkeletons(desiredCount);

  try {
    const images = [];
    for (let i = 0; i < desiredCount; i += 1) {
      const batch = await requestImages(
        contentParts,
        Number.isFinite(seedValue) ? seedValue + i : undefined,
        selectedModel
      );
      images.push(...batch);
      if (images.length >= desiredCount) break;
    }

    const trimmed = images.slice(0, desiredCount);
    if (!trimmed.length) throw new Error('No images returned.');

    trimmed.forEach((src, idx) => {
      if (skeletons[idx]) {
        replaceSkeletonWithImage(skeletons[idx], src, idx, {
          promptText: buildRecreatePrompt(),
          modelName: selectedModel,
          aspectRatio: aspectSelect?.value || '',
          sourceFeature: 'recreate'
        });
      }
    });

    imageCount.textContent = galleryGrid.children.length;
    setRecreateStatus('Recreate completed.');
  } catch (error) {
    console.error(error);
    setError(error.message || 'Recreate failed.');
    setRecreateStatus('Recreate failed.');
    skeletons.forEach((skel) => skel.remove());

    if (galleryGrid.children.length === 0) {
      galleryEmpty.style.display = 'flex';
    }
  } finally {
    state.activeRequests--;
    updateQueueStatus();
    setLoading(state.activeRequests > 0);
    setRecreateRunning(false);
  }
};

// --- Product Modal Helpers ---
const openProductModal = () => {
  if (!productPromptsModal) return;
  productPromptsModal.classList.remove('hidden');
  productPromptsModal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
};

const closeProductModal = () => {
  if (!productPromptsModal) return;
  productPromptsModal.classList.add('hidden');
  productPromptsModal.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
};

const showProductModalState = (state) => {
  // state: 'loading' | 'results' | 'error'
  if (productModalLoading) productModalLoading.classList.toggle('hidden', state !== 'loading');
  if (productModalResults) productModalResults.classList.toggle('hidden', state !== 'results');
  if (productModalError) productModalError.classList.toggle('hidden', state !== 'error');
};

const buildAccordionPromptCard = (concept, idx) => {
  const card = document.createElement('div');
  card.className = 'product-prompt-card border border-white/5 rounded-xl overflow-hidden transition-all';

  // Header (always visible) — number + short preview
  const header = document.createElement('button');
  header.type = 'button';
  header.className = 'w-full flex items-center gap-3 p-3 sm:p-4 text-left hover:bg-white/5 transition-colors';

  const numBadge = document.createElement('span');
  numBadge.className = 'shrink-0 w-6 h-6 rounded-full bg-white/10 text-gray-400 text-[10px] font-mono flex items-center justify-center';
  numBadge.textContent = idx + 1;

  const isVideo = concept.campaign_details?.asset_type !== 'Photoshoot Ad';

  const preview = document.createElement('span');
  preview.className = 'flex-1 flex flex-col gap-0.5 truncate leading-snug font-bold font-mono tracking-wide';

  const typeLabel = document.createElement('span');
  typeLabel.className = `text - [9px] uppercase tracking - widest ${isVideo ? 'text-pink-400' : 'text-blue-400'} `;
  typeLabel.textContent = isVideo ? 'Video Ad Hook' : 'Photoshoot Ad';

  const titleText = document.createElement('span');
  titleText.className = 'text-[11px] text-gray-300 truncate';
  titleText.textContent = concept.campaign_details?.style_concept || concept.concept_name || 'Concept';

  preview.appendChild(typeLabel);
  preview.appendChild(titleText);

  const chevron = document.createElement('span');
  chevron.className = 'shrink-0 text-gray-600 transition-transform duration-200 prompt-chevron';
  chevron.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>';

  header.appendChild(numBadge);
  header.appendChild(preview);
  header.appendChild(chevron);

  // Body (collapsed) — full prompt text + select button
  const body = document.createElement('div');
  body.className = 'prompt-body hidden px-4 pb-4 pt-0';

  // Helper to create header with copy button
  const createTitleWithCopy = (title, iconName, colorClass, textToCopy) => {
    const wrapper = document.createElement('div');
    wrapper.className = `flex items - center justify - between mb - 1.5 pl - 9 ${colorClass} `;

    const h5 = document.createElement('h5');
    h5.className = 'text-[10px] font-mono uppercase tracking-widest flex items-center gap-1.5';
    if (iconName) {
      h5.innerHTML = `< i data - lucide="${iconName}" class="w-3 h-3" ></i > ${title} `;
    } else {
      h5.textContent = title;
    }

    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'p-1 hover:bg-white/10 rounded-md transition-colors text-gray-500 hover:text-white mr-4';
    copyBtn.innerHTML = '<i data-lucide="copy" class="w-3 h-3"></i>';
    copyBtn.title = `Copy ${title} `;

    copyBtn.onclick = (e) => {
      e.stopPropagation();
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(textToCopy).then(() => {
        copyBtn.innerHTML = '<i data-lucide="check" class="w-3 h-3 text-green-400"></i>';
        if (window.lucide) window.lucide.createIcons({ root: copyBtn });
        setTimeout(() => {
          copyBtn.innerHTML = '<i data-lucide="copy" class="w-3 h-3"></i>';
          if (window.lucide) window.lucide.createIcons({ root: copyBtn });
        }, 2000);
      });
    };

    wrapper.appendChild(h5);
    wrapper.appendChild(copyBtn);
    return wrapper;
  };

  const startHeaderTitle = isVideo ? 'Start Frame:' : 'Photoshoot Prompt:';
  const startHeader = createTitleWithCopy(startHeaderTitle, null, 'text-gray-500', concept.generation_payload?.start_frame_prompt || '');
  const startText = document.createElement('p');
  startText.className = 'text-[11px] text-gray-300 leading-relaxed mb-4 pl-9';
  startText.textContent = concept.generation_payload?.start_frame_prompt || '';

  body.appendChild(startHeader);
  body.appendChild(startText);

  let endHeader, videoHeader;

  if (isVideo) {
    endHeader = createTitleWithCopy('End Frame:', null, 'text-gray-500', concept.generation_payload?.end_frame_prompt || '');
    const endText = document.createElement('p');
    endText.className = 'text-[11px] text-gray-300 leading-relaxed mb-4 pl-9';
    endText.textContent = concept.generation_payload?.end_frame_prompt || '';

    const combinedVideoPrompt = `Camera: ${concept.generation_payload?.video_motion_cues?.camera_movement || ''} Scene: ${concept.generation_payload?.video_motion_cues?.scene_dynamics || ''} `;
    videoHeader = createTitleWithCopy('Video Motion Cues:', 'video', 'text-pink-500', combinedVideoPrompt);
    const videoText = document.createElement('p');
    videoText.className = 'text-[11px] text-gray-300 leading-relaxed mb-4 pl-9 select-all';
    videoText.textContent = combinedVideoPrompt;

    body.appendChild(endHeader);
    body.appendChild(endText);
    body.appendChild(videoHeader);
    body.appendChild(videoText);
  }

  const selectBtn = document.createElement('button');
  selectBtn.type = 'button';
  selectBtn.className = 'ml-9 px-4 py-1.5 border border-blue-500/30 text-blue-400 bg-blue-500/10 rounded-full text-[10px] font-mono uppercase tracking-widest hover:bg-blue-500/20 transition-colors';
  selectBtn.textContent = 'Select Concept';

  body.appendChild(selectBtn);

  // Create icons for the new headers
  if (window.lucide) {
    window.lucide.createIcons({ root: startHeader });
    if (isVideo) {
      window.lucide.createIcons({ root: endHeader });
      window.lucide.createIcons({ root: videoHeader });
    }
  }

  card.appendChild(header);
  card.appendChild(body);

  // Toggle expand/collapse
  header.onclick = () => {
    const isOpen = !body.classList.contains('hidden');
    // Close all others
    productModalList.querySelectorAll('.prompt-body').forEach(b => b.classList.add('hidden'));
    productModalList.querySelectorAll('.prompt-chevron').forEach(c => c.style.transform = '');
    productModalList.querySelectorAll('.product-prompt-card').forEach(c => c.classList.remove('bg-white/5'));

    if (!isOpen) {
      body.classList.remove('hidden');
      chevron.style.transform = 'rotate(180deg)';
      card.classList.add('bg-white/5');
    }
  };

  // Select this prompt
  selectBtn.onclick = (e) => {
    e.stopPropagation();
    // store the concept object
    productState.selectedPrompt = concept;

    // Highlight selected card
    productModalList.querySelectorAll('.product-prompt-card').forEach(c => {
      c.classList.remove('border-blue-500/40');
      c.classList.add('border-white/5');
    });
    card.classList.remove('border-white/5');
    card.classList.add('border-blue-500/40');

    // Update selected preview
    if (productModalSelected) productModalSelected.classList.remove('hidden');
    if (productModalSelectedText) productModalSelectedText.textContent = concept.campaign_details?.style_concept || concept.concept_name || 'Concept';

    const isVideoSelection = concept.campaign_details?.asset_type !== 'Photoshoot Ad';

    const modalVideoContainer = document.getElementById('product-modal-video-container');
    if (modalVideoContainer) {
      if (isVideoSelection) {
        modalVideoContainer.classList.remove('hidden');
        const modalVideoEl = document.getElementById('product-modal-selected-video');
        if (modalVideoEl) modalVideoEl.textContent = `Camera: ${concept.generation_payload?.video_motion_cues?.camera_movement || ''} Scene: ${concept.generation_payload?.video_motion_cues?.scene_dynamics || ''} `;
      } else {
        modalVideoContainer.classList.add('hidden');
      }
    }

    if (productModalGenerate) productModalGenerate.disabled = false;

    // Also update sidebar elements if they exist
    if (productSelectedPromptEl) productSelectedPromptEl.classList.remove('hidden');
    if (productSelectedTextEl) productSelectedTextEl.textContent = concept.campaign_details?.style_concept || concept.concept_name || 'Concept';

    const sidebarVideoContainer = document.getElementById('product-selected-video-container');
    if (sidebarVideoContainer) {
      if (isVideoSelection) {
        sidebarVideoContainer.classList.remove('hidden');
        const sidebarVideoEl = document.getElementById('product-selected-video');
        if (sidebarVideoEl) sidebarVideoEl.textContent = `Camera: ${concept.generation_payload?.video_motion_cues?.camera_movement || ''} Scene: ${concept.generation_payload?.video_motion_cues?.scene_dynamics || ''} `;
      } else {
        sidebarVideoContainer.classList.add('hidden');
      }
    }

    if (productGenerateBtn) productGenerateBtn.disabled = false;

    // Show copy button in sidebar
    const sidebarCopyJsonBtn = document.getElementById('product-copy-json-sidebar');
    if (sidebarCopyJsonBtn) {
      sidebarCopyJsonBtn.classList.remove('hidden');
      sidebarCopyJsonBtn.classList.add('flex');
    }
  };

  return card;
};

const analyzeProductReference = async () => {
  if (productState.referenceImages.length === 0) return;

  setError('');
  resetProductResults();
  renderProductAnalysisSummary();

  // Open modal with loading state
  openProductModal();
  showProductModalState('loading');
  setProductAnalyzing(true);

  try {
    const analysis = await requestProductAnalysis(
      productState.referenceImages,
      productState.characterImage ? productState.characterImage.dataUrl : null
    );
    productState.analysis = analysis;
    renderProductAnalysisSummary();

    // Build accordion cards in modal
    if (productModalList) {
      productModalList.innerHTML = '';
      analysis.concepts.forEach((concept, idx) => {
        productModalList.appendChild(buildAccordionPromptCard(concept, idx));
      });
    }

    // Show sidebar controls
    if (productSuggestionsContainer) {
      productSuggestionsContainer.classList.remove('hidden');
      productSuggestionsContainer.classList.add('flex');
    }

    showProductModalState('results');

  } catch (error) {
    console.error('Product Analysis Failed:', error);
    resetProductResults();
    renderProductAnalysisSummary();
    if (productModalErrorText) productModalErrorText.textContent = error.message || 'Analysis failed.';
    showProductModalState('error');
    setError(`Product Analysis failed: ${error.message || 'Unknown error'} `);
  } finally {
    setProductAnalyzing(false);
  }
};

const generateProductImage = async (concept) => {
  if (state.activeRequests >= state.queueLimit) {
    setError('Queue is full. Wait for a batch to finish.');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    return;
  }
  if (productState.referenceImages.length === 0) {
    setError('Product reference images are missing.');
    return;
  }

  const analysis = productState.analysis || { products: [], bundleRules: {} };
  const analyzedProducts = Array.isArray(analysis.products) ? analysis.products : [];
  const fallbackUsagePlan = analyzedProducts.map((product) => ({
    reference_index: product.reference_index,
    product_label: product.product_label,
    placement: '',
    visibility_goal: '',
    accuracy_notes: product.accuracy_notes.length ? product.accuracy_notes : product.signature_details
  }));
  const conceptUsagePlan = Array.isArray(concept?.generation_payload?.product_usage_plan) && concept.generation_payload.product_usage_plan.length
    ? concept.generation_payload.product_usage_plan
    : fallbackUsagePlan;
  const referenceAccuracyNotes = normalizeStringArray(concept?.generation_payload?.reference_accuracy_notes);
  const bundleAccuracyRules = normalizeStringArray(analysis?.bundleRules?.accuracy_constraints);
  const isVideo = concept.campaign_details?.asset_type !== 'Photoshoot Ad';
  const selectedAspect = document.getElementById('product-modal-aspect')?.value || '1:1';
  const aspectHint = aspectHints[selectedAspect] || '';
  const optimizedGenerationReferences = await Promise.all(
    productState.referenceImages.map((item) => getOptimizedModelDataUrl(item, 'generate'))
  );
  const optimizedCharacterImageUrl = productState.characterImage
    ? await getOptimizedModelDataUrl(productState.characterImage, 'generate')
    : null;

  const buildStructuredPrompt = (briefText, type) => JSON.stringify({
    task: `product_advertisement_bundle_${type}`,
    quality: 'ultra_high_8K',
    instructions: [
      `Create an ultra high-end commercial product advertisement image for the ${type.replace(/_/g, ' ')}.`,
      'Every uploaded product reference must appear in the final image and stay clearly recognizable.',
      'Preserve exact product shape, proportions, materials, trims, hardware, seams, print placement, color blocking, and surface texture from the references.',
      'Preserve authentic on-product branding or readable text only when it already exists in the uploaded reference images, with matching spelling and placement.',
      'Do not invent extra text overlays, captions, posters, watermarks, altered logos, duplicate products, or missing products.'
    ],
    creative_brief: briefText,
    reference_bundle: {
      total_products: productState.referenceImages.length,
      analysis_summary: analysis?.summary || '',
      products: analyzedProducts.map((product) => ({
        reference_index: product.reference_index,
        product_label: product.product_label,
        category: product.category,
        colors: product.colors,
        materials: product.materials,
        brand_text_visible: product.brand_text_visible,
        signature_details: product.signature_details,
        accuracy_notes: product.accuracy_notes
      }))
    },
    product_usage_plan: conceptUsagePlan,
    accuracy_rules: [...new Set([...bundleAccuracyRules, ...referenceAccuracyNotes].filter(Boolean))],
    output_requirements: {
      resolution: '8K',
      style: 'commercial_advertisement',
      realism: 'photorealistic',
      lighting: 'professional_studio',
      post_production: 'high_end_retouching',
      focus: 'multi_product_bundle',
      preserve_reference_branding: true,
      no_overlay_text: true,
      no_watermarks: true,
      no_ui: true,
      clean_image_only: true
    }
  }, null, 2);

  const OVERLAY_ONLY_RULE =
    'ABSOLUTE RULE: Do not add extra overlay text, captions, watermarks, interface graphics, posters, or invented branding. ' +
    'Keep only authentic product text or logos that already exist on the uploaded reference products.';
  const bundleIntegrityNegative =
    'watermarks, captions, interface elements, floating text, poster typography, extra products, missing products, duplicate products, wrong product colors, altered branding, incorrect spelling, distorted straps, incorrect watch details, broken bag handles';
  const baseNegative = [concept.generation_payload?.negative_prompt || '', bundleIntegrityNegative].filter(Boolean).join(', ');

  const buildProductReferenceParts = () => {
    const parts = [];

    productState.referenceImages.forEach((item, index) => {
      const analyzedProduct = analyzedProducts[index] || {};
      const visibleTextNotes = normalizeStringArray(analyzedProduct.brand_text_visible).map((text) => `Visible text/logo: ${text}`);
      const detailNotes = [
        ...normalizeStringArray(analyzedProduct.signature_details),
        ...normalizeStringArray(analyzedProduct.accuracy_notes),
        ...visibleTextNotes
      ].slice(0, 6);

      const label = analyzedProduct.product_label || analyzedProduct.category || `Product ${index + 1}`;
      const detailText = detailNotes.length
        ? `Must match these visible details exactly: ${detailNotes.join('; ')}.`
        : 'Preserve the exact visible design, proportions, colors, and construction from this reference.';

      parts.push({
        type: 'text',
        text: `Product reference ${index + 1} of ${productState.referenceImages.length}: ${label}. ${detailText}`
      });
      parts.push({ type: 'image_url', image_url: { url: optimizedGenerationReferences[index] || item.dataUrl } });
    });

    return parts;
  };

  const startPromptText =
    `${OVERLAY_ONLY_RULE}\n\nGenerate a professional bundle-style product advertisement image based on this START FRAME creative brief:\n` +
    `${buildStructuredPrompt(concept.generation_payload?.start_frame_prompt || concept.start_frame_prompt, 'start_frame')}\n${aspectHint}\nNegative Prompt: ${baseNegative}`;

  const startContentParts = [{ type: 'text', text: startPromptText }, ...buildProductReferenceParts()];

  if (optimizedCharacterImageUrl) {
    startContentParts.push({
      type: 'text',
      text: 'Character reference. Keep this exact person consistent and style the bundle naturally around them.'
    });
    startContentParts.push({ type: 'image_url', image_url: { url: optimizedCharacterImageUrl } });
  }

  const selectedModel = productModalModel?.value || 'google/gemini-3.1-flash-image-preview';
  const desiredCount = isVideo ? 2 : 1;

  setLoading(true);
  state.activeRequests += desiredCount;
  updateQueueStatus();
  galleryEmpty.style.display = 'none';

  const skeletons = createSkeletons(desiredCount);

  try {
    // 1. Generate Start Frame first
    const startImages = await requestImages(startContentParts, undefined, selectedModel);

    if (!startImages || startImages.length === 0) {
      throw new Error('Failed to generate start frame.');
    }

    if (isVideo) {
      if (skeletons[1]) {
        // Create skeletons pushes to top, so index 1 is bottom (start frame), index 0 is top (end frame)
        replaceSkeletonWithImage(skeletons[1], startImages[0], 0, {
          promptText: JSON.stringify(concept, null, 2),
          modelName: selectedModel,
          aspectRatio: selectedAspect,
          sourceFeature: 'product'
        });
      }

      const endPromptText =
        `${OVERLAY_ONLY_RULE}\n\nGenerate a professional bundle-style product advertisement image based on this END FRAME creative brief:\n` +
        `${buildStructuredPrompt(concept.generation_payload?.end_frame_prompt || concept.end_frame_prompt, 'end_frame')}\n${aspectHint}\nNegative Prompt: ${baseNegative}`;

      // 2. Build End Frame payload using all product references plus the start frame for continuity
      const endContentParts = [
        { type: 'text', text: endPromptText },
        ...buildProductReferenceParts(),
        { type: 'text', text: 'Start frame continuity reference. Keep the same exact products, styling, and person while evolving the scene into the end frame.' },
        { type: 'image_url', image_url: { url: startImages[0] } }
      ];

      if (optimizedCharacterImageUrl) {
        endContentParts.push({
          type: 'text',
          text: 'Character continuity reference. Keep this exact person consistent in the end frame.'
        });
        endContentParts.push({ type: 'image_url', image_url: { url: optimizedCharacterImageUrl } });
      }

      // 3. Generate End Frame
      const endImages = await requestImages(endContentParts, undefined, selectedModel);

      if (endImages.length > 0 && skeletons[0]) {
        replaceSkeletonWithImage(skeletons[0], endImages[0], 1, {
          promptText: JSON.stringify(concept, null, 2),
          modelName: selectedModel,
          aspectRatio: selectedAspect,
          sourceFeature: 'product'
        });
      }
    } else {
      if (skeletons[0]) {
        replaceSkeletonWithImage(skeletons[0], startImages[0], 0, {
          promptText: JSON.stringify(concept, null, 2),
          modelName: selectedModel,
          aspectRatio: selectedAspect,
          sourceFeature: 'product'
        });
      }
    }

    imageCount.textContent = galleryGrid.children.length;

    window.scrollTo({
      top: document.querySelector('.gallery').offsetTop - 20,
      behavior: 'smooth'
    });

  } catch (error) {
    console.error(error);
    setError(error.message || 'Product Generation failed.');

    skeletons.forEach(skel => skel.remove());

    if (galleryGrid.children.length === 0) {
      galleryEmpty.style.display = 'flex';
    }
  } finally {
    state.activeRequests -= desiredCount;
    updateQueueStatus();
    setLoading(state.activeRequests > 0);
  }
};

const handleSubmit = async (event) => {
  event.preventDefault();
  setError('');

  // Check queue limit
  if (state.activeRequests >= state.queueLimit) {
    setError('Queue is full. Wait for a batch to finish.');
    return;
  }

  const basePrompt = promptInput.value.trim();
  if (!basePrompt) {
    setError('Enter a prompt.');
    promptInput.focus();
    return;
  }

  if (aspectSelect.value === 'reference') {
    const ref = getReferenceImageForAspect();
    if (!ref?.width || !ref?.height) {
      setError('Add a reference, character, scene, or style image to use Reference aspect ratio.');
      return;
    }
  }

  const desiredCount = Math.max(1, Math.min(Number(countRange.value) || 1, 4));
  const seedValue = seedInput && seedInput.value.trim() !== '' ? Number(seedInput.value) : null;
  const selectedModel = modelSelect.value || 'google/gemini-2.0-flash-exp';

  lastPrompt = buildPrompt();
  const contentParts = buildContentParts();

  // Clear prompt after capturing it
  promptInput.value = '';
  promptInput.style.height = 'auto';

  setLoading(true);
  state.activeRequests++;
  updateQueueStatus();
  galleryEmpty.style.display = 'none';

  // Create Local Skeletons
  const skeletons = createSkeletons(desiredCount);

  try {
    const images = [];

    // Batch Request
    for (let i = 0; i < desiredCount; i += 1) {
      const batch = await requestImages(
        contentParts,
        Number.isFinite(seedValue) ? seedValue + i : undefined,
        selectedModel
      );
      images.push(...batch);
      if (images.length >= desiredCount) break;
    }

    const trimmed = images.slice(0, desiredCount);
    if (!trimmed.length) throw new Error('No images returned.');

    // Replace skeletons with Real Images
    trimmed.forEach((src, idx) => {
      if (skeletons[idx]) {
        replaceSkeletonWithImage(skeletons[idx], src, idx, {
          promptText: lastPrompt,
          modelName: selectedModel,
          aspectRatio: aspectSelect?.value || '',
          sourceFeature: activeFeature
        });
      }
    });

    // Update count display based on real children
    imageCount.textContent = galleryGrid.children.length;

  } catch (error) {
    console.error(error);
    setError(error.message || 'Generation failed.');

    // Remove failed skeletons
    skeletons.forEach(skel => skel.remove());

    if (galleryGrid.children.length === 0) {
      galleryEmpty.style.display = 'flex';
    }
  } finally {
    state.activeRequests--;
    updateQueueStatus();
    setLoading(state.activeRequests > 0);
  }
};

const generateVideoPromptWithAi = async () => {
  if (state.activeRequests >= state.queueLimit) {
    if (videoStatus) videoStatus.textContent = 'Queue is full. Wait for a batch to finish.';
    return;
  }

  if (!videoState.startFrame) {
    if (videoStatus) videoStatus.textContent = 'Upload a Start Frame before generating an AI motion prompt.';
    return;
  }

  setError('');
  setVideoPromptGenerating(true);
  state.activeRequests++;
  updateQueueStatus();

  try {
    const plan = await requestVideoPromptPlan();
    videoState.promptPlan = plan;
    videoState.promptSource = 'ai';
    renderVideoPromptPlan(plan);

    if (videoPrompt) {
      videoPrompt.value = plan.motion_prompt || '';
      videoPrompt.dispatchEvent(new Event('input', { bubbles: true }));
    }

    if (videoStatus) {
      videoStatus.textContent = 'AI motion prompt generated from your frame references.';
    }
  } catch (error) {
    console.error('Video Prompt Analysis Failed:', error);
    resetVideoPromptPlan();
    if (videoStatus) videoStatus.textContent = error.message || 'AI video prompt generation failed.';
    setError(`AI video prompt generation failed: ${error.message || 'Unknown error'}`);
  } finally {
    state.activeRequests--;
    updateQueueStatus();
    setVideoPromptGenerating(false);
  }
};

const generateVideo = async () => {
  if (state.activeRequests >= state.queueLimit) {
    if (videoStatus) videoStatus.textContent = 'Queue is full. Wait for a batch to finish.';
    return;
  }

  if (!videoState.startFrame) {
    if (videoStatus) videoStatus.textContent = 'Start Frame is required.';
    return;
  }

  const model = videoModelSelect?.value || 'kling-v2-6';
  const aspect = videoAspectSelect?.value || '16:9';
  const duration = videoDurationSelect?.value || '5';
  const prompt = (videoPrompt?.value || videoState.promptPlan?.motion_prompt || '').trim();

  setVideoGenerating(true);
  state.activeRequests++;
  updateQueueStatus();
  galleryEmpty.style.display = 'none';

  const videoCard = createVideoLoadingCard(duration);

  try {
    const stripBase64Prefix = (dataUrl) => dataUrl ? dataUrl.split(',')[1] : undefined;

    const payload = {
      model_name: model,
      prompt: prompt,
      image: stripBase64Prefix(videoState.startFrame.dataUrl),
      aspect_ratio: aspect,
      duration: duration
    };

    if (videoState.endFrame) {
      payload.image_tail = stripBase64Prefix(videoState.endFrame.dataUrl);
      payload.mode = 'pro';
    }

    const response = await fetch('/api/studio/kling/generate', {
      method: 'POST',
      headers: buildHeaders(),
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    if (!response.ok) {
      const errorMsg = data?.error?.message || data?.message || (typeof data?.error === 'string' ? data.error : 'Failed to start video generation');
      throw new Error(errorMsg);
    }

    applyStudioResponseMeta(data);

    const taskId = data.data?.task_id;
    if (!taskId) throw new Error('No task ID returned.');

    videoState.taskId = taskId;
    if (videoStatus) {
      videoStatus.innerHTML = `<i data-lucide="loader-2" class="w-3 h-3 animate-spin inline-block mr-1"></i> Polling task: ${taskId}`;
      if (window.lucide) window.lucide.createIcons({ root: videoStatus });
    }

    // Polling function
    const pollStatus = async () => {
      try {
        const pollRes = await fetch('/api/studio/kling/task/' + taskId + '?model_name=' + model, {
          headers: buildHeaders()
        });
        const pollData = await pollRes.json();

        if (!pollRes.ok) {
          throw new Error(pollData.message || pollData.error?.message || (typeof pollData.error === 'string' ? pollData.error : 'Poll failed'));
        }

        const taskStatus = pollData.data?.task_status;
        if (taskStatus === 'succeed') {
          const videoUrls = pollData.data?.task_result?.videos;
          if (videoUrls && videoUrls.length > 0) {
            const videoUrl = videoUrls[0].url;
            let resolvedVideoUrl = videoUrl;
            let savedVideoMedia = null;

            // Video metadata is saved server-side via /api/studio/save-video
            console.log('Video ready:', videoUrl);

            // Persist the generated video to Supabase storage + metadata
            try {
              const saveRes = await fetch('/api/studio/save-video', {
                method: 'POST',
                headers: buildHeaders(),
                body: JSON.stringify({
                  videoUrl,
                  taskId,
                  promptText: prompt,
                  modelName: model,
                  aspectRatio: aspect,
                  sourceFeature: 'video'
                })
              });
              const saveData = await saveRes.json();
              if (!saveRes.ok) {
                console.error('Failed to save video to Supabase:', saveData);
              } else {
                console.log('Video saved to Supabase media gallery:', saveData.filePath);
                if (saveData?.filePath) {
                  resolvedVideoUrl = saveData.filePath;
                }
                savedVideoMedia = saveData?.media || null;
              }
            } catch (saveErr) {
              console.error('Error calling save-video endpoint:', saveErr);
            }

            await replaceSkeletonWithVideo(videoCard, resolvedVideoUrl, 0, savedVideoMedia);
            imageCount.textContent = galleryGrid.children.length;
            if (videoStatus) videoStatus.textContent = 'Video generation succeeded!';
            setVideoGenerating(false);
            state.activeRequests--;
            updateQueueStatus();
          } else {
            throw new Error('Task succeeded but no video url found');
          }
        } else if (taskStatus === 'failed') {
          throw new Error(pollData.data?.task_status_msg || 'Task failed on server');
        } else {
          // Still running
          const progress = pollData.data?.task_progress || 0;
          updateVideoProgress(videoCard, progress, taskStatus || 'Generating...');

          if (videoStatus) {
            videoStatus.innerHTML = '<i data-lucide="loader-2" class="w-3 h-3 animate-spin inline-block mr-1"></i> Status: ' + (taskStatus || 'Pending') + ' (' + progress + '%)';
            if (window.lucide) window.lucide.createIcons({ root: videoStatus });
          }
          setTimeout(pollStatus, 5000);
        }
      } catch (err) {
        console.error('Task Polling Error:', err);
        if (videoStatus) videoStatus.textContent = err.message || 'Video generation polling failed.';
        videoCard.remove();
        if (galleryGrid.children.length === 0) {
          galleryEmpty.style.display = 'flex';
        }
        setVideoGenerating(false);
        state.activeRequests--;
        updateQueueStatus();
      }
    };

    setTimeout(pollStatus, 3000);

  } catch (err) {
    console.error(err);
    if (videoStatus) videoStatus.textContent = err.message || 'Video generation failed.';
    videoCard.remove();
    if (galleryGrid.children.length === 0) {
      galleryEmpty.style.display = 'flex';
    }
    setVideoGenerating(false);
    state.activeRequests--;
    updateQueueStatus();
  }
};

if (videoGenerateBtn) {
  videoGenerateBtn.addEventListener('click', generateVideo);
}
if (videoAiGenerateBtn) {
  videoAiGenerateBtn.addEventListener('click', generateVideoPromptWithAi);
}
if (videoPrompt) {
  videoPrompt.addEventListener('input', () => {
    const currentValue = videoPrompt.value.trim();
    const aiValue = videoState.promptPlan?.motion_prompt ? videoState.promptPlan.motion_prompt.trim() : '';
    if (videoState.promptSource === 'ai' && currentValue === aiValue) return;
    videoState.promptSource = currentValue ? 'manual' : null;
  });
}
if (videoCopyAiJsonBtn) {
  videoCopyAiJsonBtn.addEventListener('click', () => {
    if (!videoState.promptPlan || !navigator.clipboard) return;
    navigator.clipboard.writeText(JSON.stringify(videoState.promptPlan, null, 2)).then(() => {
      videoCopyAiJsonBtn.innerHTML = '<i data-lucide="check" class="w-3 h-3"></i> Copied';
      if (window.lucide) window.lucide.createIcons({ root: videoCopyAiJsonBtn });
      setTimeout(() => {
        videoCopyAiJsonBtn.innerHTML = '<i data-lucide="copy" class="w-3 h-3"></i> Copy JSON';
        if (window.lucide) window.lucide.createIcons({ root: videoCopyAiJsonBtn });
      }, 2000);
    });
  });
}

const clearForm = () => {
  form.reset();
  state.referenceImages = [];
  state.characterImages = [];
  state.sceneImage = null;
  state.styleImage = null;
  recreateState.referenceImage = null;
  recreateState.analysis = null;
  recreateState.elements = [];
  recreateState.overrides = {};
  productState.referenceImages = [];
  productState.characterImage = null;
  resetProductResults();
  renderProductAnalysisSummary();

  videoState.startFrame = null;
  videoState.endFrame = null;
  videoState.taskId = null;
  videoState.promptSource = null;
  resetVideoPromptPlan({ clearPrompt: true });
  renderVideoStartPreview();
  renderVideoEndPreview();
  if (videoStatus) videoStatus.textContent = '';

  updateCount();
  renderReferencePreview();
  renderCharacterPreview();
  refreshScenePreview();
  refreshStylePreview();
  refreshRecreateReferencePreview();
  renderProductReferencePreview();
  renderProductCharacterPreview();
  renderRecreateEditor();
  setError('');
  setStatus('Ready');
  setRecreateStatus('');
  setProductAnalyzing(false);
  setVideoPromptGenerating(false);
  loadStudioMediaGallery({ force: true }).catch((error) => {
    console.warn('Failed to reload studio media gallery after clear.', error);
  });
};

const applyPrompt = (value) => {
  promptInput.value = value;
  promptInput.focus();
};


const syncModelSelects = () => {
  if (!modelSelect || !recreateModelSelect) return;

  const updateCustomLabel = (val) => {
    const modelSelectLabel = document.getElementById('model-select-label');
    const option = document.querySelector(`.custom - option[data - value="${val}"]`);
    if (modelSelectLabel && option) {
      modelSelectLabel.textContent = option.textContent;
    }
  };

  recreateModelSelect.value = modelSelect.value;
  recreateModelSelect.addEventListener('change', () => {
    modelSelect.value = recreateModelSelect.value;
    updateCustomLabel(modelSelect.value);
  });
  modelSelect.addEventListener('change', () => {
    recreateModelSelect.value = modelSelect.value;
    updateCustomLabel(modelSelect.value);
  });
};

// Event Listeners
if (form) form.addEventListener('submit', handleSubmit);
if (countRange) countRange.addEventListener('input', updateCount);
if (clearBtn) clearBtn.addEventListener('click', clearForm);
featureTabs.forEach((tab) => {
  tab.addEventListener('click', () => {
    const target = tab.dataset.featureTab;
    if (target) setActiveFeature(target);
  });
});
if (recreateAnalyzeBtn) recreateAnalyzeBtn.addEventListener('click', analyzeRecreateReference);
if (recreateRunBtn) recreateRunBtn.addEventListener('click', handleRecreate);
if (productAnalyzeBtn) productAnalyzeBtn.addEventListener('click', analyzeProductReference);
if (productGenerateBtn) productGenerateBtn.addEventListener('click', () => {
  if (productState.selectedPrompt) {
    generateProductImage(productState.selectedPrompt);
  }
});

const handleCopyJson = (btn) => {
  if (!productState.selectedPrompt || !navigator.clipboard) return;

  const textToCopy = JSON.stringify(productState.selectedPrompt, null, 2);

  navigator.clipboard.writeText(textToCopy).then(() => {
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i data-lucide="check" class="w-3.5 h-3.5 text-green-400"></i> Copied!';
    if (window.lucide) window.lucide.createIcons({ root: btn });

    setTimeout(() => {
      btn.innerHTML = originalText;
      if (window.lucide) window.lucide.createIcons({ root: btn });
    }, 2000);
  });
};

const sidebarCopyJsonBtn = document.getElementById('product-copy-json-sidebar');
if (sidebarCopyJsonBtn) {
  sidebarCopyJsonBtn.addEventListener('click', () => handleCopyJson(sidebarCopyJsonBtn));
}

const modalCopyJsonBtn = document.getElementById('product-copy-json-modal');
if (modalCopyJsonBtn) {
  modalCopyJsonBtn.addEventListener('click', () => handleCopyJson(modalCopyJsonBtn));
}

// Product Prompts Modal event listeners
if (productModalClose) productModalClose.addEventListener('click', closeProductModal);
if (productModalBackdrop) productModalBackdrop.addEventListener('click', closeProductModal);
if (productModalRetry) productModalRetry.addEventListener('click', () => {
  closeProductModal();
  analyzeProductReference();
});
if (productModalGenerate) productModalGenerate.addEventListener('click', () => {
  if (productState.selectedPrompt) {
    closeProductModal();
    generateProductImage(productState.selectedPrompt);
  }
});
window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && productPromptsModal && !productPromptsModal.classList.contains('hidden')) {
    closeProductModal();
  }
});
if (productViewPromptsBtn) productViewPromptsBtn.addEventListener('click', () => {
  if (productModalList && productModalList.children.length > 0) {
    openProductModal();
    showProductModalState('results');
  }
});

surpriseBtn.addEventListener('click', () => {
  const pick = surprisePrompts[Math.floor(Math.random() * surprisePrompts.length)];
  applyPrompt(pick);
});

promptInput.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' || !event.ctrlKey) return;
  event.preventDefault();
  if (generateBtn && !generateBtn.disabled) {
    if (typeof form.requestSubmit === 'function') {
      form.requestSubmit(generateBtn);
    } else {
      generateBtn.click();
    }
  }
});

const attachSampleListeners = () => {
  document.querySelectorAll('.sample').forEach((button) => {
    button.addEventListener('click', () => applyPrompt(button.dataset.prompt || ''));
  });
}
attachSampleListeners();

updateCount();
syncModelSelects();
updateQueueStatus();
renderRecreateEditor();
renderVideoStartPreview();
renderVideoEndPreview();
renderVideoPromptPlan(videoState.promptPlan);
if (studioBackLink && !isEmbeddedStudio) {
  const urlParams = new URLSearchParams(window.location.search);
  studioBackLink.href = urlParams.get('return') || '/dashboard';
  studioBackLink.classList.remove('hidden');
  studioBackLink.classList.add('inline-flex');
}
setActiveFeature(activeFeature);
loadStandaloneStudioContext().catch((error) => {
  console.error('Failed to initialize standalone studio context.', error);
});

// --- Custom Model Select Logic ---
const customModelWrapper = document.getElementById('custom-model-wrapper');
const modelSelectTrigger = document.getElementById('model-select-trigger');
const modelSelectLabel = document.getElementById('model-select-label');
const modelSelectMenu = document.getElementById('model-select-menu');
const modelSelectIcon = document.getElementById('model-select-icon');
const customOptions = document.querySelectorAll('.custom-option');

if (modelSelectTrigger && modelSelectMenu) {
  modelSelectTrigger.addEventListener('click', (e) => {
    e.stopPropagation();
    const isExpanded = !modelSelectMenu.classList.contains('hidden');

    if (isExpanded) {
      modelSelectMenu.classList.add('hidden');
      modelSelectMenu.classList.remove('flex');
      if (modelSelectIcon) modelSelectIcon.style.transform = '';
    } else {
      modelSelectMenu.classList.remove('hidden');
      modelSelectMenu.classList.add('flex');
      if (modelSelectIcon) modelSelectIcon.style.transform = 'rotate(180deg)';
    }
  });

  customOptions.forEach(option => {
    option.addEventListener('click', (e) => {
      e.stopPropagation();
      const value = option.dataset.value;
      const text = option.textContent;

      // Update hidden select
      if (modelSelect) {
        modelSelect.value = value;
        modelSelect.dispatchEvent(new Event('change'));
      }

      // Update UI
      if (modelSelectLabel) modelSelectLabel.textContent = text;

      // Close menu
      modelSelectMenu.classList.add('hidden');
      modelSelectMenu.classList.remove('flex');
      if (modelSelectIcon) modelSelectIcon.style.transform = '';
    });
  });

  // Close when clicking outside
  document.addEventListener('click', (e) => {
    if (customModelWrapper && !customModelWrapper.contains(e.target)) {
      modelSelectMenu.classList.add('hidden');
      modelSelectMenu.classList.remove('flex');
      if (modelSelectIcon) modelSelectIcon.style.transform = '';
    }
  });
}

// Initialize IndexedDB for recent uploads only, then load generated media from Supabase
initDB().then(async () => {
  try {
    if (parentAuthToken) {
      await loadStudioMediaGallery({ force: true });
    }
  } catch (e) {
    console.warn(e);
  }
}).catch(e => console.warn(e));

// --- Image History Modal Logic ---
const historyModal = document.getElementById('history-modal');
const historyBackdrop = document.getElementById('history-backdrop');
const historyClose = document.getElementById('history-close');
const historyGrid = document.getElementById('history-grid');
const historyEmpty = document.getElementById('history-empty');

let currentHistoryTarget = null; // Stores what we are picking an image for

const closeHistoryModal = () => {
  historyModal.classList.add('hidden');
  historyModal.classList.remove('flex');
  historyModal.setAttribute('aria-hidden', 'true');
  currentHistoryTarget = null;
};

const openHistoryModal = async (target) => {
  currentHistoryTarget = target;
  historyModal.classList.remove('hidden');
  historyModal.classList.add('flex');
  historyModal.setAttribute('aria-hidden', 'false');

  historyGrid.innerHTML = '';
  historyEmpty.classList.add('hidden');

  try {
    const uploads = await loadUploadedImages();
    if (uploads.length === 0) {
      historyEmpty.classList.remove('hidden');
      historyEmpty.classList.add('flex');
      return;
    }

    uploads.forEach(item => {
      const card = document.createElement('div');
      card.className = 'relative flex flex-col group cursor-pointer';

      const imgContainer = document.createElement('div');
      imgContainer.className = 'relative aspect-square rounded-xl overflow-hidden bg-black/50 border border-white/10 group-hover:border-blue-500/50 transition-colors';

      const imgEl = document.createElement('img');
      imgEl.src = item.src;
      imgEl.className = 'w-full h-full object-cover';

      const overlay = document.createElement('div');
      overlay.className = 'absolute inset-0 bg-blue-500/20 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center';
      overlay.innerHTML = '<i data-lucide="check-circle-2" class="w-6 h-6 text-white drop-shadow-lg"></i>';

      imgContainer.appendChild(imgEl);
      imgContainer.appendChild(overlay);
      card.appendChild(imgContainer);

      card.addEventListener('click', () => handleHistorySelection(item.src));
      historyGrid.appendChild(card);
    });

    if (window.lucide) window.lucide.createIcons({ root: historyGrid });
  } catch (error) {
    console.error('Failed to load uploads history', error);
  }
};

const handleHistorySelection = async (dataUrl) => {
  const target = currentHistoryTarget; // Cache the target
  closeHistoryModal(); // This resets currentHistoryTarget to null
  if (!target) return;

  // Generate a mock file object for consistency with existing functions if needed,
  // but we can just map it directly to our state shape.
  let size = null;
  try {
    size = await getImageSize(dataUrl);
  } catch (e) {
    console.warn(e);
  }

  const newItem = {
    dataUrl,
    name: 'History Image',
    width: size?.width || null,
    height: size?.height || null
  };

  if (target === 'reference') {
    if (state.referenceImages.length < 4) {
      state.referenceImages.push(newItem);
      renderReferencePreview();
    } else {
      setError('Max 4 reference images allowed.');
    }
  } else if (target === 'character') {
    if (state.characterImages.length < 6) {
      state.characterImages.push({ ...newItem, spec: '' });
      renderCharacterPreview();
    } else {
      setError('Max 6 character images allowed.');
    }
  } else if (target === 'scene') {
    state.sceneImage = newItem;
    refreshScenePreview();
  } else if (target === 'style') {
    state.styleImage = newItem;
    refreshStylePreview();
  } else if (target === 'recreate-reference') {
    recreateState.referenceImage = newItem;
    recreateState.analysis = null;
    recreateState.elements = [];
    recreateState.overrides = {};
    refreshRecreateReferencePreview();
    renderRecreateEditor();
    setRecreateStatus('Reference loaded from history. Ready to analyze.');
  } else if (target === 'product-reference') {
    if (productState.referenceImages.length >= MAX_PRODUCT_REFERENCES) {
      setError(`Max ${MAX_PRODUCT_REFERENCES} product reference images allowed.`);
      return;
    }
    productState.referenceImages.push(newItem);
    resetProductResults();
    renderProductAnalysisSummary();
    renderProductReferencePreview();
  } else if (target === 'product-character') {
    productState.characterImage = newItem;
    resetProductResults();
    renderProductAnalysisSummary();
    renderProductCharacterPreview();
  } else if (target.startsWith('recreate-element-')) {
    const elementId = target.replace('recreate-element-', '');
    const override = getElementOverride(elementId);
    override.image = newItem;
    renderElementPreview(elementId);
  }
};

if (historyClose) historyClose.addEventListener('click', closeHistoryModal);
if (historyBackdrop) historyBackdrop.addEventListener('click', closeHistoryModal);

document.querySelectorAll('.history-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    openHistoryModal(btn.dataset.target);
  });
});
