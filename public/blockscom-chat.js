(function () {
  const script = document.currentScript;
  const key = script?.getAttribute('data-key');
  const apiBase = script?.getAttribute('data-api') || 'https://webhook.ramilflaviano.art';

  if (!key) {
    console.error('[Blockscom Chat] Missing data-key');
    return;
  }

  const style = document.createElement('style');
  style.innerHTML = `
  @keyframes bc-fade-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
  .bc-chat-btn {
    position: fixed; right: 20px; bottom: 20px; z-index: 99999;
    width: 60px; height: 60px;
    background: linear-gradient(135deg, #6e8efb, #a777e3);
    color: #fff; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; box-shadow: 0 10px 25px rgba(110, 142, 251, 0.4);
    transition: all 0.3s ease;
  }
  .bc-chat-btn:hover { transform: scale(1.1) rotate(5deg); box-shadow: 0 15px 30px rgba(110, 142, 251, 0.5); }
  .bc-chat-box {
    position: fixed; right: 20px; bottom: 90px; z-index: 99999;
    width: 350px; height: 500px;
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.3);
    border-radius: 24px;
    display: none; flex-direction: column;
    overflow: hidden; font-family: 'Inter', -apple-system, sans-serif;
    box-shadow: 0 20px 40px rgba(0,0,0,0.15);
    animation: bc-fade-in 0.4s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .bc-head {
    background: linear-gradient(135deg, #6e8efb, #a777e3);
    color: #fff; padding: 20px;
    font-weight: 700; font-size: 16px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .bc-msgs {
    flex: 1; padding: 20px; overflow: auto;
    background: #f8f9fa; display: flex; flex-direction: column; gap: 12px;
  }
  .bc-row {
    max-width: 80%; padding: 10px 14px;
    border-radius: 18px; font-size: 14px; line-height: 1.4;
    word-wrap: break-word;
  }
  .bc-user {
    align-self: flex-end;
    background: #6e8efb; color: #fff;
    border-bottom-right-radius: 4px;
  }
  .bc-bot {
    align-self: flex-start;
    background: #fff; color: #333;
    border-bottom-left-radius: 4px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.05);
  }
  .bc-input {
    display: flex; padding: 15px; background: #fff;
    border-top: 1px solid #eee; align-items: center; gap: 10px;
  }
  .bc-input input {
    flex: 1; border: 1px solid #eee; padding: 12px 15px;
    border-radius: 99px; outline: none; font-size: 14px;
    transition: border-color 0.2s;
  }
  .bc-input input:focus { border-color: #6e8efb; }
  .bc-input button {
    border: 0; background: #6e8efb; color: #fff;
    width: 40px; height: 40px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; transition: background 0.2s;
  }
  .bc-input button:hover { background: #a777e3; }
  `;
  document.head.appendChild(style);

  const btn = document.createElement('div');
  btn.className = 'bc-chat-btn';
  btn.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>';

  const box = document.createElement('div');
  box.className = 'bc-chat-box';
  box.innerHTML = `
    <div class="bc-head">
      <span>Blockscom Assistant</span>
      <span style="cursor:pointer;opacity:0.8" id="bc-close">✕</span>
    </div>
    <div class="bc-msgs" id="bc-msgs"></div>
    <div class="bc-input">
      <input id="bc-input" placeholder="How can we help?"/>
      <button id="bc-send">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>
      </button>
    </div>
  `;

  document.body.appendChild(btn);
  document.body.appendChild(box);

  const msgs = box.querySelector('#bc-msgs');
  const input = box.querySelector('#bc-input');
  const send = box.querySelector('#bc-send');
  const close = box.querySelector('#bc-close');

  function push(role, text) {
    const row = document.createElement('div');
    row.className = 'bc-row ' + (role === 'user' ? 'bc-user' : 'bc-bot');
    row.textContent = text;
    msgs.appendChild(row);
    msgs.scrollTop = msgs.scrollHeight;
  }

  async function sendMsg() {
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    push('user', text);
    try {
      const r = await fetch(`${apiBase}/api/widget/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, message: text })
      });
      const j = await r.json();
      push('bot', j.reply || j.error || 'No response');
    } catch (e) {
      push('bot', 'Connection error');
    }
  }

  const toggle = () => { box.style.display = box.style.display === 'flex' ? 'none' : 'flex'; };
  btn.onclick = toggle;
  close.onclick = toggle;
  send.onclick = sendMsg;
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMsg(); });
})();
