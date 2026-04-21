/* ─────────────────────────────────────────────
   SOC Intelligence · app.js
   Dashboard + Copilot logic
───────────────────────────────────────────── */

// ── CONFIG ────────────────────────────────────

const API_URL = "http://127.0.0.1:8000";

// ── DATA ──────────────────────────────────────

const ALERTS_DATA = [
  { sev:'critical', title:'Brute Force SSH Detectado',       ip:'185.220.101.45', mitre:'T1110', src:'ssh',    ago:'4min' },
  { sev:'critical', title:'PowerShell Base64 Execução',      ip:'10.0.0.55',      mitre:'T1059', src:'sysmon', ago:'11min' },
  { sev:'high',     title:'Directory Traversal /etc/passwd', ip:'103.21.244.0',   mitre:'T1006', src:'nginx',  ago:'19min' },
  { sev:'high',     title:'Acesso .git Exposto',             ip:'45.33.32.156',   mitre:'T1595', src:'nginx',  ago:'32min' },
  { sev:'medium',   title:'Port Scan Detectado',             ip:'198.51.100.22',  mitre:'T1046', src:'fw',     ago:'41min' },
  { sev:'medium',   title:'SQL Injection Tentativa',         ip:'92.118.160.10',  mitre:'T1190', src:'nginx',  ago:'58min' },
  { sev:'low',      title:'Login Fora do Horário',           ip:'172.16.0.88',    mitre:'T1078', src:'ssh',    ago:'1h 12min' },
  { sev:'high',     title:'Processo Filho Anômalo cmd.exe',  ip:'10.0.1.12',      mitre:'T1059', src:'sysmon', ago:'1h 24min' },
  { sev:'low',      title:'Scan de Vulnerabilidade',         ip:'209.85.23.99',   mitre:'T1595', src:'nginx',  ago:'2h 03min' },
];

const IPS_DATA = [
  { ip:'185.220.101.45', country:'🇷🇺 RU', attacks:342, score:98 },
  { ip:'103.21.244.0',   country:'🇨🇳 CN', attacks:218, score:91 },
  { ip:'45.33.32.156',   country:'🇺🇸 US', attacks:174, score:78 },
  { ip:'5.188.206.26',   country:'🇳🇱 NL', attacks:129, score:72 },
  { ip:'92.118.160.10',  country:'🇧🇷 BR', attacks:87,  score:55 },
  { ip:'198.51.100.22',  country:'🇩🇪 DE', attacks:44,  score:31 },
];

const SOAR_DATA = [
  { icon:'🚫', title:'IP Bloqueado Automaticamente',  detail:'185.220.101.45 → iptables DROP',          time:'há 3min' },
  { icon:'🎫', title:'Ticket Criado — INC-2024-0891', detail:'Brute Force SSH · Severidade: CRÍTICA',    time:'há 4min' },
  { icon:'📧', title:'Alerta Enviado — Slack #soc',   detail:'PowerShell Base64 em 10.0.0.55',           time:'há 11min' },
  { icon:'🔍', title:'Varredura de Reputação',        detail:'185.220.101.45 verificado · VirusTotal',   time:'há 14min' },
];

const QUICK_PROMPTS = [
  { icon:'🔴', label:'Brute force crítico ou FP?',  q:'Esse alerta é crítico ou falso positivo? Failed password for root from 185.220.101.45 port 22 — 47 tentativas em 3 minutos.' },
  { icon:'💻', label:'Decodificar PowerShell B64',   q:'Explica o que esse comando PowerShell faz e qual o risco: powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==' },
  { icon:'📁', label:'Directory traversal — real?',  q:'Analisa esse log nginx e diz se é Directory Traversal real: 192.168.1.99 - - [21/Apr/2025] GET /../../../etc/passwd HTTP/1.1 400' },
  { icon:'📋', label:'Gerar playbook SSH BF',         q:'Gera um playbook de resposta a incidente para brute force SSH confirmado no servidor 10.0.0.5, IP atacante 185.220.101.45' },
  { icon:'🗺️', label:'MITRE: .git exposto',           q:'Qual técnica MITRE ATT&CK mapeia acesso ao /.git/config exposto? Riscos e próximos passos.' },
];

const RECENT_ALERTS_DATA = [
  { sev:'critical', title:'Brute Force SSH',            meta:'185.220.101.45 · T1110 · há 4min',  q:'Analisa esse alerta: Brute Force SSH · 47 tentativas · IP 185.220.101.45 · Porta 22 · Usuário root' },
  { sev:'critical', title:'PowerShell Encoded',         meta:'WIN-SRV01 · T1059 · há 11min',       q:'Analisa esse alerta: PowerShell com encoding Base64 · Host WIN-SRV01 · PID 4821 · argumento: -enc JABjAGw...' },
  { sev:'high',     title:'Dir. Traversal /etc/passwd', meta:'103.21.244.0 · T1006 · há 19min',    q:'Analisa esse log nginx: 103.21.244.0 GET /../../../etc/passwd HTTP/1.1 400' },
  { sev:'medium',   title:'.git/config exposto',        meta:'45.33.32.156 · T1595 · há 32min',    q:'Analisa: Acesso ao /.git/config · IP 45.33.32.156 · Status 200 · servidor api.empresa.com' },
];

const MITRE_TACTICS = ['RECON','INIT','EXEC','PERSIST','PRIVESC','LATERAL','EXFIL'];
const MITRE_ROWS = [
  ['T1595','T1078','T1059','T1053','T1068','T1021','T1041'],
  ['T1593','T1133','T1203','T1547','T1055','T1072','T1048'],
  ['T1590','T1190','T1106','T1543','T1134','T1570','T1567'],
  ['',     '',     'T1059','T1037','T1548','',     ''     ],
];
const MITRE_HITS = { 'T1595':'hit-c','T1110':'hit-c','T1059':'hit-c','T1006':'hit-h','T1190':'hit-h','T1046':'hit-m','T1078':'hit-m','T1041':'hit-h' };

// ── VIEWS ─────────────────────────────────────

function switchView(name, btn) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  btn.classList.add('active');
}

// ── CLOCK ─────────────────────────────────────

function tick() {
  const t = new Date().toLocaleTimeString('pt-BR');
  document.getElementById('clock').textContent = t;
}
tick();
setInterval(tick, 1000);

// ── KPI COUNTER ANIMATION ─────────────────────

function animateCounters() {
  document.querySelectorAll('.kpi-value[data-target]').forEach(el => {
    const target = parseInt(el.dataset.target);
    let cur = 0;
    const step = Math.max(1, Math.floor(target / 30));
    const iv = setInterval(() => {
      cur = Math.min(cur + step, target);
      el.textContent = cur;
      if (cur >= target) clearInterval(iv);
    }, 30);
  });
}

// ── ALERT FEED ────────────────────────────────

function buildAlertItem(a) {
  const div = document.createElement('div');
  div.className = 'alert-item';
  div.dataset.sev = a.sev;
  div.innerHTML = `
    <div class="alert-bar ${a.sev}"></div>
    <div class="alert-info">
      <div class="alert-title">${esc(a.title)}</div>
      <div class="alert-meta">
        <span class="ip">${esc(a.ip)}</span>
        <span class="mitre">${esc(a.mitre)}</span>
        <span>${esc(a.src.toUpperCase())}</span>
      </div>
    </div>
    <div class="alert-right">
      <div class="alert-time">−${esc(a.ago)}</div>
      <span class="sev-pill ${a.sev}">${a.sev}</span>
    </div>`;
  div.onclick = () => {
    div.style.background = 'var(--paper2)';
    setTimeout(() => div.style.background = '', 600);
  };
  return div;
}

function renderFeed(containerId, items) {
  const el = document.getElementById(containerId);
  el.innerHTML = '';
  items.forEach(a => el.appendChild(buildAlertItem(a)));
}

// Alert filter (alerts view)
let currentFilter = 'all';
function filterAlerts(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const filtered = f === 'all' ? ALERTS_DATA : ALERTS_DATA.filter(a => a.sev === f);
  renderFeed('alertsFeedFull', filtered);
}

// Live inject every 9s
const INJECT_POOL = [
  { sev:'critical', title:'Novo Brute Force Detectado',   ip:'5.188.206.26',  mitre:'T1110', src:'ssh',   ago:'0min' },
  { sev:'high',     title:'LFI /proc/self/environ',       ip:'185.234.218.5', mitre:'T1006', src:'nginx', ago:'0min' },
  { sev:'medium',   title:'Acesso incomum /admin panel',  ip:'67.205.132.10', mitre:'T1190', src:'nginx', ago:'0min' },
];
let injectIdx = 0;
setInterval(() => {
  const fresh = { ...INJECT_POOL[injectIdx++ % INJECT_POOL.length], ago: '0min' };
  ALERTS_DATA.unshift(fresh);
  if (ALERTS_DATA.length > 14) ALERTS_DATA.pop();
  renderFeed('alertsFeed', ALERTS_DATA);
  // bump kpi
  const el = document.querySelector('#kpi-threats .kpi-value');
  if (el && !el.dataset.target) el.textContent = parseInt(el.textContent) + 1;
  // live EPS jitter
  const v = 260 + Math.floor(Math.random() * 70);
  document.getElementById('liveEps').textContent = v;
  document.getElementById('epsBar').textContent = v;
}, 9000);

// ── IP TABLE ──────────────────────────────────

function renderIPs() {
  const tbody = document.getElementById('ipTable');
  tbody.innerHTML = '';
  IPS_DATA.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="ip-mono">${esc(r.ip)}</span></td>
      <td>${r.country}</td>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--amber)">${r.attacks}</td>
      <td>
        <div class="score-wrap">
          <div class="score-track"><div class="score-fill" style="width:${r.score}%"></div></div>
          <span class="score-num">${r.score}</span>
        </div>
      </td>`;
    tr.style.cursor = 'pointer';
    tbody.appendChild(tr);
  });
}

// ── MITRE GRID ────────────────────────────────

function renderMitre() {
  const grid = document.getElementById('mitreGrid');
  grid.innerHTML = '';

  // header
  const head = document.createElement('div');
  head.className = 'mitre-tactics';
  MITRE_TACTICS.forEach(t => {
    const h = document.createElement('div');
    h.className = 'mitre-tactic-head';
    h.textContent = t;
    head.appendChild(h);
  });
  grid.appendChild(head);

  // rows
  MITRE_ROWS.forEach(row => {
    const rowEl = document.createElement('div');
    rowEl.className = 'mitre-row';
    row.forEach(tech => {
      const cell = document.createElement('div');
      cell.className = 'mitre-cell' + (tech ? '' : ' empty');
      if (tech) {
        cell.textContent = tech;
        if (MITRE_HITS[tech]) cell.classList.add(MITRE_HITS[tech]);
        cell.title = tech;
        cell.onclick = () => {
          switchView('copilot', document.querySelector('[data-view="copilot"]'));
          document.getElementById('userInput').value = `Explica a técnica MITRE ${tech} e como detectar ela em logs.`;
          document.getElementById('userInput').focus();
        };
      }
      rowEl.appendChild(cell);
    });
    grid.appendChild(rowEl);
  });

  // legend
  const leg = document.createElement('div');
  leg.className = 'mitre-legend';
  leg.innerHTML = `
    <span><span class="lg-dot" style="background:var(--red)"></span> Crítico</span>
    <span><span class="lg-dot" style="background:var(--amber)"></span> Alto</span>
    <span><span class="lg-dot" style="background:var(--blue)"></span> Médio</span>
    <span><span class="lg-dot" style="background:var(--wire2)"></span> Sem hit</span>`;
  grid.appendChild(leg);
}

// ── SOAR LIST ─────────────────────────────────

function renderSoar() {
  const list = document.getElementById('soarList');
  list.innerHTML = '';
  SOAR_DATA.forEach(s => {
    const el = document.createElement('div');
    el.className = 'soar-item';
    el.innerHTML = `
      <div class="soar-icon">${s.icon}</div>
      <div class="soar-text">
        <div class="soar-title">${esc(s.title)}</div>
        <div class="soar-detail">${esc(s.detail)}</div>
      </div>
      <div class="soar-meta">
        <div class="soar-time">${esc(s.time)}</div>
        <div class="soar-ok"></div>
      </div>`;
    list.appendChild(el);
  });
}

// ── TIMELINE CHART ────────────────────────────

function renderChart() {
  const now = new Date();
  const labels = Array.from({length:13}, (_,i) => {
    const h = new Date(now); h.setHours(h.getHours() - 12 + i);
    return h.getHours().toString().padStart(2,'0') + ':00';
  });
  const critical = [2,3,1,5,8,4,2,6,9,7,3,11,7];
  const medium   = [8,6,9,12,7,10,5,8,14,6,9,12,8];
  const low      = [15,12,18,10,16,13,20,11,17,14,19,16,12];

  const ctx = document.getElementById('timelineChart').getContext('2d');
  new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label:'Crítico', data:critical, borderColor:'#c0392b', backgroundColor:'rgba(192,57,43,.1)',  borderWidth:2, pointRadius:3, pointHoverRadius:5, fill:true, tension:.4 },
        { label:'Médio',   data:medium,   borderColor:'#b45309', backgroundColor:'rgba(180,83,9,.07)',  borderWidth:1.5, pointRadius:2, fill:true, tension:.4 },
        { label:'Baixo',   data:low,      borderColor:'#1e40af', backgroundColor:'rgba(30,64,175,.05)', borderWidth:1, pointRadius:2, fill:true, tension:.4 },
      ]
    },
    options: {
      responsive:true,
      maintainAspectRatio:false,
      interaction:{ mode:'index', intersect:false },
      plugins:{
        legend:{
          labels:{
            color:'#7a7a72',
            font:{ family:"'IBM Plex Mono', monospace", size:10 },
            boxWidth:12, boxHeight:2, padding:16
          }
        },
        tooltip:{
          backgroundColor:'#ffffff',
          borderColor:'#cac6ba',
          borderWidth:1,
          titleColor:'#1a1a18',
          bodyColor:'#3d3d38',
          titleFont:{ family:"'IBM Plex Mono', monospace", size:11 },
          bodyFont:{ family:"'DM Sans', sans-serif", size:12 },
          padding:10
        }
      },
      scales:{
        x:{
          grid:{ color:'rgba(202,198,186,.4)' },
          ticks:{ color:'#7a7a72', font:{ family:"'IBM Plex Mono', monospace", size:9 } }
        },
        y:{
          grid:{ color:'rgba(202,198,186,.4)' },
          ticks:{ color:'#7a7a72', font:{ family:"'IBM Plex Mono', monospace", size:9 } }
        }
      }
    }
  });
}

// ── COPILOT ───────────────────────────────────

// SYSTEM_PROMPT mantido para referência local (não é enviado ao backend)
const SYSTEM_PROMPT = `Você é um analista SOC Tier 3 experiente. Ajuda outros analistas a investigar alertas e responder incidentes.

Regras:
- Seja direto e prático. Sem enrolação.
- Comece sempre com veredito: CRÍTICO, ALTO, MÉDIO ou FALSO POSITIVO.
- Use termos técnicos reais (MITRE, CVE, IOC, TTPs).
- Para comandos suspeitos, explica linha a linha.
- Para playbooks, usa lista numerada de ações concretas.
- Responda em português brasileiro.
- Seja como colega experiente — direto, preciso, sem frescura.
- Menciona a técnica MITRE quando relevante.
- Máximo 400 tokens. Denso e útil, não prolixo.`;

let chatCtx = null;
let chatBusy = false;
let msgCounter = 0;

function setCtx(type, el) {
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  if (chatCtx === type) { chatCtx = null; document.getElementById('chipActive').style.display = 'none'; return; }
  chatCtx = type;
  el.classList.add('active');
  const labels = { log:'Log', alert:'Alerta', cmd:'Comando', ip:'IP/IOC', play:'Playbook' };
  document.getElementById('chipActiveText').textContent = labels[type];
  document.getElementById('chipActive').style.display = 'flex';
}

function clearCtx() {
  chatCtx = null;
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  document.getElementById('chipActive').style.display = 'none';
}

function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 150) + 'px';
}

function handleKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function nowTime() {
  return new Date().toLocaleTimeString('pt-BR', { hour:'2-digit', minute:'2-digit' });
}

function esc(t) {
  return String(t)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function addUserMsg(text) {
  document.getElementById('emptyState')?.remove();
  const wrap = document.createElement('div');
  wrap.className = 'msg-user';
  wrap.innerHTML = `<div class="bubble">${esc(text).replace(/\n/g,'<br>')}</div><div class="ts">${nowTime()}</div>`;
  document.getElementById('messages').appendChild(wrap);
  scrollChat();
  msgCounter++;
  document.getElementById('msgCount').textContent = msgCounter + (msgCounter === 1 ? ' mensagem' : ' mensagens');
}

function addTyping() {
  const wrap = document.createElement('div');
  wrap.className = 'msg-ai'; wrap.id = 'typing-indicator';
  wrap.innerHTML = `
    <div class="msg-ai-head">
      <div class="ai-glyph">◈</div>
      <span class="ai-label">SOC Copilot</span>
      <span class="ai-ts">analisando...</span>
    </div>
    <div class="typing-bub">
      <div class="td"></div><div class="td"></div><div class="td"></div>
    </div>`;
  document.getElementById('messages').appendChild(wrap);
  scrollChat();
}

function removeTyping() {
  document.getElementById('typing-indicator')?.remove();
}

function renderReply(text) {
  // verdict
  let vHtml = '';
  const vMap = [
    [/\b(CRÍTICO|CRITICAL)\b/i, 'critical', '🔴'],
    [/\b(ALTO|HIGH)\b/i,         'high',     '🟠'],
    [/\b(FALSO POSITIVO|FALSE POSITIVE|FP)\b/i, 'safe', '🟢'],
    [/\b(MÉDIO|MEDIUM)\b/i,      'info',     '🔵'],
  ];
  for (const [re, cls, ico] of vMap) {
    if (re.test(text)) { vHtml = `<div class="verdict ${cls}">${ico} ${text.match(re)[0].toUpperCase()}</div>`; break; }
  }

  // markdown-ish
  let html = esc(text)
    .replace(/```([^`]+)```/gs, '<div class="code-block">$1</div>')
    .replace(/`([^`]+)`/g, '<code style="font-family:\'IBM Plex Mono\',monospace;font-size:11.5px;background:var(--paper2);padding:1px 5px;border-radius:2px">$1</code>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^(\d+)\. (.+)$/gm, (_,n,t) => `<div class="step-item"><div class="step-num">${n}</div><div>${t}</div></div>`)
    .replace(/\n\n/g,'<br><br>').replace(/\n/g,'<br>');

  return vHtml + html;
}

function addAIMsg(text) {
  const wrap = document.createElement('div');
  wrap.className = 'msg-ai';
  wrap.innerHTML = `
    <div class="msg-ai-head">
      <div class="ai-glyph">◈</div>
      <span class="ai-label">SOC Copilot</span>
      <span class="ai-ts">${nowTime()}</span>
    </div>
    <div class="bubble">${renderReply(text)}</div>`;
  document.getElementById('messages').appendChild(wrap);
  scrollChat();
  msgCounter++;
  document.getElementById('msgCount').textContent = msgCounter + (msgCounter === 1 ? ' mensagem' : ' mensagens');
}

function scrollChat() {
  const m = document.getElementById('messages');
  m.scrollTop = m.scrollHeight;
}

// ── BACKEND HELPER ────────────────────────────

function buildBackendAnswer(data) {
  const risk = data?.risk_analysis || {};
  const ai = data?.ai_analysis || 'Sem resposta da IA.';

  return [
    `Veredito: ${risk.risk_level || 'N/A'}`,
    '',
    `Classificação: ${risk.classification || 'N/A'}`,
    '',
    `Score: ${risk.score ?? 'N/A'}`,
    '',
    `Motivos:`,
    ...(risk.reasons || []).map(r => `- ${r}`),
    '',
    `Análise:`,
    ai
  ].join('\n');
}

// ── SEND MESSAGE ──────────────────────────────

async function sendMessage() {
  if (chatBusy) return;

  const input = document.getElementById("userInput");
  const text = input.value.trim();

  if (!text) return;

  chatBusy = true;

  addUserMsg(text);
  input.value = "";
  autoResize(input);

  addTyping();

  try {
    const response = await fetch(`${API_URL}/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        title: chatCtx ? `Copilot ${chatCtx}` : "Copilot Input",
        description: text,
        source: "dashboard",
        severity: "medium",
        raw_log: text,
        event_type: chatCtx || "copilot"
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    console.log("API RESPONSE:", data);

    removeTyping();

    let finalAnswer;
    try {
      finalAnswer = buildBackendAnswer(data);
    } catch (e) {
      console.error("Erro ao montar resposta:", e);
      finalAnswer = JSON.stringify(data, null, 2);
    }

    addAIMsg(finalAnswer);

  } catch (error) {
    console.error("Erro completo:", error);
    removeTyping();
    addAIMsg("⚠️ Erro ao conectar com a API local. Verifique se o FastAPI está rodando em http://127.0.0.1:8000");
  } finally {
    chatBusy = false;
  }
}

function buildBackendAnswer(data) {
  const risk = data?.risk_analysis || {};
  const ai = data?.ai_analysis || "Sem resposta da IA.";

  const reasons = Array.isArray(risk.reasons) ? risk.reasons : [];

  return [
    `Veredito: ${risk.risk_level || "N/A"}`,
    "",
    `Classificação: ${risk.classification || "N/A"}`,
    "",
    `Score: ${risk.score ?? "N/A"}`,
    "",
    `Motivos:`,
    ...reasons.map(r => `- ${r}`),
    "",
    `Análise:`,
    ai
  ].join("\n");
}

function addMessage(type, text) {
  const messages = document.getElementById("messages");

  const wrapper = document.createElement("div");
  wrapper.className = type === "user" ? "msg-user" : "msg-ai";

  if (type === "user") {
    wrapper.innerHTML = `
      <div class="bubble">${esc(text)}</div>
      <div class="timestamp">${new Date().toLocaleTimeString("pt-BR", {
        hour: "2-digit",
        minute: "2-digit"
      })}</div>
    `;
  } else {
    wrapper.innerHTML = `
      <div class="msg-ai-header">
        <div class="ai-avatar">◈</div>
        <div>
          <div class="ai-name">SOC Copilot</div>
          <div class="ai-model">FastAPI Backend</div>
        </div>
      </div>
      <div class="bubble">${formatCopilotText(text)}</div>
    `;
  }

  messages.appendChild(wrapper);
  messages.scrollTop = messages.scrollHeight;

  const msgCount = document.getElementById("msgCount");
  if (msgCount) {
    const total = messages.querySelectorAll(".msg-user, .msg-ai").length;
    msgCount.textContent = `${total} mensagens`;
  }
}

// ── COPILOT SIDEBAR ───────────────────────────

function renderPromptList() {
  const list = document.getElementById('promptList');
  list.innerHTML = '';
  QUICK_PROMPTS.forEach(p => {
    const btn = document.createElement('button');
    btn.className = 'prompt-btn';
    btn.innerHTML = `<span class="pi">${p.icon}</span>${esc(p.label)}`;
    btn.onclick = () => quickPrompt(p.q);
    list.appendChild(btn);
  });
}

function renderRecentAlerts() {
  const el = document.getElementById('recentAlerts');
  el.innerHTML = '';
  RECENT_ALERTS_DATA.forEach(a => {
    const div = document.createElement('div');
    div.className = 'recent-alert';
    const barColor = a.sev === 'critical' ? 'var(--red)' : a.sev === 'high' ? 'var(--amber)' : 'var(--blue)';
    div.innerHTML = `
      <div class="ra-bar" style="background:${barColor}"></div>
      <div>
        <div class="ra-title">${esc(a.title)}</div>
        <div class="ra-meta">${esc(a.meta)}</div>
      </div>`;
    div.onclick = () => {
      document.getElementById('userInput').value = a.q;
      autoResize(document.getElementById('userInput'));
      document.getElementById('userInput').focus();
    };
    el.appendChild(div);
  });
}

// ── INIT ──────────────────────────────────────

window.addEventListener('DOMContentLoaded', () => {
  animateCounters();
  renderChart();
  renderFeed('alertsFeed', ALERTS_DATA);
  renderFeed('alertsFeedFull', ALERTS_DATA);
  renderIPs();
  renderMitre();
  renderSoar();
  renderPromptList();
  renderRecentAlerts();
});