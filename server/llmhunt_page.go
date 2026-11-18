package server

import (
	"net/http"
)

// llmHuntPage 是一个**自包含**的页面：不依赖前端 bundle，因此加这个功能不需要
// 重新构建 Next 产物，直接随二进制发布。
//
// 鉴权沿用站点级 HTTP Basic（浏览器会自动带上），API 也接受 JWT —— 与 SPA 一致。
func (s *Server) llmHuntPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(llmHuntHTML))
}

const llmHuntHTML = `<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>大模型资产与密钥测绘 · ARTEX</title>
<style>
 :root{--bg:#0b0d12;--panel:#141821;--line:#242a36;--fg:#e6e9f0;--mut:#8b93a5;--acc:#4c8dff;--warn:#f0b429;--bad:#ef5350;--ok:#3ddc84}
 @media (prefers-color-scheme:light){:root{--bg:#f6f7fb;--panel:#fff;--line:#e3e6ee;--fg:#1b2130;--mut:#5c6577;--acc:#1a6dff}}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
 .wrap{max-width:1180px;margin:0 auto;padding:24px 20px 60px}
 h1{font-size:20px;margin:0 0 4px} .sub{color:var(--mut);font-size:13px;margin-bottom:16px}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
 label{font-size:12px;color:var(--mut);display:block;margin-bottom:6px}
 textarea,input[type=number]{width:100%;background:transparent;color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace}
 textarea{min-height:120px;resize:vertical}
 .row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:10px}
 button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
 button.ghost{background:transparent;border:1px solid var(--line);color:var(--fg)}
 button:disabled{opacity:.5;cursor:not-allowed}
 .note{font-size:12px;color:var(--warn);margin-top:8px}
 table{width:100%;border-collapse:collapse;font-size:13px} th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
 th{color:var(--mut);font-weight:500;font-size:12px;white-space:nowrap}
 code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
 .pill{display:inline-block;padding:1px 7px;border-radius:99px;font-size:11px;border:1px solid var(--line)}
 .pill.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent)}
 .pill.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 40%,transparent)}
 .pill.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,transparent)}
 .tabs{display:flex;gap:8px;margin-bottom:12px}
 .tabs button{background:transparent;color:var(--mut);border:1px solid var(--line)}
 .tabs button.on{color:var(--fg);border-color:var(--acc)}
 .muted{color:var(--mut)} .empty{color:var(--mut);font-size:13px;padding:14px 0}
 .mask{font-family:ui-monospace,Menlo,Consolas,monospace}
 .actions{display:flex;gap:6px}
 .actions button{padding:3px 8px;font-size:12px}
 #toast{position:fixed;right:18px;bottom:18px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 14px;display:none;max-width:420px}
</style></head><body>
<div class="wrap">
 <h1>大模型资产与密钥测绘</h1>
 <div class="sub">对<b>授权范围内</b>的目标做只读探测：识别暴露的推理/编排服务、判定未授权能力、在响应里识别泄露的密钥。
 引擎写死了轻量约束：只发 GET、同一主机串行且间隔 ≥1.2 秒、每台主机最多 8 个请求、全局 4 并发、命中 403/418/429 立即放弃。</div>

 <div class="card">
  <label for="seeds">目标清单（每行一个：<code>host</code> / <code>host:端口</code> / <code>https://host</code>）</label>
  <textarea id="seeds" placeholder="llm.example.com&#10;10.0.0.5:11434&#10;https://chat.example.com"></textarea>
  <div class="row">
   <label style="margin:0"><input type="checkbox" id="fromAssets"> 从资产库扫描（已登记的授权资产）</label>
   <label style="margin:0"><input type="checkbox" id="useSearch"> 用搜索引擎发现候选</label>
   <span class="muted">最多</span><input type="number" id="max" value="100" min="1" max="2000" style="width:90px">
   <span class="muted">个目标</span>
   <button id="start">开始测绘</button>
   <button id="stop" class="ghost">停止</button>
   <span id="stat" class="muted"></span>
  </div>

  <div id="searchBox" style="display:none;margin-top:12px">
   <label for="dorks">搜索词（每行一个；留空用内置的 7 条指纹词）</label>
   <textarea id="dorks" style="min-height:88px" placeholder='"Ollama" "api/tags"&#10;intitle:"ComfyUI"&#10;"Dify" "console/api/setup"'></textarea>
   <div class="row">
    <span class="muted">搜索发现的目标最多</span>
    <input type="number" id="maxSearch" value="20" min="1" max="100" style="width:90px">
    <span class="muted">个（每个只探 1 个路径）</span>
   </div>
  </div>

  <div class="note">⚠️ 只对你确认有授权的目标使用。不做网段/端口段扫描。搜索发现的是第三方站点，因此每个目标只发 1 个只读 GET（命中才继续），并跳过 github/教程站。发现密钥只登记、不验证、不使用。</div>
 </div>

 <div class="tabs">
  <button id="tabAssets" class="on">发现的实例 <span id="nAssets" class="muted"></span></button>
  <button id="tabKeys">泄露的密钥 <span id="nKeys" class="muted"></span></button>
 </div>

 <div class="card" id="paneAssets">
  <table><thead><tr><th>URL</th><th>组件</th><th>版本</th><th>未授权</th><th>模型</th><th>判据</th><th>来源</th><th></th></tr></thead>
  <tbody id="assetsBody"><tr><td colspan="8" class="empty">还没有结果。粘贴目标后点「开始测绘」。</td></tr></tbody></table>
 </div>

 <div class="card" id="paneKeys" style="display:none">
  <table><thead><tr><th>类型</th><th>掩码</th><th>来源</th><th>发现时间</th><th></th></tr></thead>
  <tbody id="keysBody"><tr><td colspan="5" class="empty">还没有发现密钥。</td></tr></tbody></table>
  <div class="note">默认只显示掩码。点「查看原文」才会向服务端取一次明文，15 秒后自动隐藏；原文不会写日志。</div>
 </div>
</div>
<div id="toast"></div>
<script>
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let revealTimers = {};

function toast(msg, bad) {
  const t = $('toast');
  t.textContent = msg; t.style.display = 'block';
  t.style.borderColor = bad ? 'var(--bad)' : 'var(--line)';
  clearTimeout(t._h); t._h = setTimeout(() => t.style.display = 'none', 4200);
}

async function api(path, opts) {
  const r = await fetch(path, Object.assign({credentials: 'same-origin', headers: {'content-type':'application/json'}}, opts || {}));
  if (!r.ok) throw new Error((await r.text()).slice(0, 200) || ('HTTP ' + r.status));
  return r.json();
}

async function refreshStatus() {
  try {
    const s = await api('/api/llmhunt/status');
    const last = s.last;
    let txt = s.running ? '扫描中…' : (last ? ('上次：' + last.status) : '尚未扫描');
    if (last && last.total) txt += ' · ' + (last.done||0) + '/' + last.total + ' 目标 · 实例 ' + (last.assets||0) + ' · 密钥 ' + (last.keys||0);
    $('stat').textContent = txt;
    $('start').disabled = !!s.running;
    $('stop').disabled = !s.running;
    return s;
  } catch (e) { $('stat').textContent = '状态读取失败'; return null; }
}

async function refreshData() {
  try {
    const [a, k] = await Promise.all([api('/api/llmhunt/assets'), api('/api/llmhunt/keys')]);
    renderAssets(a.assets || []);
    renderKeys(k.keys || []);
  } catch (e) { /* 静默 */ }
}

function renderAssets(rows) {
  $('nAssets').textContent = rows.length ? '(' + rows.length + ')' : '';
  const body = $('assetsBody');
  if (!rows.length) { body.innerHTML = '<tr><td colspan="8" class="empty">还没有结果。</td></tr>'; return; }
  body.innerHTML = rows.map(a => '<tr>' +
    '<td class="mono">' + esc(a.url) + '</td>' +
    '<td>' + esc(a.vendor || '-') + '</td>' +
    '<td class="mono">' + esc(a.version || '-') + '</td>' +
    '<td>' + (a.unauth ? '<span class="pill warn">可未授权访问</span>' : '<span class="pill">否</span>') + '</td>' +
    '<td class="mono">' + ((a.models && a.models.length) ? esc(a.models.slice(0,3).join(', ')) + (a.models.length>3 ? ' +'+(a.models.length-3) : '') : '-') + '</td>' +
    '<td class="muted" style="max-width:240px">' + esc(a.evidence || '-') + '</td>' +
    '<td class="muted">' + esc(a.source || '-') + '</td>' +
    '<td class="actions"><button class="ghost" onclick="delAsset(' + a.id + ')">删除</button></td>' +
  '</tr>').join('');
}

function renderKeys(rows) {
  $('nKeys').textContent = rows.length ? '(' + rows.length + ')' : '';
  const body = $('keysBody');
  if (!rows.length) { body.innerHTML = '<tr><td colspan="5" class="empty">还没有发现密钥。</td></tr>'; return; }
  body.innerHTML = rows.map(k => '<tr>' +
    '<td>' + esc(k.key_type) + '</td>' +
    '<td class="mask" id="mask-' + k.id + '">' + esc(k.masked) + '</td>' +
    '<td class="mono" style="max-width:320px;word-break:break-all">' + esc(k.url) + '</td>' +
    '<td class="muted">' + esc((k.found_at||'').replace('T',' ').slice(0,19)) + '</td>' +
    '<td class="actions">' +
      '<button class="ghost" onclick="reveal(' + k.id + ')">查看原文</button>' +
      '<button class="ghost" onclick="delKey(' + k.id + ')">删除</button>' +
    '</td></tr>').join('');
}

async function reveal(id) {
  if (!confirm('这会向服务端取一次密钥明文，仅在本页显示 15 秒，请确认你已获授权。')) return;
  try {
    const r = await api('/api/llmhunt/keys/' + id + '/reveal');
    const cell = $('mask-' + id);
    if (!cell) return;
    cell.textContent = r.raw || '';
    cell.style.color = 'var(--bad)';
    clearTimeout(revealTimers[id]);
    revealTimers[id] = setTimeout(() => { cell.textContent = '已隐藏'; cell.style.color = ''; setTimeout(() => location.reload(), 1200); }, 15000);
    toast('已显示，15 秒后自动隐藏');
  } catch (e) { toast('取原文失败：' + e.message, true); }
}

async function delKey(id) {
  if (!confirm('删除这条密钥记录？')) return;
  try { await api('/api/llmhunt/keys/' + id, {method:'DELETE'}); toast('已删除'); refreshData(); }
  catch (e) { toast('删除失败：' + e.message, true); }
}
async function delAsset(id) {
  if (!confirm('删除这个实例（连带它的密钥记录）？')) return;
  try { await api('/api/llmhunt/assets/' + id, {method:'DELETE'}); toast('已删除'); refreshData(); }
  catch (e) { toast('删除失败：' + e.message, true); }
}

$('useSearch').onchange = () => { $('searchBox').style.display = $('useSearch').checked ? '' : 'none'; };

$('start').onclick = async () => {
  const seeds = $('seeds').value.trim();
  const fromAssets = $('fromAssets').checked;
  const useSearch = $('useSearch').checked;
  if (!seeds && !fromAssets && !useSearch) { toast('请粘贴目标、勾选资产库，或勾选搜索引擎发现', true); return; }
  const max = parseInt($('max').value || '100', 10);
  const maxSearch = parseInt($('maxSearch').value || '20', 10);
  const dorks = $('dorks').value;
  try {
    $('start').disabled = true;
    const r = await api('/api/llmhunt/scan', {method:'POST', body: JSON.stringify({seeds, from_assets: fromAssets, use_search: useSearch, dorks, max_from_search: maxSearch, max_targets: max})});
    toast('已开始：' + r.targets + ' 个目标');
    refreshStatus();
  } catch (e) { toast('启动失败：' + e.message, true); refreshStatus(); }
};

$('stop').onclick = async () => {
  try { await api('/api/llmhunt/stop', {method:'POST', body:'{}'}); toast('已请求停止'); refreshStatus(); }
  catch (e) { toast('停止失败：' + e.message, true); }
};

$('tabAssets').onclick = () => { $('tabAssets').classList.add('on'); $('tabKeys').classList.remove('on'); $('paneAssets').style.display=''; $('paneKeys').style.display='none'; };
$('tabKeys').onclick = () => { $('tabKeys').classList.add('on'); $('tabAssets').classList.remove('on'); $('paneKeys').style.display=''; $('paneAssets').style.display='none'; };

refreshStatus(); refreshData();
setInterval(async () => { const s = await refreshStatus(); if (s && s.running) refreshData(); }, 3000);
</script>
</body></html>`
