/* NetHub 前端逻辑。
   后端调用约定（Wails 运行时自动生成的 bindings）：
     window.go.webui.Backend.<Method>(...)
   Go 侧返回值末尾带 error 的方法，Promise 会 reject —— 统一在 call() 里兜住。 */

'use strict';

const B = () => window.go.webui.Backend;   // 每次取，避免绑定还没注入时抓到 undefined
const R = () => window.runtime;

let state = { theme: 'light' };
let chains = [];
let chainHealth = {};   // 链名 → 上游健康快照
let routes = [];
let conns = [];
let lastPrecheck = [];   // 最近一次体检报告（诊断页那张卡渲染用）
let autoScrollLog = true;

/* ═══════════════ 基础工具 ═══════════════ */

async function call(fn, ...args) {
  const b = B();
  if (!b) throw new Error('后端绑定还没就绪');
  return await b[fn](...args);
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function toast(title, text, kind = 'info') {
  const host = document.getElementById('toasts');
  const t = el('div', 'toast ' + kind);
  t.appendChild(el('h4', null, title));
  if (text) t.appendChild(el('p', null, text));
  host.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .2s'; }, 4200);
  setTimeout(() => t.remove(), 4500);
}

function fail(e) {
  const msg = (e && e.message) ? e.message : String(e);
  toast('操作失败', msg, 'error');
  return msg;
}

/* ═══════════════ 模态框 ═══════════════ */

const modal = {
  ok: null,
  open(title, bodyNodes, onOk, okText) {
    document.getElementById('modalTitle').textContent = title;
    const body = document.getElementById('modalBody');
    body.replaceChildren(...bodyNodes);
    document.getElementById('modalErr').textContent = '';
    document.getElementById('modalOk').textContent = okText || '确定';
    // 回执类模态框会把「取消」藏起来，这里恢复默认显示，否则它会一直缺着
    document.getElementById('modalCancel').style.display = '';
    document.getElementById('modalBackdrop').classList.add('is-open');
    this.onOk = onOk;
    setTimeout(() => {
      const f = body.querySelector('input, textarea, select');
      if (f) { f.focus(); if (f.select) try { f.select(); } catch (_) {} }
    }, 60);
    return body;
  },
  close() {
    document.getElementById('modalBackdrop').classList.remove('is-open');
    document.getElementById('modalBody').replaceChildren();
    this.onOk = null;
  },
  error(msg) { document.getElementById('modalErr').textContent = msg; }
};

function confirmBox(title, text, danger, okText) {
  return new Promise(res => {
    const p = el('p', null, text);
    p.style.color = 'var(--body)';
    // okText 可自定义按钮文案；不传就按 danger 给默认值（danger 只是样式，不该抢文案）
    modal.open(title, [p], () => { modal.close(); res(true); }, okText || (danger ? '删除' : '确定'));
    const cancel = () => { modal.close(); res(false); };
    document.getElementById('modalCancel').onclick = cancel;
    document.getElementById('modalX').onclick = cancel;
  });
}

/* ═══════════════ 主题 ═══════════════ */

function applyTheme(mode) {
  state.theme = mode === 'dark' ? 'dark' : 'light';
  document.documentElement.dataset.theme = state.theme;
  document.getElementById('btnTheme').textContent = state.theme === 'dark' ? '浅色模式' : '深色模式';
}

async function toggleTheme() {
  const next = state.theme === 'dark' ? 'light' : 'dark';
  applyTheme(next);                       // 先本地切，界面立刻响应
  try { await call('SetTheme', next); } catch (e) { fail(e); }
}

/* ═══════════════ 标签页 ═══════════════ */

function showPage(name) {
  // 选项卡 + 顶部栏里的「设置」（它不在 tab 组里，但用的是同一套切换）
  document.querySelectorAll('.tab, .tab-top').forEach(t =>
    t.classList.toggle('is-active', t.dataset.page === name));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('is-active', p.id === 'page-' + name));
  if (name === 'log') scrollLogToEnd();
  if (name === 'conn') loadConns();
  if (name === 'diag') { precheckConfig(true); loadTargetHealth(); loadPatrol(); }
}

/* ═══════════════ 规则智能：最具体优先 / 命中查询 ═══════════════ */

async function sortRoutes() {
  try {
    await call('SortRoutes');
    await loadRoutes();
    toast('已整理规则顺序', '越具体（/32、带端口）的排在越前面', 'success');
  } catch (e) { fail(e); }
}

async function explainTarget() {
  const raw = (document.getElementById('explainIp').value || '').trim();
  if (!raw) { toast('先填一批目标', '每行一个，例如 10.0.0.5:5432 或 172.16.0.0/24', 'warn'); return; }

  // 先按和后台一致的规则切一遍，决定是“详细解释”还是“批量表”
  const tokens = raw.split(/[\n,，;；\t ]+/).map(s => {
    const i = s.indexOf('#');
    return (i >= 0 ? s.slice(0, i) : s).trim();
  }).filter(Boolean);

  if (tokens.length === 1) { return explainOne(tokens[0]); }

  let v;
  try { v = await call('SimulateTargets', raw); }
  catch (e) { fail(e); return; }

  const head = el('div', 'sim-summary');
  head.textContent = v.summary;
  const box = el('div', 'sim-box');
  box.appendChild(head);

  const tbl = el('div', 'table');
  const th = el('div', 'trow thead sim-grid');
  ['目标', '会怎么走', '命中的规则'].forEach(h => th.appendChild(el('div', 'cell', h)));
  tbl.appendChild(th);
  (v.rows || []).forEach(r => {
    const row = el('div', 'trow sim-grid');
    row.appendChild(el('div', 'cell mono', r.input || ''));
    const c2 = el('div', 'cell');
    const badge = el('span', 'sim-badge ' + actionClass(r));
    badge.textContent = !r.ok ? '无法解析' : (r.action || '未命中');
    c2.appendChild(badge);
    row.appendChild(c2);
    row.appendChild(el('div', 'cell dim', !r.ok ? (r.err || '')
      : ((r.ruleNo ? '第 ' + r.ruleNo + ' 条 ' : '') + (r.rule || '—') +
        (r.chain ? ' → ' + r.chain : '') + (r.note ? '　（' + r.note + '）' : ''))));
    tbl.appendChild(row);
  });
  box.appendChild(tbl);
  modal.open('批量模拟结果', [box], null);
}

// 单个目标：沿用原来的详细解释（含链健康、目标巡检、被抢先的规则）
async function explainOne(raw) {
  const i = raw.lastIndexOf(':');
  const ip = i > 0 ? raw.slice(0, i) : raw;
  const port = i > 0 ? raw.slice(i + 1) : '';
  let v;
  try { v = await call('ExplainTarget', ip, port); }
  catch (e) { toast('查不了', (e && e.message) || String(e), 'error'); return; }

  const lines = [];
  if (!v.matched) {
    lines.push('不拦截（直连）', '');
    lines.push('没有任何规则命中这个目标，所以它不经过我们 —— 按系统原本的路由走。');
  } else {
    lines.push('命中第 ' + (v.ruleIndex + 1) + ' 条规则' + (v.ruleName ? '「' + v.ruleName + '」' : ''));
    lines.push('动作：' + v.action);
    if (v.chain && v.action.indexOf('链') === 0) lines.push('链：' + v.chain);
    if (v.chainHealth) {
      lines.push('');
      lines.push('该链上游（策略 ' + v.chainHealth.strategy + '，探测 ' + v.chainHealth.probe + '）：');
      v.chainHealth.upstreams.forEach(u => {
        lines.push('  ' + (u.known ? (u.ok ? '● 可用' : '● 不可用') : '○ 待探测') + '  ' +
          u.url + (u.latency ? '  ' + u.latency : '') + (u.error ? '  ' + u.error : ''));
      });
    }
    if (v.targetHealth) {
      lines.push('');
      lines.push('目标上次巡检：' + (v.targetHealth.ok ? '可达 ' + v.targetHealth.latency : '不可达：' + v.targetHealth.error) +
        '（' + v.targetHealth.checked + '）');
    }
  }
  if (v.portIgnored) {
    lines.push('');
    lines.push('（未填端口 —— 这次只看目标，带端口条件的规则可能没算进来）');
  }
  if (v.shadowed && v.shadowed.length) {
    lines.push('');
    lines.push('被抢先、永远不会生效的规则：');
    v.shadowed.forEach(s => lines.push('  第 ' + (s.index + 1) + ' 条' + (s.name ? '「' + s.name + '」' : '') + ' → ' + s.action));
  }
  const pre = el('pre', 'explain-out mono');
  pre.textContent = lines.join('\n');
  modal.open('这个目标怎么走 —— ' + v.input, [pre], null);
}

function actionClass(r) {
  if (!r.ok) return 'bad';
  if (r.action && r.action.indexOf('隧道') >= 0) return 'tunnel';
  if (r.action && r.action.indexOf('阻断') >= 0) return 'bad';
  if (r.action && r.action.indexOf('直连') >= 0) return 'direct';
  return 'none';
}

/* ═══════════════ headless 模式（Windows 服务） ═══════════════ */

async function loadService() {
  const top = document.getElementById('svcInfo');
  const row = document.getElementById('svcStateRow');
  if (!top || !row) return;
  let v = null;
  try { v = await call('GetService'); } catch (e) { return; }
  if (!v) return;

  const map = { running: '运行中', stopped: '已停止', starting: '启动中', stopping: '停止中', 'not installed': '未安装', unknown: '未知' };
  top.textContent = '服务状态：' + (map[v.state] || v.state) +
    (v.elevated ? '' : '（非管理员，装/卸会失败）');

  // 最底下那行：装没装一眼能看出来
  row.replaceChildren();
  if (!v.known) {
    row.appendChild(el('span', 'hint', '? 查不到服务状态（需要管理员权限才能问服务管理器）'));
    return;
  }
  if (v.installed) {
    row.appendChild(el('span', 'svc-ok', '✓ 服务已安装'));
    row.appendChild(el('span', 'hint', '　当前' + (map[v.state] || v.state)));
    if (v.state !== 'running') {
      row.appendChild(el('span', 'hint', '　—— 点「启动」让它跑起来（跑起来才有拦截）'));
    }
  } else {
    row.appendChild(el('span', 'svc-bad', '✗ 服务未安装'));
    row.appendChild(el('span', 'hint', '　—— 需要开机即启（不等登录）就点「安装服务」'));
  }
}

/* ═══════════════ 巡检设置 ═══════════════ */

/* 巡检的开关与间隔（用户自己定） */
async function loadPatrol() {
  const on = document.getElementById('patrolOn');
  const iv = document.getElementById('patrolInterval');
  const info = document.getElementById('patrolInfo');
  if (!on || !iv) return;
  let v = null;
  try { v = await call('GetPatrol'); } catch (e) { return; }
  if (!v) return;
  on.checked = !!v.enabled;
  iv.value = v.enabled ? v.interval : '';
  if (info) {
    info.textContent = v.enabled
      ? '每轮最多探 ' + v.count + ' 个目标（只探用过的）'
      : '已关闭自动巡检（仍可手动「立即巡检」）';
  }
}

async function savePatrol() {
  const on = document.getElementById('patrolOn');
  const iv = document.getElementById('patrolInterval');
  try {
    await call('SetPatrol', on.checked, iv.value);
    await loadPatrol();
    toast(on.checked ? '已启用自动巡检' : '已关闭自动巡检',
      on.checked ? '间隔 ' + iv.value : '需要时点「立即巡检」', 'success');
  } catch (e) { fail(e); }
}

/* ═══════════════ 配置体检 / 备份 / 诊断包 ═══════════════ */

async function precheckConfig(quiet) {
  const out = document.getElementById('precheckOut');
  if (!out) return;
  out.textContent = '正在体检…';
  let lines = [];
  try { lines = await call('PrecheckConfig'); }
  catch (e) { out.textContent = '体检失败：' + ((e && e.message) || e); return; }
  const rep = lines || [];
  lastPrecheck = rep;
  out.textContent = rep.join('\n');
  // 进页面自动跑的那次不弹提示（报告就在眼前）；手动点只报“有错”
  const bad = rep.filter(l => l.trim().startsWith('✗')).length;
  if (!quiet && bad) {
    toast('体检发现问题', bad + ' 项错误，见上方报告', 'error');
  }
}

async function exportDiagnostics() {
  try {
    const p = await call('ExportDiagnostics');
    if (p) toast('已导出诊断包', p + '　　凭据已抹掉，可直接发出去', 'success');
  } catch (e) { fail(e); }
}

async function loadBackups() {
  const box = document.getElementById('backupList');
  if (!box) return;
  let list = [];
  try { list = await call('ListBackups'); } catch (e) { return; }
  box.replaceChildren();
  if (!list || !list.length) {
    box.appendChild(el('div', null, '还没有备份。每次保存配置都会自动备一份。'));
    return;
  }
  box.appendChild(el('div', null, '最近 ' + list.length + ' 份备份（恢复前会先把当前配置也备一份）：'));
  const row = el('div', 'input-row');
  list.slice(0, 8).forEach(name => {
    row.appendChild(btn(name.replace(/^config-|\.yaml$/g, ''), 'btn btn-xs', async () => {
      if (!await confirmBox('回滚配置', '用备份 ' + name + ' 覆盖当前配置并重启服务？', true)) return;
      try {
        await call('RestoreBackup', name);
        await loadSettings(); await loadChains(); await loadRoutes(); await loadBackups();
        toast('已回滚', name, 'success');
      } catch (e) { fail(e); }
    }));
  });
  box.appendChild(row);
}

/* ═══════════════ 业务目标巡检 ═══════════════ */

async function loadTargetHealth() {
  let list = [];
  try { list = await call('GetTargetHealth'); } catch (e) { return; }
  const t = document.getElementById('targetTable');
  if (!t) return;
  t.replaceChildren();
  const head = el('div', 'trow thead target-grid');
  ['目标', '链', '状态', '延迟', '检查时间'].forEach(h => head.appendChild(el('div', 'cell', h)));
  t.appendChild(head);
  if (!list || !list.length) {
    t.appendChild(el('div', 'empty', '还没有可以巡检的目标 —— 等有内网连接之后（或点「立即巡检」）。'));
    return;
  }
  list.forEach(x => {
    const row = el('div', 'trow target-grid');
    row.appendChild(el('div', 'cell mono', x.target));
    row.appendChild(el('div', 'cell dim', x.chain));
    row.appendChild(el("div", "cell " + (x.ok ? "strong" : "svc-bad"), x.ok ? "可达" : "不可达"));
    row.appendChild(el('div', 'cell mono', x.ok ? x.latency : '—'));
    const c = el('div', 'cell dim', x.checked);
    if (x.error) c.title = x.error;
    row.appendChild(c);
    t.appendChild(row);
  });
}

/* ═══════════════ 连接列表 ═══════════════ */

/* 字节数的人类可读写法（与后端 humanBytes 对齐）。 */
function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return n.toFixed(1) + ' ' + units[i];
}

async function loadConns() {
  let d = null;
  try { d = await call('GetConns'); }
  catch (e) { return; }   // 轮询失败静默：别每 1.5 秒弹一次错
  conns = (d && d.list) || [];

  document.getElementById('badgeConn').textContent = (d && d.active) || 0;
  const per = d && d.perChain
    ? Object.keys(d.perChain).map(k => k + ' ' + d.perChain[k]).join('　')
    : '';
  document.getElementById('connSummary').textContent =
    '累计 ' + ((d && d.total) || 0) + '　活跃 ' + ((d && d.active) || 0) + (per ? '　　' + per : '');

  const t = document.getElementById('connTable');
  t.replaceChildren();
  const head = el('div', 'trow thead conn-grid');
  ['#', '目标', '动作', '链', '时长', '↑ 发送', '↓ 接收', '状态'].forEach(h =>
    head.appendChild(el('div', 'cell', h)));
  t.appendChild(head);

  if (!conns.length) {
    t.appendChild(el('div', 'empty', '还没有连接。命中规则的连接会实时出现在这里。'));
    return;
  }

  conns.forEach((c, i) => {
    const row = el('div', 'trow conn-grid');
    row.appendChild(el('div', 'cell dim', String(i + 1)));
    row.appendChild(el('div', 'cell mono', c.target || ''));
    row.appendChild(el('div', 'cell' + (c.action === '阻断' ? ' dim' : ''), c.action || ''));
    row.appendChild(el('div', 'cell dim', c.chain || '—'));
    row.appendChild(el('div', 'cell dim', c.dur || ''));

    const up = el('div', 'cell mono', '↑ ' + fmtBytes(c.up));
    const down = el('div', 'cell mono', '↓ ' + fmtBytes(c.down));
    if (c.action === '直连') {
      up.title = '直连的流量只统计出方向（回来的包不经内核过滤器）';
      down.title = '直连不统计入方向';
    }
    row.appendChild(up);
    row.appendChild(down);

    const st = el('div', 'cell' + (c.state === '进行中' ? ' strong' : ' dim'), c.state || '');
    if (c.error) st.title = c.error;
    row.appendChild(st);
    t.appendChild(row);
  });
}

/* ═══════════════ 状态刷新 ═══════════════ */

async function refreshState() {
  let s;
  try { s = await call('GetState'); } catch (e) {
    // 不再静默 return —— 之前这里 catch 到底，绑定一坏就永久停在“未启动”，
    // 完全看不出出事了。只提示一次，避免每 1.5 秒刷屏。
    if (!refreshState._warned) {
      refreshState._warned = true;
      console.error('GetState 失败', e);
      toast('状态获取失败', String((e && e.message) || e), 'error');
    }
    return;
  }
  refreshState._warned = false;
  state = Object.assign(state, s);

  const on = !!s.running;
  const bad = !on && !!(s.error);
  const rs = document.getElementById('runState');
  rs.classList.toggle('is-on', on);
  rs.classList.toggle('is-bad', bad);
  // 三态：Ready（绿，呼吸）/ Error（红，呼吸）/ 已停止（灰，静止）
  document.getElementById('runStateText').textContent = on ? 'Ready' : (bad ? 'Error' : '已停止');
  // 出错原因平时不占位置，悬停能看；内部中转端口同样只在悬停里出现
  rs.title = bad
    ? s.error
    : ('内部中转端口 ' + (s.relay || '—') + '（实现细节，无需配置）');
  document.getElementById('btnToggle').textContent = on ? '停止服务' : '启动服务';
  document.getElementById('btnToggle').className = on ? 'btn' : 'btn btn-primary';

  document.getElementById('stTotal').textContent = s.totalConns;
  document.getElementById('stActive').textContent = s.activeConns;

  document.getElementById('pathConfig').textContent = s.configPath || '-';
  document.getElementById('pathLog').textContent = s.logPath || '-';
  document.getElementById('hostsInfo').textContent =
    (s.hostsInFile ? '标记区块已存在' : '未写入标记区块') + ' · ' + (s.hostsPath || '');

  // 主题以后端为准（只在变化时同步，避免打断用户刚点的切换）
  if (s.theme && s.theme !== state.theme) applyTheme(s.theme);

  // 开机自启：状态由系统决定，回写勾选框
  const cbAuto = document.getElementById('setAutostart');
  if (!cbAuto.dataset.busy) {
    cbAuto.checked = !!s.autostart;
  }
  document.getElementById('autoInfo').textContent =
    (s.autostart ? '已启用' : '未启用') + (s.autoDetail || '');
}

/* ═══════════════ 日志 ═══════════════ */

const MAXLOG = 1500;

function logNode(l) {
  const row = el('div', 'logline lv-' + (l.level || 'info').toLowerCase());
  row.appendChild(el('span', 't', l.time));
  row.appendChild(el('span', 'lv', l.level));
  row.appendChild(el('span', 'tx', l.text));
  return row;
}

function pushLog(l) {
  const box = document.getElementById('logBox');
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.appendChild(logNode(l));
  while (box.childElementCount > MAXLOG) box.removeChild(box.firstChild);
  if (nearBottom) scrollLogToEnd();
}

function scrollLogToEnd() {
  const box = document.getElementById('logBox');
  box.scrollTop = box.scrollHeight;
}

async function loadLogs() {
  const box = document.getElementById('logBox');
  box.replaceChildren();
  let list = [];
  try { list = await call('GetLogs'); } catch (_) {}
  list.forEach(l => box.appendChild(logNode(l)));
  scrollLogToEnd();
}

/* ═══════════════ 链路表 ═══════════════ */

async function loadChains() {
  try { chains = await call('GetChains'); } catch (e) { return fail(e); }
  await loadChainHealth();
  document.getElementById('badgeChain').textContent = chains.length;

  // 预热连接池近况（A11）：养着几条、命中过多少次
  const wi = document.getElementById('warmInfo');
  if (wi) {
    try {
      const st = await call('GetState');
      wi.textContent = st.poolWarm > 0
        ? ('预热会话：养着 ' + st.poolWarm + ' 条 · 已命中 ' + (st.poolHits || 0) + ' 次')
        : '';
    } catch (e) { /* 拿不到就不显示 */ }
  }

  const t = document.getElementById('chainTable');
  t.replaceChildren();

  const head = el('div', 'trow thead chain-grid');
  ['链名', '上游（凭据已遮蔽）', '健康', '说明', ''].forEach(h =>
    head.appendChild(el('div', 'cell', h)));
  t.appendChild(head);

  if (!chains.length) {
    const e = el('div', 'empty', '还没有链路。点「添加链路」或「从 .bat 批量导入」。');
    t.appendChild(e);
    return;
  }

  chains.forEach((c, i) => {
    const row = el('div', 'trow chain-grid');
    row.appendChild(el('div', 'cell strong', c.name));

    const ups = c.forwards && c.forwards.length ? c.forwards : [c.forward || ''];
    const upCell = el('div', 'cell mono', ups[0] +
      (ups.length > 1 ? '  +' + (ups.length - 1) + ' 个' : ''));
    if (ups.length > 1) upCell.title = ups.join('\n');
    else upCell.title = ups[0];
    row.appendChild(upCell);

    row.appendChild(healthCell(chainHealth[c.name]));
    row.appendChild(el('div', 'cell dim', c.note || ''));

    const acts = el('div', 'cell actions');
    acts.appendChild(btn('编辑', 'btn btn-xs', () => chainForm(i)));
    acts.appendChild(btn('↑', 'btn btn-xs', () => moveChain(i, -1)));
    acts.appendChild(btn('↓', 'btn btn-xs', () => moveChain(i, 1)));
    acts.appendChild(btn('删除', 'btn btn-xs btn-danger', () => delChain(c.name)));
    row.appendChild(acts);
    t.appendChild(row);
  });
}

/* 每条上游一个小圆点：绿=可用、红=不可用、灰=还没探过；悬停看细节。 */
async function loadChainHealth() {
  try {
    const hs = await call('GetChainHealth');
    chainHealth = {};
    (hs || []).forEach(h => { chainHealth[h.name] = h; });
  } catch (e) { /* 探测信息拿不到不影响主流程 */ }
}

function healthCell(h) {
  const c = el('div', 'cell');
  if (!h || !h.upstreams || !h.upstreams.length) {
    c.textContent = '—';
    return c;
  }
  let ok = 0;
  h.upstreams.forEach(u => {
    const dot = el('span', 'dot ' + (u.known ? (u.ok ? 'ok' : 'bad') : ''));
    dot.title = u.url + (u.latency ? '　' + u.latency : '') + (u.error ? '　' + u.error : '');
    c.appendChild(dot);
    if (u.known && u.ok) ok++;
  });
  const summary = h.upstreams.length > 1
    ? ok + '/' + h.upstreams.length
    : (h.upstreams[0].latency || (h.upstreams[0].known ? '不通' : '待探测'));
  c.appendChild(el('span', 'dim', summary));
  c.title = '策略 ' + h.strategy + '　探测间隔 ' + h.probe;
  return c;
}

function btn(text, cls, fn) {
  const b = el('button', cls, text);
  b.onclick = fn;
  return b;
}

/* 链路编辑表单 —— 也用于"从 bat 导入后回填" */
function chainForm(index, preset) {
  const isNew = index == null;
  const src = preset || (isNew
    ? { name: '', forwards: [''], strategy: 'failover', probe: '30s', note: '' }
    : chains[index]);

  const name = input('text', src.name, '例如 proxy-a（规则里用这个名字引用它）');
  const ups = (src.forwards && src.forwards.length) ? src.forwards : [src.forward || ''];
  const forwards = textarea(ups.join('\n'),
    '一行一个上游。填多个就是故障转移/负载转移：\nsocks5+tls://host-a:10080?auth=…\nsocks5+tls://host-b:10080?auth=…', 3);
  forwards.classList.add('mono');

  const strategy = el('select', 'input');
  [['failover', '故障转移（按顺序试，第一个能用的就用）'],
   ['round', '轮询（均摊到多条上游）'],
   ['random', '随机'],
   ['hash', '粘性（同一台客户端固定走同一条上游）']].forEach(([v, label]) => {
    const o = el('option', null, label);
    o.value = v;
    strategy.appendChild(o);
  });
  strategy.value = src.strategy || 'failover';

  const probe = input('text', src.probe || '30s', '健康探测间隔：30s / 1m / off（关）');
  const note = input('text', src.note, '随便写（显示在链路的说明列）');

  const importBtn = btn('从 gost .bat 导入…', 'btn btn-sm', async () => {
    try {
      const r = await call('PickBatFile');
      if (!r) return;                      // 用户取消
      forwards.value = r.forward;          // 只取 -F：上游能力已内置，-L 不再需要
      if (!name.value) name.value = r.name;
      toast('已读取 ' + r.file, r.forward, 'success');
    } catch (e) { modal.error(fail(e)); }
  });

  const warn = el('p', 'hint', '凭据会明文保存在 config.yaml，别外传。');
  const nodes = [
    field('链名', name),
    field('上游', forwards, '支持 socks5 / socks5+tls / socks4 / http / https；旧 gost 脚本可直接导入'),
    field('', importBtn),
    field('策略', strategy, '多条上游时怎么挑：故障转移（默认）/ 轮询 / 随机'),
    field('健康探测', probe, '定时只探到代理这一段（不碰业务目标）；探到不通的会先排到最后'),
    field('备注', note), field('', warn),
  ];

  modal.open(isNew ? '添加链路' : '编辑链路', nodes, async () => {
    try {
      const payload = {
        name: name.value,
        forwards: splitTargets(forwards.value),
        strategy: strategy.value,
        probe: probe.value,
        note: note.value,
      };
      if (isNew) await call('AddChain', payload);
      else await call('UpdateChain', src.name, payload);
      modal.close();
      await loadChains();
      toast(isNew ? '已添加链路' : '已更新链路',
        payload.name + '（' + payload.forwards.length + ' 条上游）', 'success');
    } catch (e) { modal.error(fail(e)); }
  });
}

function input(type, value, placeholder) {
  const i = el('input', 'input');
  i.type = type;
  i.value = value || '';
  if (placeholder) i.placeholder = placeholder;
  i.spellcheck = false;
  return i;
}

function textarea(value, placeholder, rows) {
  const t = el('textarea', 'input textarea');
  t.value = value || '';
  t.rows = rows || 5;
  t.spellcheck = false;
  if (placeholder) t.placeholder = placeholder;
  return t;
}

/* 批量操作的统一回执：新增/跳过分列，跳过的原因必须写出来 ——
   否则用户以为全加上了，规则却不生效。 */
function showBatchResult(title, verb, added, skipped) {
  modal.open(title,
    [el('p', null, verb + ' ' + added.length + ' 条，跳过 ' + skipped.length + ' 条'),
     ...added.map(s => el('div', 'hint', '✓ ' + s)),
     ...skipped.map(s => el('div', 'hint', '· ' + s))],
    () => modal.close(), '知道了');
  document.getElementById('modalCancel').style.display = 'none';
}

function field(label, node, hint) {
  const f = el('div', 'field');
  if (label) f.appendChild(el('label', null, label));
  f.appendChild(node);
  if (hint) f.appendChild(el('span', 'hint', hint));
  return f;
}

async function moveChain(i, d) {
  const to = i + d;
  if (to < 0 || to >= chains.length) return;
  try { await call('MoveChain', i, to); await loadChains(); } catch (e) { fail(e); }
}

async function delChain(name) {
  if (!await confirmBox('删除链路', '确定删除链 ' + name + ' 吗？', true)) return;
  try { await call('DeleteChain', name); await loadChains(); toast('已删除链路', name, 'success'); }
  catch (e) { fail(e); }
}

async function importBats() {
  try {
    const r = await call('ImportBatDir');
    if (!r) return;
    await loadChains();
    const added = r.added || [], skipped = r.skipped || [];
    showBatchResult('导入结果', '新增/更新', added, skipped);
  } catch (e) { fail(e); }
}

/* ═══════════════ 规则表 ═══════════════ */

async function loadRoutes() {
  try { routes = await call('GetRoutes'); } catch (e) { return fail(e); }
  document.getElementById('badgeRule').textContent = routes.length;

  const t = document.getElementById('ruleTable');
  t.replaceChildren();

  const head = el('div', 'trow thead rule-grid');
  ['#', '规则名', '目标 IP / CIDR', '走哪条链 / 直连', '说明（该链备注）', ''].forEach(h =>
    head.appendChild(el('div', 'cell', h)));
  t.appendChild(head);

  if (!routes.length) {
    t.appendChild(el('div', 'empty', '还没有规则。点「添加规则」把内网网段指到某条链；本机网段 / 局域网邻居选「直连」。'));
    return;
  }

  routes.forEach(r => {
    const row = el('div', 'trow rule-grid');
    const idxCell = el('div', 'cell');
    idxCell.appendChild(el('span', 'idx', String(r.index + 1)));
    row.appendChild(idxCell);
    row.appendChild(el('div', 'cell' + (r.name ? ' strong' : ' dim'), r.name || '（未命名）'));
    row.appendChild(targetsCell(r.targets || [], r.ports || [], r.shadowed || []));
    row.appendChild(el('div', 'cell' + (r.direct || r.block ? ' dim' : ''), actionLabel(r)));
    row.appendChild(el('div', 'cell dim', r.note || ''));

    const acts = el('div', 'cell actions');
    acts.appendChild(btn('编辑', 'btn btn-xs', () => ruleForm(r.index)));
    acts.appendChild(btn('↑', 'btn btn-xs', () => moveRoute(r.index, -1)));
    acts.appendChild(btn('↓', 'btn btn-xs', () => moveRoute(r.index, 1)));
    acts.appendChild(btn('删除', 'btn btn-xs btn-danger', () => delRoute(r.index)));
    row.appendChild(acts);
    t.appendChild(row);
  });
}

/* 目标列：一条规则可以挂十几个目标，列表里只给摘要，全量放 title，悬停能看全。
   带端口条件时在末尾追一个暗淡的“· 端口 …”标签。 */
function targetsCell(list, ports, shadowed) {
  const cap = 3;
  const c = el('div', 'cell mono');
  c.textContent = list.slice(0, cap).join(' ') +
    (list.length > cap ? '  +' + (list.length - cap) + ' 个' : '');
  ports = ports || [];
  if (ports.length) c.appendChild(el('span', 'dim', '  · 端口 ' + ports.join(',')));
  shadowed = shadowed || [];
  if (shadowed.length) {
    const warn = el('span', 'shadow-warn', '  ⚠ ' + shadowed.length + ' 个目标被前面的规则覆盖');
    warn.title = '这些目标永远轮不到（自上而下、命中即停）：\n' + shadowed.join('\n');
    c.appendChild(warn);
  }
  if (list.length > 1 || ports.length || shadowed.length) {
    c.title = list.join('\n') + (ports.length ? '\n端口 ' + ports.join(',') : '');
  }
  return c;
}

/* 规则动作的显示名：direct / block 是保留动作（不是链名）。 */
function actionLabel(r) {
  if (r.direct) return '直连（不走代理）';
  if (r.block) return '阻断';
  return r.chain;
}

/* 下拉里选中的值 → 提示语里用的短名。 */
function actionName(v) {
  if (v === 'direct') return '直连';
  if (v === 'block') return '阻断';
  return v;
}

function ruleForm(index) {
  const isNew = index == null;
  const src = isNew
    ? { name: '', targets: [], ports: [], chain: chains[0] ? chains[0].name : '' }
    : routes.find(r => r.index === index);
  if (!chains.length) { toast('无法添加规则', '请先到「隧道链路」页添加一条链', 'warn'); return; }

  const name = input('text', src.name, '例如 内网 A 段（可留空）');
  const targets = textarea((src.targets || []).join('\n'),
    '每行一个，也可用逗号/顿号/空格分隔：\n10.0.1.0/24\n10.0.0.0/24, 192.168.100.0/24', 5);
  // 本地直连最容易忘：一键把本机网段填进来（局域网邻居/打印机/共享盘用得上）
  const targetsBox = el('div', 'input-row top');
  targetsBox.appendChild(targets);
  targetsBox.appendChild(btn('填本机网段', 'btn btn-xs', async () => {
    try {
      const subs = await call('LocalSubnets');
      if (!subs || !subs.length) { toast('没读到本机网段', '接口上没有 IPv4 地址', 'warn'); return; }
      const cur = splitTargets(targets.value);
      const add = subs.filter(s => !cur.includes(s));
      if (!add.length) { toast('已经在里面了', subs.join(' '), 'info'); return; }
      targets.value = cur.concat(add).join('\n');
    } catch (e) { fail(e); }
  }));
  const sel = el('select', 'input');
  // 「直连」是保留动作（后端保留链名 direct）：命中后不改包、不进隧道。
  const oDirect = el('option', null, '直连（不走代理）');
  oDirect.value = 'direct';
  sel.appendChild(oDirect);
  const oBlock = el('option', null, '阻断（丢弃）');
  oBlock.value = 'block';
  sel.appendChild(oBlock);
  chains.forEach(c => {
    const o = el('option', null, c.name + '   —   ' + (c.forward || ''));
    o.value = c.name;
    sel.appendChild(o);
  });
  sel.value = src.chain || chains[0].name;

  const ports = input('text', (src.ports || []).join(', '), '留空 = 全部端口；也可 443, 8000-9000');

  const nodes = [
    field('规则名', name, '给这条规则起个名字（可留空）'),
    field('目标', targetsBox,
      '单个 IP 会自动存成 /32；填多个目标就是同一条规则 —— 命中其中任意一个都走下面这个动作'),
    field('端口', ports,
      '留空 = 任意端口。填了就要求「目标命中 且 端口命中」；' +
      '想排除某个端口（比如 Windows 更新的 7680），把它写成前面一条「直连」规则、端口只填那个端口'),
    field('动作', sel,
      '「直连」= 不改写、不进隧道（本机网段、打印机、共享盘、同事机器用这个）；' +
      '「阻断」= 直接丢弃；规则自上而下匹配，命中即停'),
  ];

  modal.open(isNew ? '添加规则' : '编辑规则', nodes, async () => {
    try {
      if (isNew) await call('AddRoute', name.value, targets.value, sel.value, ports.value);
      else await call('UpdateRoute', index, name.value, targets.value, sel.value, ports.value);
      modal.close();
      await loadRoutes();
      toast(isNew ? '已添加规则' : '已更新规则',
        (name.value.trim() || '未命名') + '：' + splitTargets(targets.value).length + ' 个目标' +
        (splitTargets(ports.value).length ? '，端口 ' + ports.value.trim() : '') + ' → ' +
        actionName(sel.value),
        'success');
    } catch (e) { modal.error(fail(e)); }
  });
}

/* 只为在提示语里数一下目标个数（真正的拆分与归一化在后端做）。 */
function splitTargets(raw) {
  return String(raw || '').split(/[\s,，;；、]+/).filter(Boolean);
}

async function moveRoute(i, d) {
  const to = i + d;
  if (to < 0 || to >= routes.length) return;
  try { await call('MoveRoute', i, to); await loadRoutes(); } catch (e) { fail(e); }
}

async function delRoute(i) {
  const r = routes.find(x => x.index === i);
  const ts = r.targets || [];
  const desc = r.name ? '「' + r.name + '」' : (ts.length > 1 ? ts.length + ' 个目标' : ts[0]);
  if (!await confirmBox('删除规则',
      '确定删除规则 ' + desc + '（' + ts.length + ' 个目标' +
      ((r.ports && r.ports.length) ? '，端口 ' + r.ports.join(',') : '') + ' → ' +
      actionName(r.block ? 'block' : r.direct ? 'direct' : r.chain) + '）吗？', true)) return;
  try { await call('DeleteRoute', i); await loadRoutes(); toast('已删除规则', desc, 'success'); }
  catch (e) { fail(e); }
}

/* ═══════════════ Clash 共存检测 ═══════════════ */


function renderClash(v) {
  const st = document.getElementById('clashState');
  const good = v.allCorrect && v.publicOk;
  st.textContent = (v.headline ? v.headline + '\n' : '') + (v.verdict || '');
  st.className = 'clash-state ' + (good ? 'is-ok' : (v.needFix ? 'is-error' : 'is-warn'));

  const det = document.getElementById('clashDetail');
  det.replaceChildren();

  const modeName = { none: '未开启系统代理', system: '普通系统代理', pac: 'PAC（自动配置脚本）' }[v.mode] || v.mode;
  const meta = el('div', 'hint');
  meta.textContent = '系统代理：' + modeName + (v.server ? '　' + v.server : '');
  det.appendChild(meta);

  if (v.hosts && v.hosts.length) {
    const t = el('div', 'clash-table');
    ['内网目标', '数据走向', '判定'].forEach(h => t.appendChild(el('div', null, h)));
    v.hosts.forEach(it => {
      const good2 = it.correct && it.reachable;
      t.appendChild(el('div', 'mono', it.host));
      t.appendChild(el('div', it.correct ? null : 'clash-no',
        it.correct ? '直连（我们的隧道）' : '交给 Clash（代理节点）'));
      let txt;
      if (it.correct && it.reachable) txt = '✓ 正确（实测可达 ' + it.kind + '）';
      else if (it.correct && !it.reachable) txt = '✗ 走向对但隧道不通';
      else if (it.reachable) txt = '✗ 错误：内网被代理了';
      else txt = '✗ 错误：内网被代理了，且到不了' + (it.altPath && it.altOk ? '（直连是通的）' : '');
      t.appendChild(el('div', good2 ? 'clash-ok' : 'clash-no', txt));
    });
    det.appendChild(t);
  }

  if (v.coverage && v.coverage.checked && v.coverage.checked.length) {
    const hit = v.coverage.checked.length - ((v.coverage.missed || []).length);
    const c = el('div', 'hint');
    c.textContent = '绕过覆盖：' + hit + '/' + v.coverage.checked.length + ' 命中（含内网网段代表 IP）';
    if (v.coverage.missed && v.coverage.missed.length) {
      c.textContent += '　✗ 未覆盖：' + v.coverage.missed.join(';');
      c.className = 'hint clash-no';
    }
    det.appendChild(c);
  }

  if (v.mode !== 'none') {
    const pub = el('div', 'hint');
    pub.textContent = v.publicOk
      ? '公网（走 Clash）：通（' + v.publicKind + '）'
      : '公网（走 Clash）：不通　' + (v.publicErr || '');
    det.appendChild(pub);
  }

  const wrap = document.getElementById('clashFixWrap');
  wrap.hidden = !v.needFix;
  if (v.needFix) document.getElementById('clashBypass').value = v.bypassList || '';
}

async function clashCheck() {
  const st = document.getElementById('clashState');
  st.className = 'clash-state';
  st.textContent = '检测中…（每个内网目标会实跑它实际会走的那条路，约 10 秒）';
  try {
    renderClash(await call('ClashCheck'));
  } catch (e) {
    st.className = 'clash-state is-error';
    st.textContent = '检测失败：' + ((e && e.message) || String(e));
  }
}

async function copyBypass() {
  const inp = document.getElementById('clashBypass');
  const text = inp.value;
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch (_) {
    // WebView2 里 clipboard API 可能要权限，回退到选中+execCommand
    inp.removeAttribute('readonly');
    inp.select();
    try { ok = document.execCommand('copy'); } catch (__) { ok = false; }
    inp.setAttribute('readonly', '');
  }
  toast(ok ? '已复制' : '复制失败', ok ? '粘贴到 Clash Verge 的「绕过地址」' : '请手动选中复制', ok ? 'success' : 'warn');
}

/* ═══════════════ 设置 ═══════════════ */

async function loadSettings() {
  let s;
  try { s = await call('GetSettings'); } catch (e) { return fail(e); }
  // 只用界面上确实存在的字段（别再引用已被移除的 setRelay，
  // 那会抛 TypeError 把 boot() 整个搞挂，导致状态轮询都注册不上）
  setChecked('setHostsManage', s.hostsManage);
  setValue('setHostsEntries', (s.hostsEntries || []).join('\n'));
  setValue('setDialTimeout', s.dialTimeout || 5);
  setValue('setDialBudget', s.dialBudget || 10);
  setValue('setRaceAfter', s.raceAfter === 0 ? 0 : (s.raceAfter || 150));
  const dh = document.getElementById('dialHint');
  if (dh) {
    dh.textContent = '默认 5s / 10s / 150ms。上游半死时，业务等待时间约等于「单次超时」；'
      + '现网上游握手实测 0.1～0.8s，5s 余量足够。'
      + '「竞速起跑」= 第一条超过这个时间还没连上就并发试其他上游、取先到的（填 0 关闭）；'
      + '实测某条链的 CONNECT 要 620ms、另一条只要 75ms，竞速能直接把业务拉到快链路。改完点「保存并重启」生效。';
  }
}

// 安全地取元素：元素不存在时返回 null 而不是报错，
// 避免某个面板改版后把整页初始化连带打挂。
function setChecked(id, v) {
  const e = document.getElementById(id);
  if (e) e.checked = !!v;
}
function setValue(id, v) {
  const e = document.getElementById(id);
  if (e) e.value = v;
}
// 数字输入框取值（空/非法 → def）
function intVal(id, def) {
  const e = document.getElementById(id);
  const n = e ? parseInt(e.value, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : def;
}

async function saveSettings(restart) {
  const elEntries = document.getElementById('setHostsEntries');
  const elManage = document.getElementById('setHostsManage');
  const payload = {
    hostsManage: !!(elManage && elManage.checked),
    hostsEntries: elEntries ? elEntries.value.split('\n').map(s => s.trim()).filter(Boolean) : [],
    theme: state.theme,
    dialTimeout: intVal('setDialTimeout', 5),
    dialBudget: intVal('setDialBudget', 10),
    // 竞速起跑允许 0（= 关闭），所以单独处理
    raceAfter: (function () {
      const e = document.getElementById('setRaceAfter');
      const n = e ? parseInt(e.value, 10) : NaN;
      return Number.isFinite(n) && n >= 0 ? n : 150;
    })(),
  };
  try {
    await call('SaveSettings', payload);
    toast('设置已保存', restart ? '正在重启服务…' : 'hosts 托管 / relay 的改动需要重启才生效', 'success');
    if (restart) { await call('Restart'); await refreshState(); }
  } catch (e) { fail(e); }
}

/* ═══════════════ 启动 ═══════════════ */

function wire() {
  // 窗口按钮
  document.getElementById('winMin').onclick = () => R().WindowMinimise();
  document.getElementById('winMax').onclick = () => R().WindowToggleMaximise();
  document.getElementById('winClose').onclick = () => call('HideToTray').catch(() => R().WindowHide());

  // 标签
  document.querySelectorAll('.tab').forEach(t => t.onclick = () => showPage(t.dataset.page));
  document.getElementById('btnSettings').onclick = () => showPage('settings');

  // 主操作
  document.getElementById('btnToggle').onclick = async () => {
    const rs = document.getElementById('runState');
    rs.classList.add('is-busy');
    try { state.running ? await call('Stop') : await call('Start'); }
    catch (e) { toast('操作失败', (e && e.message) || String(e), 'error'); }
    finally { rs.classList.remove('is-busy'); refreshState(); }
  };
  document.getElementById('btnRestart').onclick = async () => {
    try { await call('Restart'); toast('已重启', '拦截与隧道已重新建立', 'success'); }
    catch (e) { toast('重启失败', (e && e.message) || String(e), 'error'); }
    refreshState();
  };
  document.getElementById('btnTheme').onclick = toggleTheme;

  // 日志页
  document.getElementById('btnClearLog').onclick = () => {
    document.getElementById('logBox').replaceChildren();
  };
  document.getElementById('btnOpenLog').onclick = () => call('OpenLogDir').catch(fail);
  document.getElementById('btnSelfTest').onclick = () => {
    const out = document.getElementById('selfTestOut');
    if (out) { out.textContent = '正在自检…（逐条链探真实内网主机）'; out.dataset.started = ''; }
    pushLog({ time: now(), level: 'INFO', text: '开始链路自检…' });
    call('SelfTest').catch(fail);
  };

  // 连接页
  document.getElementById('btnConnRefresh').onclick = () => loadConns();

  // 规则页
  document.getElementById('btnRuleSort').onclick = sortRoutes;
  document.getElementById('btnExplain').onclick = explainTarget;
  document.getElementById('explainIp').onkeydown = e => {
    // Ctrl/⌘+Enter 触发（普通 Enter 要能换行，因为现在是多行输入）
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) explainTarget();
  };

  // 诊断页：巡检设置
  document.getElementById('btnPatrolSave').onclick = savePatrol;

  // 设置页：体检 / 诊断包 / Windows 服务
  document.getElementById('btnPrecheck').onclick = () => precheckConfig(false);
  document.getElementById('btnDiag').onclick = exportDiagnostics;
  document.getElementById('btnSvcInstall').onclick = async () => {
    if (!await confirmBox('安装为 Windows 服务',
        '装成服务后会随开机自动启动（无人登录也跑，无界面）。确定吗？', false, '安装')) return;
    try {
      await call('InstallService');
      toast('已安装服务', '点「启动」让它跑起来', 'success');
    } catch (e) { fail(e); }
    await loadService();
  };
  document.getElementById('btnSvcStart').onclick = async () => {
    try { await call('StartService'); toast('服务已启动', '无界面运行中（日志在程序目录）', 'success'); }
    catch (e) { fail(e); }
    await loadService();
  };
  document.getElementById('btnSvcStop').onclick = async () => {
    try { await call('StopService'); toast('服务已停止', '', 'success'); }
    catch (e) { fail(e); }
    await loadService();
  };
  document.getElementById('btnSvcUninstall').onclick = async () => {
    if (!await confirmBox('卸载服务', '停止并删除 Windows 服务 NetHub？', true, '卸载')) return;
    try { await call('UninstallService'); toast('已卸载服务', '', 'success'); }
    catch (e) { fail(e); }
    await loadService();
  };

  // 连接页：业务目标巡检
  document.getElementById('btnProbeTargets').onclick = async () => {
    try { await call('ProbeTargetsNow'); toast('正在巡检业务目标', '经隧道连一次、不发数据', 'info'); }
    catch (e) { fail(e); }
    setTimeout(loadTargetHealth, 3000);
  };

  // 链路页
  document.getElementById('btnChainAdd').onclick = () => chainForm(null);
  document.getElementById('btnChainProbe').onclick = async () => {
    try { await call('ProbeChains'); toast('正在探测上游', '只测到代理这一段，不碰业务目标', 'info'); }
    catch (e) { fail(e); }
    setTimeout(loadChains, 1500);
  };
  document.getElementById('btnChainImport').onclick = importBats;

  // 规则页
  document.getElementById('btnRuleAdd').onclick = () => ruleForm(null);

  // 设置页
  document.getElementById('btnSaveSettings').onclick = () => saveSettings(false);
  document.getElementById('btnSaveRestart').onclick = () => saveSettings(true);
  document.getElementById('btnOpenConfig').onclick = () => call('OpenConfigFile').catch(fail);
  document.getElementById('btnOpenDir').onclick = () => call('OpenProgramDir').catch(fail);
  document.getElementById('btnExportPkg').onclick = async () => {
    try {
      const r = await call('ExportPackage');
      if (!r || !r.path) return; // 用户取消
      const box = el('div');
      const tip = el('div', r.warning ? 'export-warn' : 'hint');
      tip.textContent = r.warning ? ('⚠ ' + r.warning) : '解压后在客户机器上双击「启动NetHub.cmd」（会弹 UAC，必须点「是」）。';
      box.appendChild(tip);
      const ul = el('ul', 'export-list');
      (r.files || []).forEach(f => { const li = el('li', 'mono'); li.textContent = f; ul.appendChild(li); });
      box.appendChild(ul);
      const warn = el('div', 'hint');
      warn.textContent = '含明文上游凭据 —— 别往群里/邮件列表发；传输后可用 SHA256SUMS.txt 校验。';
      box.appendChild(warn);
      modal.open('装机包已导出：' + r.path, [box], null);
    } catch (e) { fail(e); }
  };
  document.getElementById('btnExportCfg').onclick = async () => {
    try {
      const p = await call('ExportConfig');
      if (p) toast('已导出配置', p + '　（含上游凭据，请通过安全渠道分发）', 'success');
    } catch (e) { fail(e); }
  };
  document.getElementById('btnExportDoc').onclick = async () => {
    try {
      const p = await call('ExportSummary');
      if (p) toast('已导出配置说明', p + '　（不含凭据，可安全发送）', 'success');
    } catch (e) { fail(e); }
  };

  document.getElementById('btnHostsApply').onclick = async () => {
    const entries = document.getElementById('setHostsEntries').value.split('\n').map(s => s.trim()).filter(Boolean);
    try {
      await call('ApplyHosts', entries);
      toast('hosts 已更新', entries.length + ' 条内网域名映射已写入', 'success');
      refreshState();
    } catch (e) { fail(e); }
  };
  document.getElementById('btnHostsRemove').onclick = async () => {
    try { await call('RemoveHosts'); toast('已移除', 'hosts 里的标记区块已删除', 'success'); refreshState(); }
    catch (e) { fail(e); }
  };

  // Clash 共存检测
  document.getElementById('btnClashCheck').onclick = () => clashCheck();
  document.getElementById('btnCopyBypass').onclick = () => copyBypass();

  // 开机自启：一变就生效
  const cbAuto = document.getElementById('setAutostart');
  cbAuto.onchange = async () => {
    cbAuto.dataset.busy = '1';
    try {
      await call('SetAutostart', cbAuto.checked);
      toast(cbAuto.checked ? '已设置开机自启' : '已取消开机自启',
            cbAuto.checked ? '下次登录后延迟 20 秒静默启动，不弹 UAC' : '', 'success');
    } catch (e) {
      cbAuto.checked = !cbAuto.checked;    // 回滚
      fail(e);
    } finally {
      delete cbAuto.dataset.busy;
      refreshState();
    }
  };

  // 模态框
  document.getElementById('modalOk').onclick = () => { if (modal.onOk) modal.onOk(); };
  document.getElementById('modalCancel').onclick = () => modal.close();
  document.getElementById('modalX').onclick = () => modal.close();

  // Esc 关模态框
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && document.getElementById('modalBackdrop').classList.contains('is-open')) modal.close();
  });

  // 事件订阅
  R().EventsOn('log', l => pushLog(l));
  R().EventsOn('notify', n => toast(n.title, n.text, n.kind === 'error' ? 'error' : n.kind === 'warn' ? 'warn' : 'success'));
  R().EventsOn('selftest', p => {
    const text = p.ok ? ('自检通过：' + p.target + ':' + p.port) : ('自检失败：' + p.target + ' ' + (p.err || ''));
    pushLog({ time: now(), level: p.ok ? 'INFO' : 'ERROR', text });
    appendSelfTest(text);
  });
}

/* 自检结果追加到诊断页的输出框（同时也写运行日志）。 */
function appendSelfTest(text) {
  const out = document.getElementById('selfTestOut');
  if (!out) return;
  const line = now() + '  ' + text;
  out.textContent = out.dataset.started ? (out.textContent + '\n' + line) : line;
  out.dataset.started = '1';
}

function now() {
  const d = new Date();
  const p = (n, l = 2) => String(n).padStart(l, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()) + '.' + p(d.getMilliseconds(), 3);
}

async function boot() {
  // 等 bindings 注入
  for (let i = 0; i < 60 && !B(); i++) await new Promise(r => setTimeout(r, 50));
  if (!B()) { toast('启动异常', '后端绑定未注入', 'error'); return; }

  wire();
  applyTheme('light');

  // 状态轮询【先注册】：任何面板加载失败都不能让状态栏冻在启动前的快照上。
  setInterval(refreshState, 1500);
  // 连接列表只看当前页：不在这一页就不拉，省得白跑
  setInterval(() => {
    const p = document.getElementById('page-conn');
    if (p && p.classList.contains('is-active')) loadConns();
  }, 1500);
  // 链路页的上游健康：只在这一页时刷新
  setInterval(() => {
    const p = document.getElementById('page-chain');
    if (p && p.classList.contains('is-active')) loadChains();
  }, 5000);

  await refreshState();
  applyTheme(state.theme);

  // 各面板独立加载：一个坏了不影响其他，而且要把错误显性报出来
  const panels = await Promise.allSettled([loadLogs(), loadChains(), loadRoutes(), loadSettings()]);
  await loadBackups();
  await loadService();
  const bad = panels.filter(p => p.status === 'rejected');
  if (bad.length) {
    console.error('面板加载失败', bad.map(p => p.reason));
    toast('部分面板加载失败', bad.map(p => String(p.reason)).join('；'), 'error');
  }

  refreshState();
  clashCheck();   // 进界面就跑一次共存检测（失败不影响其他）
}

window.addEventListener('DOMContentLoaded', () => boot().catch(e => toast('初始化失败', String(e), 'error')));
