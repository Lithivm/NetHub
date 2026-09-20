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
  if (name === 'conn') { loadConns(); loadCountDirect(); }
  if (name === 'diag') { precheckConfig(true); loadTargetHealth(); loadPatrol(); loadLastSelfTest(); }
}

/* ═══════════════ 规则智能：最具体优先 / 命中查询 ═══════════════ */

async function sortRoutes() {
  try {
    await call('SortRoutes');
    await loadRoutes();
    toast('已整理规则顺序', '具体的排前面（/32、带端口），本机自身 / 环回类放最后', 'success');
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

/* 复制体检结果：方便贴到聊天/工单里（比让人去截图快，也比打包一个 zip 轻）。 */
async function copyPrecheck() {
  const out = document.getElementById('precheckOut');
  const txt = ((out && out.textContent) || '').trim();
  if (!txt || txt === '正在体检…') {
    toast('还没有体检结果', '点一下「重新体检」', 'info');
    return;
  }
  try {
    await navigator.clipboard.writeText(txt);
    toast('已复制体检结果', txt.split('\n').length + ' 行，直接粘给对方即可', 'success');
  } catch (e) {
    toast('复制失败', '手动选中上面的文本复制即可', 'warn');
  }
}

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
  ['#', '进程', '目标', '动作', '链', '时长', '↑ 发送', '↓ 接收', '状态'].forEach(h =>
    head.appendChild(el('div', 'cell', h)));
  t.appendChild(head);

  if (!conns.length) {
    t.appendChild(el('div', 'empty', '还没有连接。命中规则的连接会实时出现在这里。'));
    return;
  }

  conns.forEach((c, i) => {
    const row = el('div', 'trow conn-grid');
    row.appendChild(el('div', 'cell dim', String(i + 1)));
    // 进程列：谁发起的。查不到时显示“未知”——不做伪装（受保护进程/系统服务查不到）。
    const pc = el('div', 'cell', c.proc || '未知');
    pc.classList.add(c.proc ? '' : 'dim');
    if (c.proc) {
      pc.title = c.proc + (c.pid ? '  (PID ' + c.pid + ')' : '') +
        '\n点击可查完整路径';
      pc.style.cursor = 'pointer';
      pc.onclick = async () => {
        try {
          const p = await call('ProcPath', c.pid);
          toast(c.proc, p || '（拿不到完整路径，可能是受保护进程）');
        } catch (e) { toast('查进程失败', String((e && e.message) || e), 'error'); }
      };
    } else if (c.pid) {
      pc.title = 'PID ' + c.pid + '，但拿不到进程名';
    }
    row.appendChild(pc);
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

    const ups = c.forwards && c.forwards.length ? c.forwards : [c.forward || ""];
    const upCell = el('div', 'cell mono', ups[0] +
      (ups.length > 1 ? '  +' + (ups.length - 1) + ' 个' : ''));
    if (ups.length > 1) upCell.title = ups.join('\n');
    else upCell.title = ups[0];
    // 列表只回答一件事：这条链带不带凭据。地址细节（含口令）在编辑页明文看。
    if (c.auth) {
      const tag = el('span', 'cred-tag',
        '  带凭据' + (c.credUser ? '（' + c.credUser + '）' : ''));
      tag.title = '这条链的上游需要认证（地址里带账号口令，明文存在 config.yaml）。\n' +
        '要看/改真实地址：点「编辑」，里面就是完整地址。';
      upCell.appendChild(tag);
    } else {
      // 没凭据是“要你补”的状态，不能用跟“带凭据”一样的绿色（用户反馈：看着像好事）
      const tag = el('span', 'cred-tag is-missing', '  无凭据');
      tag.title = '这条链的上游不需要认证（地址里没有账号口令）';
      upCell.appendChild(tag);
    }
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
async function chainForm(index, preset) {
  const isNew = index == null;
  let src = preset || (isNew
    ? { name: '', forwards: [''], strategy: 'failover', probe: '30s', note: '' }
    : chains[index]);

  // 已有链：去后端取**真实地址**（含凭据明文）——编辑页就是拿来改凭据的，
  // 藏起来除了多造麻烦没任何意义（列表那边只标“带不带凭据”就够了）。
  if (!isNew && !preset) {
    try {
      const plain = await call('ChainForwardPlain', src.name);
      if (plain && plain.length) src = Object.assign({}, src, { forwards: plain });
    } catch (e) {
      toast('取真实上游地址失败', String((e && e.message) || e) + '　（下面显示的是简化地址，保存前请自己核对）', 'warn');
    }
  }

  const name = input('text', src.name, '例如 proxy-a（规则里用这个名字引用它）');
  const ups = (src.forwards && src.forwards.length) ? src.forwards : [src.forward || ''];
  const forwards = textarea(ups.join('\n'),
    '一行一个上游。填多个就是故障转移/负载转移：\nsocks5+tls://host-a:10080?auth=…\nsocks5+tls://host-b:10080?auth=…', 3);
  forwards.classList.add('mono');
  // 这里显示的是明文（含账号口令）—— 要让人一眼看到自己到底配的是什么
  const credNote = el('div', 'hint');
  if (src.auth) {
    credNote.className = 'export-warn';
    credNote.textContent = '⚠ 上面就是完整地址（含账号口令）。保存后也**明文**写在 config.yaml 里' +
      '（和 gost 的启动脚本一样），账号 ' + (src.credUser || '—') + '。';
  } else {
    credNote.textContent = '上游 URL 里带 user:pass@ 或 ?auth=base64(user:pass) 都可以；保存后明文写在 config.yaml 里，别外传。';
  }

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

  const warn = el('p', 'hint', '口令是明文存在 config.yaml 里（和 gost 脚本一样）—— 别提交进 git、别发群里。');
  const nodes = [
    field('链名', name),
    field('上游', forwards, '支持 socks5 / socks5+tls / socks4 / http / https；旧 gost 脚本可直接导入'),
    field('', credNote),
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
  // 第一列是开关，表头也跟着居中，否则“开”字会和开关错开一格
  head.appendChild(el('div', 'cell center', '开'));
  ['#', '规则名', '目标 IP / CIDR', '走哪条链 / 直连', '说明（该链备注）', ''].forEach(h =>
    head.appendChild(el('div', 'cell', h)));
  t.appendChild(head);

  if (!routes.length) {
    t.appendChild(el('div', 'empty', '还没有规则。点「添加规则」把内网网段指到某条链；本机网段 / 局域网邻居选「直连」。'));
    return;
  }

  routes.forEach(r => {
    const row = el('div', 'trow rule-grid');
    if (!r.enabled) row.classList.add('is-off');

    // 规则开关：一下点到位（现场要在多个内网环境之间来回切，不能每次弹表单）
    const swCell = el('div', 'cell');
    const sw = el('button', 'rule-switch' + (r.enabled ? ' is-on' : ''));
    sw.type = 'button';
    sw.title = r.enabled
      ? '已启用 —— 点一下停用（停用后不进匹配、不占目标，也不进内核过滤器）'
      : '已停用 —— 点一下启用';
    sw.setAttribute('aria-pressed', r.enabled ? 'true' : 'false');
    sw.onclick = async () => {
      sw.disabled = true;
      try {
        await call('SetRouteEnabled', r.index, !r.enabled);
        await loadRoutes();
        toast(r.enabled ? '已停用规则' : '已启用规则',
          (r.name || '（未命名）') + (r.enabled ? '：不再接管它的目标' : '：现在开始接管'),
          'success');
      } catch (e) {
        sw.disabled = false;
        fail(e);
      }
    };
    swCell.appendChild(sw);
    row.appendChild(swCell);

    const idxCell = el('div', 'cell');
    idxCell.appendChild(el('span', 'idx', String(r.index + 1)));
    row.appendChild(idxCell);
    row.appendChild(el('div', 'cell' + (r.name ? ' strong' : ' dim'), r.name || '（未命名）'));
    row.appendChild(targetsCell(r.targets || [], r.ports || [], r.shadowed || [], r.localNets || [], r.inactive, r.apps || [], r.hostResolves || []));
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
function targetsCell(list, ports, shadowed, localNets, inactive, apps, resolves) {
  const cap = 3;
  const c = el('div', 'cell mono');
  c.textContent = list.slice(0, cap).join(' ') +
    (list.length > cap ? '  +' + (list.length - cap) + ' 个' : '');
  // 域名目标：把解析结果直接摆出来（悬停看全部；解析不到就是**这条规则什么都没拦**）
  for (const hr of (resolves || [])) {
    const s = hr.failed
      ? el('span', 'resolve-bad', '  ⚠ ' + hr.host + ' 解析不到')
      : el('span', 'dim', '  → ' + (hr.ips || []).join(','));
    s.title = hr.failed
      ? hr.host + ' 现在解析不到，这条规则暂不匹配任何流量。\n原因：' + (hr.lastErr || '未知') +
        '\n修法：确认本机 DNS 能解析这个名字（内网域名通常只有客户网内的 DNS 才解得开），' +
        '或者在「设置 → 系统 hosts 接管」里写一条 IP 域名映射。'
      : hr.host + ' 解析到 ' + (hr.ips || []).join(', ') +
        (hr.age ? '（' + hr.age + ' 前解析' + (hr.stale ? '，已过期，正在刷新' : '') + '）' : '');
    c.appendChild(s);
  }
  ports = ports || [];
  if (ports.length) c.appendChild(el('span', 'dim', '  · 端口 ' + ports.join(',')));
  // A20：进程条件 —— 只按进程的规则（无目标）这里会先说清楚“谁”
  apps = apps || [];
  if (apps.length) {
    const a = el('span', 'dim', (list.length ? '  · ' : '') + '进程 ' + apps.join(','));
    a.title = '只匹配这些进程发起的连接：' + apps.join(', ') +
      '\n查不到进程的连接（系统服务/受保护进程）不会命中带进程条件的规则';
    c.appendChild(a);
  }
  if (!list.length && !apps.length) c.appendChild(el('span', 'dim', '任何连接'));
  localNets = localNets || [];
  if (localNets.length) {
    // A16：这条规则只在某些本机网段下生效；当前不满足就标出来（别让人以为“配了却没生效”）
    const s = el('span', inactive ? 'shadow-warn' : 'dim',
      '  · 仅限本机在 ' + localNets.join(',') + (inactive ? '（当前网络不满足，暂时不生效）' : ''));
    s.title = '本机地址落在 ' + localNets.join(',') + ' 里时这条规则才生效';
    c.appendChild(s);
  }
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
  chains.forEach(c => {    const o = el('option', null, c.name + '   —   ' + (c.forward || ''));
    o.value = c.name;
    sel.appendChild(o);
  });
  sel.value = src.chain || chains[0].name;

  const ports = input('text', (src.ports || []).join(', '), '留空 = 全部端口；也可 443, 8000-9000');

  // A20：进程条件（可选）。定位是“例外”，所以放在后面、并写明代价。
  // 支持 * 通配；查不到进程时这条条件不命中。
  const apps = input('text', (src.apps || []).join(', '),
    '留空 = 不看进程（常规做法）。进程名或 *.exe / *weixin*，逗号分隔；' +
    '写了它就要求“目标命中 且 是这些进程发的”——只填进程、不填目标也可以');
  const appBox = el('div', 'input-row top');
  appBox.appendChild(apps);
  appBox.appendChild(btn('从当前连接选', 'btn btn-xs', async () => {
    try {
      const d = await call('GetConns');
      const list = ((d && d.list) || []).filter(c => c.proc);
      if (!list.length) {
        toast('暂时没有带进程信息的连接', '先让目标程序发起一次连接，再回来点这里', 'info');
        return;
      }
      // 按出现次数排序：用得多的排前面
      const cnt = {};
      list.forEach(c => { cnt[c.proc] = (cnt[c.proc] || 0) + 1; });
      const names = Object.keys(cnt).sort((a, b) => cnt[b] - cnt[a]);
      modal.open('选进程', [field('最近发起过连接的进程', checkboxList(names, cnt),
        '勾选后写进“进程”框；也可以直接手打进程名')], async () => {
        const picked = Array.from(document.querySelectorAll('.pick-app:checked')).map(x => x.value);
        if (picked.length) {
          const cur = splitTargets(apps.value);
          apps.value = cur.concat(picked.filter(p => !cur.includes(p))).join(', ');
        }
        modal.close();
      }, '加入');
    } catch (e) { fail(e); }
  }));

  // A16：可选“仅在这些本机网段下生效”
  const localNets = textarea((src.localNets || []).join('\n'),
    '留空 = 总是生效。填了就要求“本机也有个地址在这些网段里”才生效，\n示例：10.0.0.0/8（在公司才走隧道，回家自动直连）', 3);
  const lnBox = el('div', 'input-row top');
  lnBox.appendChild(localNets);
  lnBox.appendChild(btn('填本机网段', 'btn btn-xs', async () => {
    try {
      const subs = await call('LocalSubnets');
      if (!subs || !subs.length) { toast('没读到本机网段', '接口上没有 IPv4 地址', 'warn'); return; }
      localNets.value = splitTargets(localNets.value).concat(subs).join('\n');
    } catch (e) { fail(e); }
  }));

  const nodes = [
    field('规则名', name, '给这条规则起个名字（可留空）'),
    field('目标', targetsBox,
      "单个 IP 会自动存成 /32；也可以直接写域名（main.his.com）；填多个目标就是同一条规则 —— 命中其中任意一个都走下面这个动作"),
    field('端口', ports,
      '留空 = 任意端口。填了就要求「目标命中 且 端口命中」；' +
      '想排除某个端口（比如 Windows 更新的 7680），把它写成前面一条「直连」规则、端口只填那个端口'),
    field('动作', sel,
      '「直连」= 不改写、不进隧道（本机网段、打印机、共享盘、同事机器用这个）；' +
      '「阻断」= 直接丢弃；规则自上而下匹配，命中即停'),
    field('进程（可选）', appBox,
      '用来写“例外”：某个程序必须走隧道、或绝不允许走隧道（哪怕它的目标不固定）。' +
      '⚠ 查不到进程的连接（系统服务、受保护进程）不会命中带进程条件的规则 —— 宁可漏过也不误伤；' +
      '另外“只填进程、不填目标”会让所有流量都过一遗用户态（性能略降），慎用'),
    field('生效条件（可选）', lnBox,
      '只在这台机器处于某个网络时才生效 —— 笔记本在公司走隧道、回家自动直连。' +
      '当前不满足条件的规则会在列表里标灰，不会模棱两可地“好像没生效”'),
  ];

  modal.open(isNew ? '添加规则' : '编辑规则', nodes, async () => {
    try {
      if (isNew) await call('SaveRoute', -1, {
        name: name.value, targets: targets.value, chain: sel.value,
        ports: ports.value, localNets: localNets.value, apps: apps.value,
      });
      else await call('SaveRoute', index, {
        name: name.value, targets: targets.value, chain: sel.value,
        ports: ports.value, localNets: localNets.value, apps: apps.value,
      });
      modal.close();
      await loadRoutes();
      toast(isNew ? '已添加规则' : '已更新规则',
        (name.value.trim() || '未命名') + '：' + splitTargets(targets.value).length + ' 个目标' +
        (splitTargets(ports.value).length ? '，端口 ' + ports.value.trim() : '') +
        (splitTargets(apps.value).length ? '，仅 ' + apps.value.trim().replace(/\s+/g, ' ') + ' 发起' : '') +
        ' → ' +
        actionName(sel.value) +
        (splitTargets(localNets.value).length ? '（仅限本机在 ' + localNets.value.trim().replace(/\s+/g, ' ') + ' 时）' : ''),
        'success');
    } catch (e) { modal.error(fail(e)); }
  });
}

/* 勾选列表：多选用（选进程用）。cnt 只用来在右侧显示出现次数。 */
function checkboxList(items, cnt) {
  const box = el('div', 'pick-list');
  items.forEach(name => {
    const row = el('label', 'pick-row');
    const cb = el('input', 'pick-app');
    cb.type = 'checkbox';
    cb.value = name;
    row.appendChild(cb);
    row.appendChild(el('span', 'mono', name));
    if (cnt && cnt[name]) row.appendChild(el('span', 'dim', '× ' + cnt[name]));
    box.appendChild(row);
  });
  return box;
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

/* 常驻告警条：把"内网可能被 Clash 接管"这种红线从日志提到界面上。
   它不自动消失 —— 只有检测结果变成 OK 才隐。这样即使人当时不在电脑前，回来也能看到。 */
function noticeBar(kind, title, text, actionLabel, actionFn) {
  const bar = document.getElementById('noticeBar');
  bar.replaceChildren();
  if (!kind) { bar.hidden = true; return; }
  bar.hidden = false;
  bar.className = 'noticebar is-' + kind;
  bar.appendChild(el('span', 'nb-title', title));
  if (text) bar.appendChild(el('span', 'nb-text', text));
  if (actionLabel && actionFn) bar.appendChild(btn(actionLabel, 'btn btn-xs', actionFn));
  bar.appendChild(btn('详情', 'btn btn-xs', () => {
    // 直接跳到「诊断」页的 Clash 共存卡，那里有逐条走向与修法
    showPage('diag');
    const c = document.getElementById('clashDetail');
    if (c) c.scrollIntoView({ block: 'center' });
  }));
}

/* 内网被交给 Clash 是红线（DNS 外泄/封号），所以用它驱动常驻横幅。 */
function updateClashBar(v) {
  if (!v) { noticeBar(null); return; }
  if (v.coverage && v.coverage.ok === false && (v.coverage.missed || []).length) {
    const missed = v.coverage.missed;
    noticeBar('error', '内网可能被其他代理接管（红线）',
      missed.length + ' 个目标不在系统代理的绕过列表里：' + missed.slice(0, 4).join('; ') +
        (missed.length > 4 ? ' 等' : '') +
        '　—— 这几个不在系统代理的绕过列表里，按域名访问内网时**可能**先交给它（它用自己的 DNS 解析，内网域名有出内网的风险）· 实测环境：Clash Verge v2.5.2',
      '复制要加的网段', async () => {
        const list = (v.bypassList || missed.join(';'));
        try {
          await navigator.clipboard.writeText(list);
          toast('已复制', '粘到 Clash Verge → 设置 → 系统代理 → 绕过地址：' + list, 'success');
        } catch (e) {
          toast('复制失败，请手动复制', list, 'warn');
        }
      });
    return;
  }
  noticeBar(null);
}


/* 开机与轮询用：只读注册表的覆盖结果（便宜），驱动常驻告警条。 */
async function refreshClashBar() {
  let c;
  try { c = await call('ClashCoverage'); } catch (e) { return; }
  updateClashBar({ coverage: c, bypassList: ((c && c.missed) || []).join(';') });
}

function renderClash(v) {
  updateClashBar(v);
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
  await renderLoopInfo();
}

// A14：疑似环路（最典型的成因就是被别的代理绕回来，所以放在这张卡里）
async function renderLoopInfo() {
  const box = document.getElementById('loopInfo');
  if (!box) return;
  let v = null;
  try { v = await call('GetLoopInfo'); } catch (e) { return; }
  if (!v || !v.alerts) {
    box.className = 'hint';
    box.textContent = '环路检测：未发现异常。';
    return;
  }
  box.className = 'export-warn';
  box.textContent = '⚠ 疑似环路 ' + v.alerts + ' 次；最近一次（' + (v.at || '') + '）：' + (v.last || '');
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
  loadAbout();
  setValue('setDialTimeout', s.dialTimeout || 5);
  setValue('setDialBudget', s.dialBudget || 10);
  setValue('setRaceAfter', s.raceAfter === 0 ? 0 : (s.raceAfter || 300));
  setValue('setWarm', s.warmSessions === 0 ? 0 : (s.warmSessions || 2));
  const dh = document.getElementById('dialHint');
  if (dh) {
    // 这里只留**当前值**一行；每个数字的完整解释在旁边的“i”弹窗里
    dh.textContent = '当前：单次 ' + (s.dialTimeout || 5) + ' 秒 / 总预算 ' + (s.dialBudget || 10) +
      ' 秒 / 竞速 ' + (s.raceAfter === 0 ? 0 : (s.raceAfter || 300)) +
      ' 毫秒 / 预热 ' + (s.warmSessions === 0 ? 0 : (s.warmSessions || 2)) + ' 条。改完点「保存并重启」生效。';
  }
}

// 长说明统一放这里；界面上的小字只留一句概括 + 一个“i”按钮。
const HELP = {
  dial: {
    title: '上游拨号：这几个数字是什么意思',
    paras: [
      '「单次超时」= 一条上游最多等多久。实测现网握手 0.1～0.8 秒，5 秒余量充足；调小切得更快，但可能误杀慢链路。',
      '「总预算」= 一整次连接最多花多久（所有上游加起来）。超过就失败，不再干等。',
      '「竞速起跑」= 第一条超过这个时间还没连上，就并发试其他上游、取先到的；0 = 关闭竞速。',
      '实测某条链的 CONNECT 要 620ms、另一条只要 75ms，竞速能直接把业务拉到快链路；',
      '但太激进会让健康上游也每条都多拨一次，所以默认 300ms 而不是更小。',
      '「预热会话」= 每条上游提前养几条“已握手、只差 CONNECT”的会话，业务来了不用等握手；0 = 关闭（不预热）。',
      '单位：前两个是秒，第三个是毫秒，最后一个是个数。改完点「保存并重启」生效。',
    ],
  },
  service: {
    title: 'headless 模式（Windows 服务）',
    paras: [
      '装成服务后：开机即启（不等登录）、以 LocalSystem 跑、没有界面（纯引擎）。',
      '配置与日志跟界面版完全共用（都在程序目录），所以两边看到的是同一份东西。',
      '安装 / 卸载需要管理员权限 —— 本程序本来就是以管理员跑的，点就行。',
      '开机自启建议二选一：计划任务（登录后静默启动，能看托盘）或本服务（无人登录也能跑）；两个都开反而会有两份。',
    ],
  },
  clash: {
    title: '与其它代理共存：它依据什么判断、怎么修',
    paras: [
      '检测依据是 Windows 的「系统代理设置」（注册表里的代理服务器 / 绕过列表）——不限于 Clash，任何装到系统代理上的工具都一样适用。',
      '实测环境：Clash Verge v2.5.2。',
      '如果这台机器压根没启用系统代理，本页会直接判定正常。',
      '要修的时候：把内网网段和域名填进那个工具的「绕过地址」，让它别把内网请求也接过去；',
      '填完可以用同处的「当前绕过」核对是不是真的写进去了。',
      '不修也能用，但如果工具把域名解析也接走（DNS 外泄），我们可能拿不到真实的 IP。',
      '为什么不帮你自动填：这份配置由那个工具自己维护，它每次应用系统代理都会重写该值 —— 实测我们写进去 5 秒内就被冲掉。',
      '两个程序抢一个全局设置，得不偿失。',
    ],
  },
  hosts: {
    title: '系统 hosts 接管：我们会动哪一部分',
    paras: [
      '我们只写自己那一段（文件里带 NetHub 标记的那几行），块外的内容（Docker、微信 pin 之类）一个字都不碰。',
      '第一次写入前会把原文件备份成 hosts.nethub.bak，只备一次，不覆盖最初的版本。',
      '块外如果已经有一条同名记录，会被我们接管（挪进我们的段）——因为 Windows 取第一条匹配，不处理的话我们写的不会生效。',
      '写完会刷一次 DNS 缓存，否则系统可能继续用缓存里的旧解析。',
      '这个文件别的程序也会改（杀软、微信、Clash、VPN 都会写）；被改掉后我们每 60 秒会自检并改回来，日志里会说明原因。',
      '日志里出现“hosts 被其他程序改动了…已自动恢复”就是这件事，不是报错。',
    ],
  },
};

function showHelp(key) {
  const h = HELP[key];
  if (!h) return;
  const box = el('div', 'help-body');
  for (const p of h.paras) box.appendChild(el('p', 'help-p', p));
  modal.open(h.title, [box], null);
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
      return Number.isFinite(n) && n >= 0 ? n : 300;
    })(),
    warmSessions: (function () {
      const e = document.getElementById('setWarm');
      const n = e ? parseInt(e.value, 10) : NaN;
      return Number.isFinite(n) && n >= 0 ? n : 2;
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
    if (out) out.textContent = '正在自检…（逐条链探真实内网主机）';
    pushLog({ time: now(), level: 'INFO', text: '开始链路自检…' });
    call('SelfTest').catch(fail);
  };
  const btnSelfTestCopy = document.getElementById('btnSelfTestCopy');
  if (btnSelfTestCopy) btnSelfTestCopy.onclick = async () => {
    const out = document.getElementById('selfTestOut');
    if (!out || !out.dataset.report) return;
    try { await navigator.clipboard.writeText(out.dataset.report); toast('已复制', '自检结果已复制到剪贴板', 'success'); }
    catch { toast('复制失败', '请手动选中复制', 'warn'); }
  };
  const bind = (id, key) => { const b = document.getElementById(id); if (b) b.onclick = () => showHelp(key); };
  bind('btnHelpDial', 'dial');
  bind('btnHelpService', 'service');
  bind('btnHelpClash', 'clash');
  bind('btnHelpHosts', 'hosts');

  // 连接页
  document.getElementById('btnConnRefresh').onclick = () => loadConns();
  document.getElementById('setCountDirect').onchange = async (ev) => {
    try {
      await call('SetCountDirect', ev.target.checked);
      toast('已保存', ev.target.checked ? '直连流量从现在起也会被统计（服务已重启）' : '直连流量不再经过我们（零开销）', 'success');
      await loadCountDirect();
    } catch (e) { fail(e); ev.target.checked = !ev.target.checked; }
  };

  // 规则页
  document.getElementById('btnRuleSort').onclick = sortRoutes;
  document.getElementById('btnRuleOverlap').onclick = checkOverlaps;
  document.getElementById('btnExplain').onclick = explainTarget;
  document.getElementById('explainIp').onkeydown = e => {
    // Ctrl/⌘+Enter 触发（普通 Enter 要能换行，因为现在是多行输入）
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) explainTarget();
  };

  // 诊断页：巡检设置
  document.getElementById('btnPatrolSave').onclick = savePatrol;

  // 设置页：体检 / 诊断包 / Windows 服务
  document.getElementById('btnPrecheck').onclick = () => precheckConfig(false);
  document.getElementById("btnDiag").onclick = exportDiagnostics;
  document.getElementById("btnCopyPrecheck").onclick = copyPrecheck;
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
  wireAbout();
  document.getElementById('btnExportCfg').onclick = async () => {
    try {
      const p = await call('ExportConfig');
      if (p) toast('已导出配置', p + '　（里面是明文上游口令：新机器上「导入配置」选它即可开箱即用；别发群里）', 'success');
    } catch (e) { fail(e); }
  };
  document.getElementById('btnExportDoc').onclick = async () => {
    try {
      const p = await call('ExportConfigRedacted');
      if (p) toast('已导出（口令已抹掉）', p + '　（可以发给别人看配置；导入后需补上游口令）', 'success');
    } catch (e) { fail(e); }
  };
  document.getElementById('btnDialReset').onclick = resetDialDefaults;
  document.getElementById('btnImportURL').onclick = importConfigFromURL;
  document.getElementById('btnImportCfg').onclick = async () => {
    const ok = await confirmBox('导入配置',
      '会先用新配置做一次完整校验，通过后自动备份当前配置再生效并重启服务。校验不过则什么都不改。确定继续？',
      false, '选择文件');
    if (!ok) return;
    try {
      const p = await call('ImportConfig');
      if (p) {
        toast('已导入配置并重启', p, 'success');
        await reloadAll();
      }
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
  });
  // 自检的整体结果：直接渲染在「链路自检」框里（不用回日志里找）
  R().EventsOn('selftest-report', r => renderSelfTest(r));
}

/* 自检结果渲染到诊断页的输出框（原样列出每条链，方便整段复制给 agent）。 */
function renderSelfTest(r) {
  const out = document.getElementById('selfTestOut');
  if (!out || !r) return;
  const lines = [];
  const head = r.bad === 0
    ? `✓ ${r.total} 条链全部可用（${r.at}）`
    : `✗ ${r.bad}/${r.total} 条链有问题（${r.at}）`;
  lines.push(head);
  for (const c of (r.chains || [])) {
    lines.push((c.ok ? '  ✓ ' : '  ✗ ') + c.name);
    for (const d of (c.detail || [])) lines.push('      ' + d);
  }
  out.textContent = lines.join('\n');
  out.dataset.report = lines.join('\n');
}

/* 打开设置页时把上次结果补上（开机自动跑过一次，不必重复点）。 */
async function loadLastSelfTest() {
  try {
    const r = await call('LastSelfTest');
    if (r && r.at) renderSelfTest(r);
  } catch { /* 拿不到就算了，不影响手动自检 */ }
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
  // Clash 绕过覆盖：开机就要挂常驻告警条，之后每分钟复核一次（只读注册表，很便宜）
  refreshClashBar();
  setInterval(refreshClashBar, 60000);
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

/* 直连统计开关（A15） */
async function loadCountDirect() {
  const cb = document.getElementById('setCountDirect');
  if (!cb) return;
  let v = null;
  try { v = await call('GetCountDirect'); } catch (e) { return; }
  if (!v) return;
  cb.checked = !!v.on;
  const info = document.getElementById('countDirectInfo');
  if (info) {
    info.textContent = v.on
      ? '当前：开。直连流量的 ↑↓ 都会有数字（每包多一点开销）。'
      : '当前：关。直连的字节数只有出方向的一点点（过滤器不碰直连流量，这是默认的零开销姿势）。';
  }
}

/* 规则重叠检查（用户点按钮才跑：重叠不一定错，只摆事实） */
async function checkOverlaps() {
  let r;
  try { r = await call('CheckOverlaps'); } catch (e) { return fail(e); }

  const box = el('div', 'sim-box');
  const sum = el('div', 'sim-summary');
  sum.textContent = r.summary || '';
  box.appendChild(sum);

  if (!r.rows || !r.rows.length) {
    const p = el('div', 'hint');
    p.style.padding = '12px 16px';
    p.textContent = '所有规则的目标与端口都不重叠 —— 顺序怎么放都不会互相影响。';
    box.appendChild(p);
    modal.open('规则重叠检查', [box], null);
    return;
  }

  const tbl = el('div', 'table');
  const th = el('div', 'trow thead ov-grid');
  ['规则对', '重叠范围', '实际归谁', '怎么办'].forEach(h => th.appendChild(el('div', 'cell', h)));
  tbl.appendChild(th);

  r.rows.forEach(o => {
    const row = el('div', 'trow ov-grid');
    // 规则对
    const c1 = el('div', 'cell');
    c1.appendChild(el('span', 'dim', '前 ' + o.earlier + ' '));
    c1.appendChild(el('span', null, o.earlierName || '（未命名）'));
    c1.appendChild(el('span', 'dim', '  ↔  后 ' + o.later + ' '));
    c1.appendChild(el('span', null, o.laterName || '（未命名）'));
    row.appendChild(c1);
    // 重叠范围
    const c2 = el('div', 'cell mono dim');
    c2.textContent = (o.targets || []).join('  ') + ((o.ports && o.ports.length) ? '  端口 ' + o.ports.join(',') : '');
    c2.title = (o.targets || []).join('\n');
    row.appendChild(c2);
    // 实际归谁
    const c3 = el('div', 'cell');
    const badge = el('span', 'sim-badge ' + (o.kind === 'dead' ? 'bad' : o.kind === 'shadowed' ? 'none' : 'direct'));
    badge.textContent = o.kind === 'dead' ? '永远轮不到' : o.kind === 'shadowed' ? '部分被抢' : '正常';
    c3.appendChild(badge);
    c3.appendChild(el('span', 'dim', '  ' + o.resolution));
    row.appendChild(c3);
    // 怎么办（只给选择，不下命令）
    const c4 = el('div', 'cell dim');
    c4.textContent = o.kind === 'fine'
      ? '不用动：更窄的本来就在前面'
      : '两种选择：① 就是想让它生效 → 点「按优先级排序」；② 就是想让前面那条兜底 → 保持现状即可（这是合法写法）';
    row.appendChild(c4);
    tbl.appendChild(row);
  });
  box.appendChild(tbl);
  modal.open('规则重叠检查', [box], null);
}

/* 从 URL 导入配置（团队统一下发的最小形态） */
async function importConfigFromURL() {
  const el = document.getElementById('importURL');
  const url = (el && el.value || '').trim();
  if (!url) { toast('先填地址', '例如 https://内网地址/nethub-config.yaml', 'warn'); return; }
  if (!await confirmBox('从地址导入配置',
      '会先下载并做一次完整校验，通过后自动备份当前配置再生效并重启服务。确定继续？', false, '下载并导入')) return;
  try {
    const p = await call('ImportConfigFromURL', url);
    if (p) {
      toast('已从地址导入配置并重启', p, 'success');
      await reloadAll();
    }
  } catch (e) { fail(e); }
}

/* 关于卡 */
function setText(id, t) {
  const e = document.getElementById(id);
  if (e) e.textContent = t == null ? '-' : String(t);
}

async function loadAbout() {
  let v = null;
  try { v = await call('GetAbout'); } catch (e) { return; }
  if (!v) return;
  setText('aboutGo', v.goVersion || '-');
  setText('aboutVersion', v.version === 'dev' ? 'dev' : v.version);
  state.repo = v.repo || 'https://github.com/Lithivm/NetHub';
  const link = document.getElementById('repoLink');
  if (link) link.href = state.repo;
}

/* 关于卡：同一个按钮两种状态 —— 没新版时是「检查更新」，查到新版就变成「下载并更新」。
   过程与结果都走 toast 与按钮文字，卡片里不堆说明文字。 */
function wireAbout() {
  const btn = document.getElementById('btnCheckUpdate');
  if (!btn) return;
  let pending = null;
  btn.onclick = async () => {
    if (pending) return startUpdate(btn, pending);
    btn.disabled = true;
    btn.textContent = '检查中…';
    try {
      const v = await call('CheckUpdate');
      if (v && v.hasNew) {
        pending = v;
        btn.textContent = '下载并更新';
        btn.className = 'btn btn-sm btn-primary';
        toast('有新版本 ' + v.latest, '当前 ' + v.current + '。点「下载并更新」会自动升级并重启。', 'success');
      } else {
        btn.textContent = '检查更新';
        toast('检查更新', (v && v.note) ? v.note : '没拿到结果。', 'info');
      }
    } catch (e) {
      btn.textContent = '检查更新';
      fail(e);
    } finally { btn.disabled = false; }
  };
}

/* 一键更新：确认 → 下载（进度写在按钮上）→ 校验 → 替换 → 自动重启 */
async function startUpdate(btn, info) {
  const ok = await confirmBox('下载并更新到 ' + info.latest,
    '会从 GitHub 下载新版本、校验完整性、替换程序文件，然后自动重启。\n' +
    '重启时隧道会中断几秒；上一版本保留为 nethub.exe.old，出问题可回滚（命令行 nethub.exe -rollback）。',
    false, '开始更新');
  if (!ok) return;
  btn.disabled = true;
  btn.textContent = '准备中…';
  try {
    await call('DownloadAndUpdate');
  } catch (e) {
    btn.disabled = false;
    btn.textContent = '下载并更新';
    return fail(e);
  }
  const tick = setInterval(async () => {
    let s = null;
    try { s = await call('GetUpdateStatus'); } catch (e) { return; }
    if (!s) return;
    if (s.stage === 'download') btn.textContent = s.percent >= 0 ? ('下载中 ' + s.percent + '%') : '下载中…';
    else if (s.stage === 'verify') btn.textContent = '校验中…';
    else if (s.stage === 'stage') btn.textContent = '解包中…';
    else if (s.stage === 'swap' || s.stage === 'restart') btn.textContent = '重启中…';
    if (s.stage === 'error' || s.stage === 'done') {
      clearInterval(tick);
      btn.disabled = false;
      if (s.stage === 'error') {
        btn.textContent = '下载并更新';
        toast('更新失败', s.err || s.text || '', 'error');
      } else {
        btn.textContent = '检查更新';
        btn.className = 'btn btn-sm';
        toast('检查更新', s.text || '', 'info');
      }
    }
  }, 500);
}

/* 上游拨号：重置为默认（只回填输入框。保存与重启仍由用户决定 —— 不在用户没点保存时动线上服务） */
function resetDialDefaults() {
  setValue('setDialTimeout', 5);
  setValue('setDialBudget', 10);
  setValue('setRaceAfter', 300);
  setValue('setWarm', 2);
  toast('已填回默认值', '单次 5s / 总预算 10s / 竞速起跑 300ms / 预热 2 条。点「保存并重启」才生效。', 'success');
}


/* 导入配置（本地文件 / 从地址）后把界面整体刷一遍。
   之前这里调用的函数根本不存在（名字不写在这里，免得自检把它当成一处调用），导入成功后界面会直接抛错、停在不刷新状态。 */
async function reloadAll() {
  await Promise.all([
    loadChains(),
    loadRoutes(),
    loadSettings(),
    loadBackups(),
    loadConns(),
    loadTargetHealth(),
    precheckConfig(true),
  ]);
  await refreshState();
}
