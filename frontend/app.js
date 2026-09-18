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

function confirmBox(title, text, danger) {
  return new Promise(res => {
    const p = el('p', null, text);
    p.style.color = 'var(--body)';
    modal.open(title, [p], () => { modal.close(); res(true); }, danger ? '删除' : '确定');
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
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('is-active', t.dataset.page === name));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('is-active', p.id === 'page-' + name));
  if (name === 'log') scrollLogToEnd();
  if (name === 'conn') loadConns();
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
  const rs = document.getElementById('runState');
  rs.classList.toggle('is-on', on);
  document.getElementById('runStateText').textContent = on ? '运行中' : '未启动';
  document.getElementById('btnToggle').textContent = on ? '停止服务' : '启动服务';
  document.getElementById('btnToggle').className = on ? 'btn' : 'btn btn-primary';

  document.getElementById('stRelay').textContent = s.relay || '-';
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
   ['random', '随机']].forEach(([v, label]) => {
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
    row.appendChild(targetsCell(r.targets || [], r.ports || []));
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
function targetsCell(list, ports) {
  const cap = 3;
  const c = el('div', 'cell mono');
  c.textContent = list.slice(0, cap).join(' ') +
    (list.length > cap ? '  +' + (list.length - cap) + ' 个' : '');
  ports = ports || [];
  if (ports.length) c.appendChild(el('span', 'dim', '  · 端口 ' + ports.join(',')));
  if (list.length > 1 || ports.length) {
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

async function saveSettings(restart) {
  const elEntries = document.getElementById('setHostsEntries');
  const elManage = document.getElementById('setHostsManage');
  const payload = {
    hostsManage: !!(elManage && elManage.checked),
    hostsEntries: elEntries ? elEntries.value.split('\n').map(s => s.trim()).filter(Boolean) : [],
    theme: state.theme,
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
    document.getElementById('logBox').appendChild(
      logNode({ time: now(), level: 'INFO', text: '开始链路自检…' }));
    call('SelfTest').catch(fail);
  };

  // 连接页
  document.getElementById('btnConnRefresh').onclick = () => loadConns();

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
    pushLog({ time: now(), level: p.ok ? 'INFO' : 'ERROR',
      text: p.ok ? ('自检通过：' + p.target + ':' + p.port) : ('自检失败：' + p.target + ' ' + (p.err || '')) });
  });
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
  const bad = panels.filter(p => p.status === 'rejected');
  if (bad.length) {
    console.error('面板加载失败', bad.map(p => p.reason));
    toast('部分面板加载失败', bad.map(p => String(p.reason)).join('；'), 'error');
  }

  refreshState();
  clashCheck();   // 进界面就跑一次共存检测（失败不影响其他）
}

window.addEventListener('DOMContentLoaded', () => boot().catch(e => toast('初始化失败', String(e), 'error')));
