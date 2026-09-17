/* netproxy 前端逻辑。
   后端调用约定（Wails 运行时自动生成的 bindings）：
     window.go.webui.Backend.<Method>(...)
   Go 侧返回值末尾带 error 的方法，Promise 会 reject —— 统一在 call() 里兜住。 */

'use strict';

const B = () => window.go.webui.Backend;   // 每次取，避免绑定还没注入时抓到 undefined
const R = () => window.runtime;

let state = { theme: 'light' };
let chains = [];
let routes = [];
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
}

/* ═══════════════ 状态刷新 ═══════════════ */

async function refreshState() {
  let s;
  try { s = await call('GetState'); } catch (_) { return; }
  state = Object.assign(state, s);

  const on = !!s.running;
  const rs = document.getElementById('runState');
  rs.classList.toggle('is-on', on);
  document.getElementById('runStateText').textContent = on ? '运行中' : '未启动';
  document.getElementById('btnToggle').textContent = on ? '停止服务' : '启动服务';
  document.getElementById('btnToggle').className = on ? 'btn' : 'btn btn-primary';

  document.getElementById('stRelay').textContent = s.relay || '-';
  document.getElementById('stPids').textContent = s.gostPids || '-';
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
  document.getElementById('badgeChain').textContent = chains.length;

  const t = document.getElementById('chainTable');
  t.replaceChildren();

  const head = el('div', 'trow thead chain-grid');
  ['链名', '本地 socks5 监听', '上游转发（凭据已遮蔽）', '说明', ''].forEach(h =>
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
    row.appendChild(el('div', 'cell mono', c.listen));
    row.appendChild(el('div', 'cell mono dim', c.forward));
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

function btn(text, cls, fn) {
  const b = el('button', cls, text);
  b.onclick = fn;
  return b;
}

/* 链路编辑表单 —— 也用于"从 bat 导入后回填" */
function chainForm(index, preset) {
  const isNew = index == null;
  const src = preset || (isNew ? { name: '', listen: '', forward: '', note: '' } : chains[index]);

  const name = input('text', src.name, '例如 proxy-a（规则里用这个名字引用它）');
  const listen = input('text', src.listen, 'host:port，例如 127.0.0.1:1082');
  const forward = input('text', src.forward, 'gost -F 的值');
  forward.classList.add('mono');
  const note = input('text', src.note, '随便写（显示在链路的说明列）');

  const importBtn = btn('从 gost .bat 导入…', 'btn btn-sm', async () => {
    try {
      const r = await call('PickBatFile');
      if (!r) return;                      // 用户取消
      listen.value = r.listen;
      forward.value = r.forward;
      if (!name.value) name.value = r.name;
      toast('已读取 ' + r.file, r.listen, 'success');
    } catch (e) { modal.error(fail(e)); }
  });

  const warn = el('p', 'hint', '凭据会明文保存在 config.yaml，别外传。');
  const nodes = [
    field('链名', name), field('本地监听', listen), field('上游转发', forward),
    field('', importBtn), field('备注', note), field('', warn),
  ];

  modal.open(isNew ? '添加链路' : '编辑链路', nodes, async () => {
    try {
      const payload = { name: name.value, listen: listen.value, forward: forward.value, note: note.value };
      if (isNew) await call('AddChain', payload);
      else await call('UpdateChain', src.name, payload);
      modal.close();
      await loadChains();
      toast(isNew ? '已添加链路' : '已更新链路', payload.name, 'success');
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
    modal.open('导入结果',
      [el('p', null, '新增/更新 ' + added.length + ' 条，跳过 ' + skipped.length + ' 条'),
       ...added.map(s => el('div', 'hint', '✓ ' + s)),
       ...skipped.map(s => el('div', 'hint', '· ' + s))],
      () => modal.close(), '知道了');
    document.getElementById('modalCancel').style.display = 'none';
  } catch (e) { fail(e); }
}

/* ═══════════════ 规则表 ═══════════════ */

async function loadRoutes() {
  try { routes = await call('GetRoutes'); } catch (e) { return fail(e); }
  document.getElementById('badgeRule').textContent = routes.length;

  const t = document.getElementById('ruleTable');
  t.replaceChildren();

  const head = el('div', 'trow thead rule-grid');
  ['#', '目标 IP / CIDR', '走哪条链', '说明（该链备注）', ''].forEach(h =>
    head.appendChild(el('div', 'cell', h)));
  t.appendChild(head);

  if (!routes.length) {
    t.appendChild(el('div', 'empty', '还没有规则。点「添加规则」把内网网段指到某条链。'));
    return;
  }

  routes.forEach(r => {
    const row = el('div', 'trow rule-grid');
    const idxCell = el('div', 'cell');
    idxCell.appendChild(el('span', 'idx', String(r.index + 1)));
    row.appendChild(idxCell);
    row.appendChild(el('div', 'cell mono strong', r.target));
    row.appendChild(el('div', 'cell', r.chain));
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

function ruleForm(index) {
  const isNew = index == null;
  const src = isNew ? { target: '', chain: chains[0] ? chains[0].name : '' } : routes.find(r => r.index === index);
  if (!chains.length) { toast('无法添加规则', '请先到「隧道链路」页添加一条链', 'warn'); return; }

  const target = input('text', src.target, '单个 IP（10.0.1.10）或网段（10.0.1.0/24）');
  target.classList.add('mono');
  const sel = el('select', 'input');
  chains.forEach(c => {
    const o = el('option', null, c.name + '   —   ' + c.listen);
    o.value = c.name;
    sel.appendChild(o);
  });
  sel.value = src.chain || chains[0].name;

  const nodes = [
    field('目标', target, '单个 IP 会自动存成 /32；规则自上而下匹配，命中即停'),
    field('走哪条链', sel),
  ];

  modal.open(isNew ? '添加规则' : '编辑规则', nodes, async () => {
    try {
      if (isNew) await call('AddRoute', target.value, sel.value);
      else await call('UpdateRoute', index, target.value, sel.value);
      modal.close();
      await loadRoutes();
      toast(isNew ? '已添加规则' : '已更新规则', target.value, 'success');
    } catch (e) { modal.error(fail(e)); }
  });
}

async function moveRoute(i, d) {
  const to = i + d;
  if (to < 0 || to >= routes.length) return;
  try { await call('MoveRoute', i, to); await loadRoutes(); } catch (e) { fail(e); }
}

async function delRoute(i) {
  const r = routes.find(x => x.index === i);
  if (!await confirmBox('删除规则', '确定删除规则 ' + r.target + ' → ' + r.chain + ' 吗？', true)) return;
  try { await call('DeleteRoute', i); await loadRoutes(); toast('已删除规则', r.target, 'success'); }
  catch (e) { fail(e); }
}

/* ═══════════════ Clash 共存检测 ═══════════════ */


function renderClash(v) {
  const st = document.getElementById('clashState');
  st.textContent = v.verdict || '';
  st.className = 'clash-state ' + (v.needFix ? 'is-warn' : (v.items && v.items.length ? 'is-ok' : ''));

  const det = document.getElementById('clashDetail');
  det.replaceChildren();

  const modeName = { none: '未开启系统代理', system: '普通系统代理', pac: 'PAC（自动配置脚本）' }[v.mode] || v.mode;
  const meta = el('div', 'hint');
  meta.textContent = '模式：' + modeName
    + (v.proxyAddr ? '　代理：' + v.proxyAddr : '')
    + (v.bypassCount ? '　绕过条目：' + v.bypassCount + ' 条' : '')
    + '　隧道自检：' + v.tunnelOk + '/' + v.tunnelTotal;
  det.appendChild(meta);

  if (v.items && v.items.length) {
    const t = el('div', 'clash-table');
    ['内网域名', '直连（实测）', '系统代理判定', '交给代理能到吗（实测）'].forEach(h =>
      t.appendChild(el('div', null, h)));
    v.items.forEach(it => {
      t.appendChild(el('div', 'mono', it.host));
      t.appendChild(el('div', it.directOk ? 'clash-ok' : 'clash-no',
        it.directOk ? '通（' + it.directKind + '）' : '不通'));
      t.appendChild(el('div', it.bypassed ? 'clash-ok' : 'clash-warn',
        it.bypassed ? '走直连' : '交给代理'));
      t.appendChild(el('div', it.proxyOk ? 'clash-ok' : 'clash-no',
        it.proxyOk ? '通（' + it.proxyKind + '）' : '不通'));
    });
    det.appendChild(t);

    const leg = el('div', 'hint');
    leg.textContent = '读法：浏览器实际走哪条路由「系统代理判定」决定 —— 判定为「走直连」时只需第一列通（最后一列无关紧要）；'
      + '判定为「交给代理」时必须最后一列也通，否则浏览器就打不开内网域名。';
    det.appendChild(leg);

    const pub = el('div', 'hint');
    pub.textContent = v.publicProxy
      ? '公网对照（www.baidu.com 经代理）：通　—— 说明代理本身是好的'
      : '公网对照（www.baidu.com 经代理）：不通　—— 代理本身可能有问题：' + (v.publicErr || '');
    det.appendChild(pub);
  }

  const wrap = document.getElementById('clashFixWrap');
  wrap.hidden = !v.needFix;
  if (v.needFix) document.getElementById('clashBypass').value = v.bypassList || '';
}

async function clashCheck() {
  const st = document.getElementById('clashState');
  st.className = 'clash-state';
  st.textContent = '检测中…（每个域名会实跑直连与经代理两条路，约 10 秒）';
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
  document.getElementById('setGostEnabled').checked = s.gostEnabled;
  document.getElementById('setGostExe').value = s.gostExe || '';
  document.getElementById('setRelay').value = s.relay || '';
  document.getElementById('setHostsManage').checked = s.hostsManage;
  document.getElementById('setHostsEntries').value = (s.hostsEntries || []).join('\n');
}

async function saveSettings(restart) {
  const payload = {
    gostEnabled: document.getElementById('setGostEnabled').checked,
    gostExe: document.getElementById('setGostExe').value,
    relay: document.getElementById('setRelay').value,
    hostsManage: document.getElementById('setHostsManage').checked,
    hostsEntries: document.getElementById('setHostsEntries').value.split('\n').map(s => s.trim()).filter(Boolean),
    theme: state.theme,
  };
  try {
    await call('SaveSettings', payload);
    toast('设置已保存', restart ? '正在重启服务…' : 'gost 托管 / relay 的改动需要重启才生效', 'success');
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

  // 链路页
  document.getElementById('btnChainAdd').onclick = () => chainForm(null);
  document.getElementById('btnChainImport').onclick = importBats;

  // 规则页
  document.getElementById('btnRuleAdd').onclick = () => ruleForm(null);

  // 设置页
  document.getElementById('btnPickGost').onclick = async () => {
    try { const p = await call('PickGostExe'); if (p) document.getElementById('setGostExe').value = p; }
    catch (e) { fail(e); }
  };
  document.getElementById('btnSaveSettings').onclick = () => saveSettings(false);
  document.getElementById('btnSaveRestart').onclick = () => saveSettings(true);
  document.getElementById('btnOpenConfig').onclick = () => call('OpenConfigFile').catch(fail);
  document.getElementById('btnOpenDir').onclick = () => call('OpenProgramDir').catch(fail);

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
  await refreshState();
  applyTheme(state.theme);
  await Promise.all([loadLogs(), loadChains(), loadRoutes(), loadSettings()]);
  refreshState();
  setInterval(refreshState, 1500);
  clashCheck();   // 进界面就跑一次共存检测（失败不影响其他）
}

window.addEventListener('DOMContentLoaded', () => boot().catch(e => toast('初始化失败', String(e), 'error')));
