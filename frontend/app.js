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
  t.appendChild(el('span', 'toast-bar')); // 倒计时进度条，让“它什么时候会消失”看得见
  host.appendChild(t);
  setTimeout(() => t.classList.add('is-out'), 4000);
  setTimeout(() => t.remove(), 4300);
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
  // 两段式滑块：滑块位置看容器上的 data-theme，文字选中态看按钮的 is-active
  const seg = document.getElementById('themeSeg');
  if (seg) seg.dataset.theme = state.theme;
  document.querySelectorAll('#themeSeg .seg2-btn').forEach(b =>
    b.classList.toggle('is-active', b.dataset.theme === state.theme));
}

// setTheme 直接指定主题（设置页里点哪一个就是哪一个），不再是“切换”。
async function setTheme(mode) {
  const next = mode === 'dark' ? 'dark' : 'light';
  if (next === state.theme) return;   // 点已选中的那个：什么都不做（不写盘）
  applyThemeSoft(next);               // 先本地切，界面立刻响应
  try { await call('SetTheme', next); } catch (e) { fail(e); }
}

// 切主题时让**整页颜色**淡过去，而不是所有颜色硬切一下。
//
// 做法：切换前给 <html> 挂 .theme-anim（CSS 里那份 560ms 色彩过渡），切完摘掉。
// 用临时类而不是常驻：常驻的话日常 hover/选中也会被拖到 560ms，反而发黏。
// 只动颜色、不动 transform —— 标签指示块与主题滑块自己的动画得以保留。
let themeAnimTimer = 0;
function applyThemeSoft(mode) {
  const root = document.documentElement;
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) { applyTheme(mode); return; }   // 系统要求减少动效：直接切
  root.classList.add('theme-anim');
  // 刻意**不做**强制回流（`void root.offsetWidth`）：transition 是拿「变化后的样式」
  // 判定要不要起动画的，所以同一个任务里加类 + 改色就够了；而那句会强制一次
  // **全页同步样式计算+布局**（日志页几千行时非常贵），反过来造成"点了半天才开始变"。
  applyTheme(mode);
  clearTimeout(themeAnimTimer);
  // 800ms > CSS 里的 560ms：过渡走完再摘类，否则最后一段会硬跳
  themeAnimTimer = setTimeout(() => root.classList.remove('theme-anim'), 800);
}

/* ═══════════════ 标签页 ═══════════════ */

// 顶部标签条的滑动指示块：跟着当前 tab 走（位置/宽度由 JS 量出来，不写死）。
//
// 位置走 transform（合成器上跑，不触发布局）；宽度只有切到不等宽的「诊断」才会变。
// opts.immediate = 直接落位、不滑动 —— 首次渲染、字体加载完、窗口尺寸变化时用，
// 否则会看到它从 0 滑过来 / 拖着一路动画。
function positionTabThumb(opts) {
  const nav = document.getElementById('tabs');
  if (!nav) return;
  const thumb = nav.querySelector('.tab-thumb');
  const active = nav.querySelector('.tab.is-active');
  if (!thumb || !active) return;
  const immediate = !!(opts && opts.immediate);
  if (immediate) {
    thumb.classList.add('no-anim');
    void thumb.offsetWidth;   // 强制回流：先让 no-anim 生效，这次改动才不会补动画
  }
  thumb.style.transform = 'translateX(' + active.offsetLeft + 'px)';
  thumb.style.width = active.offsetWidth + 'px';
  if (immediate) requestAnimationFrame(() => thumb.classList.remove('no-anim'));
}

function showPage(name) {
  // 选项卡 + 顶部栏里的「设置」（它不在 tab 组里，但用的是同一套切换）
  document.querySelectorAll('.tab, .tab-top').forEach(t =>
    t.classList.toggle('is-active', t.dataset.page === name));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('is-active', p.id === 'page-' + name));
  positionTabThumb();
  if (name === 'log') { scrollLogToEnd(); loadLogVerbose(); }
  if (name === 'conn') { loadConns(); loadCountDirect(); loadQuicBlock(); }
  if (name === 'diag') { precheckConfig(true); loadTargetHealth(); loadPatrol(); loadLastSelfTest(); }
}

/* ═══════════════ 规则智能：最具体优先 / 命中查询 ═══════════════ */

async function sortRoutes() {
  let changed = false;
  try {
    changed = await call('SortRoutes');
    await loadRoutes();
  } catch (e) { fail(e); return; }
  if (changed) {
    toast('已整理规则顺序', '具体的排前面（/32、带端口），本机自身 / 环回类放最后', 'success');
  } else {
    toast('顺序已经是最具体优先', '不需要调整', 'success');
  }
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
  // 这里不再自写一行“最近 N 份备份（…）”—— 卡片上已经有固定标签「最近三份备份:」了
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
    t.appendChild(emptyState(ICON_TARGET, '还没有可以巡检的目标', '等有内网连接之后，或点「立即巡检」。', null, null));
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
    t.appendChild(emptyState(ICON_LINK, '还没有连接', '命中规则的连接会实时出现在这里。', null, null));
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
  // 只读态：引擎锁被别的进程（服务版/另一实例）拿着 —— 本界面不跑引擎，只展示。
  // 两种引擎同时跑会各自改写到自己的 relay（静默互扰），所以宁可只读也不降级启动。
  const ro = !!s.readOnly;
  const rs = document.getElementById('runState');
  rs.classList.toggle('is-on', on);
  rs.classList.toggle('is-bad', bad && !ro);   // 只读不是故障：别同时挂 is-bad（琥珀会被红色盖掉）
  rs.classList.toggle('is-busy', ro);          // 琥珀色、不呼吸
  // 四态：Ready（绿，呼吸）/ Error（红，呼吸）/ 只读（琥珀，静止）/ 已停止（灰，静止）
  document.getElementById('runStateText').textContent =
    ro ? '只读' : (on ? 'Ready' : (bad ? 'Error' : '已停止'));
  // 出错原因平时不占位置，悬停能看；内部中转端口同样只在悬停里出现
  rs.title = ro
    ? (s.readOnlyWhy || '服务版正在运行') + ' —— 点「接管引擎」可切回界面版'
    : (bad ? s.error : ('内部中转端口 ' + (s.relay || '—') + '（实现细节，无需配置）'));
  // 只读态下别让用户去点会失败的东西：藏掉启动/停止、置灰重启，只留「接管引擎」
  document.getElementById('btnTakeover').style.display = ro ? '' : 'none';
  const tog = document.getElementById('btnToggle');
  tog.style.display = ro ? 'none' : '';
  tog.textContent = on ? '停止' : '启动';
  tog.className = on ? 'btn' : 'btn btn-primary';
  document.getElementById('btnRestart').disabled = ro;
  if (ro && !state.roNotified) {
    state.roNotified = true;
    toast('服务版正在运行', '界面以只读方式启动（不碰流量）；要由界面接管，点顶栏「接管引擎」', 'warn');
  } else if (!ro) {
    state.roNotified = false;
  }

  document.getElementById('stTotal').textContent = s.totalConns;
  document.getElementById('stActive').textContent = s.activeConns;

  document.getElementById('pathConfig').textContent = s.configPath || '-';
  document.getElementById('pathLog').textContent = s.logPath || '-';
  document.getElementById('hostsInfo').textContent =
    (s.hostsInFile ? '标记区块已存在' : '未写入标记区块') + ' · ' + (s.hostsPath || '');

  // 主题以后端为准（只在变化时同步，避免打断用户刚点的切换）
  if (s.theme && s.theme !== state.theme) applyTheme(s.theme);

  // 开机自启：状态由系统决定，回写勾选框（勾选状态就是唯一指示，不再另外写一行小字）
  const cbAuto = document.getElementById('setAutostart');
  if (!cbAuto.dataset.busy) {
    cbAuto.checked = !!s.autostart;
  }
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

  // 预热连接池近况（A11）：当前就绪几条、命中过多少次
  const wi = document.getElementById('warmInfo');
  if (wi) {
    try {
      const st = await call('GetState');
      wi.textContent = st.poolWarm > 0
        ? ('预热会话：就绪 ' + st.poolWarm + ' 条 · 已命中 ' + (st.poolHits || 0) + ' 次')
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
    const e = emptyState(ICON_CHAIN, '还没有链路', '点「添加链路」，或「从 gost .bat 导入」。', '添加链路', () => chainForm(null));
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

/* 行拖拽排序（规则/链路通用，自己实现不用 HTML5 draggable）。
   拖拽时**实时挤开**：浮动卡片跟手，原位置变成一个高亮空槽并随鼠标上下移动，
   松手瞬间恢复内容、再异步落库 —— 所以“落下”是即时的，不用等后端往返。
   按钮/开关/输入框上按下不触发；横向位移为主不启动。 */
function wireRowDrag(tableId, onMove) {
  const tableEl = document.getElementById(tableId);
  if (!tableEl) return;
  const rows = () => [...tableEl.children].filter(r => r.classList.contains('trow') && !r.classList.contains('thead'));
  let d = null; // { row, from, x0, y0, grabY, rowRect, ghost, started }

  const startGhost = () => {
    const g = d.row.cloneNode(true);
    g.classList.add('row-ghost');
    g.classList.remove('is-dragging');
    g.style.left = d.rowRect.left + 'px';
    g.style.top = d.rowRect.top + 'px';
    g.style.width = d.rowRect.width + 'px';
    g.style.height = d.rowRect.height + 'px';
    document.body.appendChild(g);
    d.ghost = g;
    d.row.classList.add('is-dragging'); // 原行内容隐藏、留出高亮空槽
    document.body.style.userSelect = 'none';
  };

  // 根据鼠标纵向位置把原行实时插到该去的位置（这一步就是“挤开上下卡片”）。
  // 用 FLIP 让被挤开的行平滑滑动，而不是瞬间跳过去。
  const preview = clientY => {
    const others = rows().filter(r => r !== d.row);
    let ref = null;
    for (const r of others) {
      const rect = r.getBoundingClientRect();
      if (clientY < rect.top + rect.height / 2) { ref = r; break; }
    }
    // 位置没变就别白做动画（否则每一帧都在重置 transform）
    if ((!ref && tableEl.lastElementChild === d.row) || (ref && d.row.nextElementSibling === ref)) return;

    const list = rows();
    const before = new Map(list.map(r => [r, r.getBoundingClientRect().top]));
    if (ref) tableEl.insertBefore(d.row, ref);
    else tableEl.appendChild(d.row);

    for (const r of list) {
      if (r === d.row) continue; // 被拖的行由浮动卡片代表，不参与滑动
      const was = before.get(r);
      const delta = was - r.getBoundingClientRect().top;
      if (!delta) continue;
      // FLIP：先无过渡地放到旧位置，强制回流，再带过渡回到 0
      r.style.transition = 'none';
      r.style.transform = 'translateY(' + delta + 'px)';
      void r.offsetHeight;
      r.style.transition = 'background var(--ease), transform .16s cubic-bezier(.2,.8,.2,1)';
      r.style.transform = '';
    }
  };

  const onMouseMove = e => {
    if (!d) return;
    const dy = e.clientY - d.y0;
    const dx = e.clientX - d.x0;
    if (!d.started) {
      if (Math.abs(dy) < 4) return;                        // 还没动够，先不启动
      if (Math.abs(dx) > Math.abs(dy)) { cleanup(); return; } // 横向为主 → 不是排序意图
      d.started = true;
      startGhost();
    }
    e.preventDefault();
    // 浮动卡片只上下动（left 固定），并夹在列表可视范围内
    const listRect = tableEl.getBoundingClientRect();
    const h = d.rowRect.height;
    const top = Math.max(listRect.top, Math.min(listRect.bottom - h, e.clientY - d.grabY));
    d.ghost.style.top = top + 'px';
    preview(e.clientY);
  };

  const cleanup = () => {
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
    document.body.style.userSelect = '';
    if (d) {
      if (d.ghost) d.ghost.remove();
      d.row.classList.remove('is-dragging'); // 内容立刻回来 = “马上落下”
      d.row.style.transition = '';
      d.row.style.transform = '';
    }
    d = null;
  };

  const onMouseUp = async () => {
    const drag = d;
    if (!drag) return;
    const row = drag.row;
    const from = drag.from;
    const started = drag.started;
    cleanup();
    if (!started) return;
    const to = rows().indexOf(row);
    if (from < 0 || to < 0 || to === from) return;
    await onMove(from, to); // 视觉已到位，这里只是落库 + 刷新序号
  };

  tableEl.addEventListener('mousedown', e => {
    if (e.button !== 0) return;
    const row = e.target.closest('.trow');
    if (!row || row.classList.contains('thead')) return;
    if (e.target.closest('button, input, textarea, select, a, .rule-switch')) return;
    const rect = row.getBoundingClientRect();
    d = { row, from: rows().indexOf(row), x0: e.clientX, y0: e.clientY,
          grabY: e.clientY - rect.top, rowRect: rect, ghost: null, started: false };
    e.preventDefault();
    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);
  });
}

/* ═══════════════ 空状态 ═══════════════ */

// 统一的空状态：淡图标 + 标题 + 一句说明 + 可选的引导按钮。
// 以前只有一行灰字，用户得自己猜到右上角去点“添加”。
// 图标是固定内嵌 SVG，不含任何用户数据（innerHTML 在这只是搬常量）。
function emptyState(icon, title, hint, actionLabel, actionFn) {
  const box = el('div', 'empty');
  const ic = el('div', 'empty-icon');
  ic.innerHTML = icon;
  box.appendChild(ic);
  box.appendChild(el('div', 'empty-title', title));
  if (hint) box.appendChild(el('div', 'empty-hint', hint));
  if (actionLabel && actionFn) box.appendChild(btn(actionLabel, 'btn btn-sm btn-primary', actionFn));
  return box;
}
const ICON_RULE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><circle cx="3.5" cy="6" r="1.4"/><circle cx="3.5" cy="12" r="1.4"/><circle cx="3.5" cy="18" r="1.4"/></svg>';
const ICON_CHAIN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 14.5 14.5 9.5"/><path d="M8 12 5.5 14.5a3.5 3.5 0 0 0 5 5L13 17"/><path d="M16 12 18.5 9.5a3.5 3.5 0 0 0-5-5L11 7"/></svg>';
const ICON_LINK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2.5-6 4 12L16 12h5"/></svg>';
const ICON_TARGET = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><line x1="12" y1="2" x2="12" y2="5"/><line x1="12" y1="19" x2="12" y2="22"/><line x1="2" y1="12" x2="5" y2="12"/><line x1="19" y1="12" x2="22" y2="12"/></svg>';

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
    credNote.textContent = '⚠ 上面就是完整地址（含账号口令）。保存后也以明文写在 config.yaml 里' +
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
        payload.name + '（' + payload.forwards.length + ' 条上游）' + await saveNote(), 'success');
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

/* 勾选行（弹窗里用）：返回 { node, input }，调用方拿 input.checked 取值。
   id 传了就挂上 —— 界面自检要靠它找到这个勾。 */
function checkField(checked, text, id) {
  const l = el('label', 'check');
  const cb = el('input');
  cb.type = 'checkbox';
  cb.checked = !!checked;
  if (id) cb.id = id;
  l.appendChild(cb);
  l.appendChild(el('span', null, text));
  return { node: l, input: cb };
}

/* 拖拽排序：把第 from 条移到第 to 条（绝对值，拖拽落点算出）。 */
async function moveChainTo(from, to) {
  try { await call('MoveChain', from, to); } catch (e) { fail(e); }
  await loadChains();
}

async function delChain(name) {
  if (!await confirmBox('删除链路', '确定删除链 ' + name + ' 吗？', true)) return;
  try { await call('DeleteChain', name); await loadChains(); toast('已删除链路', name + await saveNote(), 'success'); }
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
  ['#', '规则名', '目标 IP / CIDR', '走哪条链 / 直连', ''].forEach(h =>
    head.appendChild(el('div', 'cell', h)));
  t.appendChild(head);

  if (!routes.length) {
    t.appendChild(emptyState(ICON_RULE, '还没有规则', '把内网网段指到某条链；本机网段 / 局域网邻居选「直连」。', '添加规则', () => ruleForm(null)));
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

    // 规则名 + 链备注两行显示（原“说明”单独一列；合并后目标列能宽很多、视觉噪音更少）
    const nameCell = el('div', 'cell stack');
    nameCell.appendChild(el('div', 'name' + (r.name ? '' : ' dim'), r.name || '（未命名）'));
    if (r.note) nameCell.appendChild(el('div', 'sub', r.note));
    nameCell.title = [r.name || '（未命名）', r.note].filter(Boolean).join(' — ');
    row.appendChild(nameCell);

    row.appendChild(targetsCell(r.targets || [], r.ports || [], r.shadowed || [], r.localNets || [], r.inactive, r.apps || [], r.hostResolves || [], r.wildcards || []));
    const actCell = el('div', 'cell' + (r.direct || r.block ? ' dim' : ''));
    actCell.appendChild(el('span', null, actionLabel(r)));
    if (r.allowQuic) {
      const q = el('span', 'sub', '  不拦 QUIC');
      q.title = '这条规则的目标放行 QUIC：UDP 443 直连出去，不进过滤器（TCP 仍按本规则走）';
      actCell.appendChild(q);
    }
    row.appendChild(actCell);

    const acts = el('div', 'cell actions');
    acts.appendChild(btn('编辑', 'btn btn-xs', () => ruleForm(r.index)));
    acts.appendChild(btn('删除', 'btn btn-xs btn-danger', () => delRoute(r.index)));
    row.appendChild(acts);
    t.appendChild(row);
  });
}

/* 目标列：一条规则可以挂十几个目标，列表里只给摘要，全量放 title，悬停能看全。
   带端口条件时在末尾追一个暗淡的“· 端口 …”标签。 */
function targetsCell(list, ports, shadowed, localNets, inactive, apps, resolves, wildcards) {
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
  // 通配域名（*.his.com）/ 中间带星（db-*.his.com）：显示这条规则现在**真的在管什么**。
  //
  // 历史教训：一开始只看“学到了几个 IP”，接管路径（我们回假 IP）根本不产生真实 IP，
  // 于是一条正在干活的规则显示成“还没学到任何 IP”，看起来像坏的 —— 用户反馈过两次。
  // 现在以**接管过的名字**为主证据（那是它干活的直接记录），IP 只是补充。
  for (const w of (wildcards || [])) {
    const ips = w.ips || [];
    const names = w.names || [];
    const s = el('span', (ips.length || names.length) ? 'dim' : 'resolve-bad',
      ips.length ? '  → 已覆盖 ' + ips.length + ' 个 IP'
        : names.length ? '  ✓ 接管中 · 已管 ' + names.length + ' 个名字'
          : (w.takeover ? '  ✓ 接管中（还没命中过名字）' : '  ⚠ 还没学到任何 IP'));
    const nameList = names.slice(0, 12).join('\n') + (names.length > 12 ? '\n…（还有 ' + (names.length - 12) + ' 个）' : '');
    s.title = (ips.length || names.length)
      ? w.pattern + ' 现在：\n' +
        (names.length ? '接管的名字（命中即拦，会换回真实 IP 再走这条链）：\n' + nameList + '\n' : '') +
        (ips.length ? '已知真实 IP：\n' + ips.join('\n') + '\n' : '') +
        (w.updated && w.updated !== '—' ? '（最后一次更新：' + w.updated + ' 前）' : '')
      : w.takeover
        ? w.pattern + ' 正在接管：命中它的域名在 DNS 阶段就被回了假 IP（我们自己的地址），\n' +
          '连到假 IP 会被拦下、换回真实 IP 再走这条规则指定的链 —— 所以这条规则已经在工作。\n' +
          '现在写“还没命中过名字”只是指：本进程启动以来还没有名字落到这个模式上\n' +
          '（应用还没访问过，或它走的是加密 DNS）。第一次真访问之后这里会列出名字。'
        : w.pattern + ' 目前没匹配到任何 IP。\n原因：通配域名只能靠“观察应用自己的 DNS 应答”知道 IP，' +
          '还没看到任何名字落到这个模式上（应用还没访问过，或用了加密 DNS/DoH，那样我们看不见）。';
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

  // 档 2：这条规则的目标放行 QUIC（UDP 443 直连）。默认跟着全局阻断走。
  const quic = checkField(src.allowQuic, '这条规则的目标不拦 QUIC（UDP 443 直接出去）', 'ruleAllowQuic');

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
    field('QUIC（可选）', quic.node,
      '默认跟全局「QUIC 阻断」走：本该走链的目标，它的 UDP 443 会被拦下（UDP 不走隧道，不拦就是绕过隧道直连漏出）。' +
      '真碰到“只认 HTTP/3”的系统时勾这里 —— 只放它的 QUIC 直连，TCP 那条路仍按本规则走。' +
      '勾了之后这些目标不进 UDP 侧过滤器，一个包也不收回用户态。'),
  ];

  modal.open(isNew ? '添加规则' : '编辑规则', nodes, async () => {
    try {
      if (isNew) await call('SaveRoute', -1, {
        name: name.value, targets: targets.value, chain: sel.value,
        ports: ports.value, localNets: localNets.value, apps: apps.value,
        allowQuic: quic.input.checked,
      });
      else await call('SaveRoute', index, {
        name: name.value, targets: targets.value, chain: sel.value,
        ports: ports.value, localNets: localNets.value, apps: apps.value,
        allowQuic: quic.input.checked,
      });
      modal.close();
      await loadRoutes();
      toast(isNew ? '已添加规则' : '已更新规则',
        (name.value.trim() || '未命名') + '：' + splitTargets(targets.value).length + ' 个目标' +
        (splitTargets(ports.value).length ? '，端口 ' + ports.value.trim() : '') +
        (splitTargets(apps.value).length ? '，仅 ' + apps.value.trim().replace(/\s+/g, ' ') + ' 发起' : '') +
        (quic.input.checked ? '，它的 QUIC 直连' : '') +
        ' → ' +
        actionName(sel.value) +
        (splitTargets(localNets.value).length ? '（仅限本机在 ' + localNets.value.trim().replace(/\s+/g, ' ') + ' 时）' : '') +
        await saveNote(),
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

async function moveRouteTo(from, to) {
  try { await call('MoveRoute', from, to); } catch (e) { fail(e); }
  await loadRoutes();
}

async function delRoute(i) {
  const r = routes.find(x => x.index === i);
  const ts = r.targets || [];
  const desc = r.name ? '「' + r.name + '」' : (ts.length > 1 ? ts.length + ' 个目标' : ts[0]);
  if (!await confirmBox('删除规则',
      '确定删除规则 ' + desc + '（' + ts.length + ' 个目标' +
      ((r.ports && r.ports.length) ? '，端口 ' + r.ports.join(',') : '') + ' → ' +
      actionName(r.block ? 'block' : r.direct ? 'direct' : r.chain) + '）吗？', true)) return;
  try { await call('DeleteRoute', i); await loadRoutes(); toast('已删除规则', desc + await saveNote(), 'success'); }
  catch (e) { fail(e); }
}

/* ═══════════════ Clash 共存检测 ═══════════════ */

/* 常驻告警条：把"内网可能被 Clash 接管"这种问题从日志提到界面上。
   它不自动消失 —— 只有检测结果变成 OK 才隐。这样即使人当时不在电脑前，回来也能看到。
   右边的 × 可以关掉；关掉只对本次运行有效（按标题记，条件恢复后自动忘掉）。 */
const noticeDismissed = new Set();
function noticeBar(kind, title, text, actionLabel, actionFn) {
  const bar = document.getElementById('noticeBar');
  if (!kind) {
    noticeDismissed.clear();   // 问题没了 → 忘掉之前关过的，下次再出还会提示
    bar.replaceChildren();
    bar.hidden = true;
    return;
  }
  if (noticeDismissed.has(title)) { bar.hidden = true; return; }
  bar.replaceChildren();
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
  const close = btn('×', 'nb-close', () => {
    noticeDismissed.add(title);
    bar.replaceChildren();
    bar.hidden = true;
  });
  close.setAttribute('aria-label', '关闭');
  close.title = '关闭（本次运行内不再提示）';
  bar.appendChild(close);
}

/* 内网被交给别的代理会出问题（DNS 外泄/封号），所以用它驱动常驻横幅。 */
function updateClashBar(v) {
  if (!v) { noticeBar(null); return; }
  if (v.coverage && v.coverage.ok === false && (v.coverage.missed || []).length) {
    const missed = v.coverage.missed;
    noticeBar('error', '内网可能被其他代理接管',
      missed.length + ' 个目标不在系统代理的绕过列表里：' + missed.slice(0, 4).join('; ') +
        (missed.length > 4 ? ' 等' : '') +
        '　—— 这几个不在系统代理的绕过列表里，按域名访问内网时可能先交给它（它用自己的 DNS 解析，内网域名有出内网的风险）',
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
    const missed = v.coverage.missed || [];
    const hit = v.coverage.checked.length - missed.length;
    const c = el('div', 'hint');
    c.textContent = '绕过覆盖：' + hit + '/' + v.coverage.checked.length + ' 命中（下列目标逐个核对过）';
    c.className = hit === v.coverage.checked.length ? 'hint' : 'hint clash-no';
    det.appendChild(c);

    // 检测什么就显示什么：把**实际核对过的每一个目标**列出来（不列的话，
    // 加了网段而数字没变，会让人以为这项检测是写死的）。默认收起，点一下展开。
    const box = el('details', 'clash-cov');
    const sum = el('summary', 'hint');
    sum.textContent = '查看核对明细（' + v.coverage.checked.length + ' 项）';
    box.appendChild(sum);
    const tbl = el('div', 'clash-table');
    ['核对目标', '绕过列表', '判定'].forEach(h => tbl.appendChild(el('div', null, h)));
    const missSet = new Set(missed);
    v.coverage.checked.forEach(t0 => {
      const bad = missSet.has(t0);
      tbl.appendChild(el('div', 'mono', t0));
      tbl.appendChild(el('div', bad ? 'clash-no' : null, bad ? '✗ 没命中' : '✓ 命中'));
      tbl.appendChild(el('div', bad ? 'clash-no' : 'clash-ok',
        bad ? '会被交给 Clash（内网有外泄风险）' : '不会进代理'));
    });
    box.appendChild(tbl);
    det.appendChild(box);
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
  setChecked('setLogVerbose', s.logVerbose);
  setValue('setHostsEntries', (s.hostsEntries || []).join('\n'));
  loadAbout();
  setValue('setDialTimeout', s.dialTimeout || 5);
  setValue('setDialBudget', s.dialBudget || 10);
  setValue('setRaceAfter', s.raceAfter === 0 ? 0 : (s.raceAfter || 300));
  setValue('setWarm', s.warmSessions === 0 ? 0 : (s.warmSessions || 2));
  setValue('setAutoDelay', s.autostartDelay === 0 ? 0 : (s.autostartDelay || 20));
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
      '「预热会话」= 每条上游提前建立几条“已握手、只差 CONNECT”的会话，业务来了不用等握手；0 = 关闭（不预热）。',
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
      '【前提】只有对方也跑在【系统代理模式】时才能共存：应用把域名交给代理端口，我们按 IP 段各自分流，互不打扰。',
      'PAC 模式不行：PAC 是让应用自己决定直连还是走代理，它会把内网请求也交给代理，我们抢不回来。',
      'TUN 模式更不行：TUN 会把全机流量与 DNS 一起抓走（Clash 的 tun 配置里就写着 dns-hijack: any:53、auto-route: true），那时 NetHub 的透明接管会失效 —— 两者只能二选一。',
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
  rule: {
    title: '目标写 IP 还是写域名？通配域名靠什么匹配',
    paras: [
      'IP / CIDR：最好懂 —— 包里就是 IP，写到哪拦到哪，不依赖任何解析。',
      'IP 通配（10.100.100.*）：写法是整段（等于 /24），方便照搬 Proxifier 里已有的规则。',
      '域名（main.his.com）：启动时以及每 5 分钟解析一次，拿解析到的 IP 去匹配；解析到 IP 后会把它交给上游去解析（内网域名往往只有客户网内的 DNS 才解得开）。',
      '解析不到的域名规则：什么都不拦（不猜、也不退化成拦全部），日志与规则页都会标出来。',
      '通配域名（*.his.com）：不包含 his.com 本身，包含任意层级（a.b.his.com 也算），大小写不敏感。',
      '通配域名没法提前解析，只能靠“观察应用自己的 DNS 应答”知道名字→IP；所以我们只读嗅探 DNS（不改任何包）。',
      'DNS 接管（默认开）是更稳的那条路：命中通配规则的名字，我们在 DNS 阶段就回一个假 IP 拦下来，\n连上来时再换回真实 IP —— 名字在连接之前就到手了，不依赖嗅探。',
      '规则页的“已覆盖 N 个 IP”来自观察结果；显示“接管中（还没学到 IP）”表示这条规则已经在工作，\n只是那些名字的真实 IP 还没被记录下来（第一次连上之后就有了）。',
      '接管关掉时“还没学到任何 IP”才是真的什么都不拦。',
      '观察不到的情形：应用用了加密 DNS（DoH/DoT）、或自己实现了解析器 → 那时靠嗅探的通配规则不生效\n（接管开着的话仍然生效）。',
      '一个 IP 被多个域名共用时：命中任一匹配的名字即可（同一个 IP 属于通配覆盖范围就算命中）。',
      '想要“更稳”的写法：把关键内网域名同时写一条具体域名规则，不依赖观察。',
      '另外：TCP 7680（Windows 更新传递优化）是内置直连的，不需要在规则里写 —— 它在客户内网里不该进隧道。',
      '要关掉这个内置行为：config.yaml 的 tuning 下加 builtin_direct_disabled: true。',
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

async function saveSettings() {
  const elEntries = document.getElementById('setHostsEntries');
  const elManage = document.getElementById('setHostsManage');
  const payload = {
    hostsManage: !!(elManage && elManage.checked),
    hostsEntries: elEntries ? elEntries.value.split('\n').map(s => s.trim()).filter(Boolean) : [],
    theme: state.theme,
    dialTimeout: intVal('setDialTimeout', 5),
    dialBudget: intVal('setDialBudget', 10),
    // 启动延迟允许 0（= 登录后立即启动），所以单独处理
    autostartDelay: (function () {
      const e = document.getElementById('setAutoDelay');
      const n = e ? parseInt(e.value, 10) : NaN;
      return Number.isFinite(n) && n >= 0 ? Math.min(n, 600) : 20;
    })(),
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
    toast('设置已保存', '主机 hosts、中转端口、DNS 接管的改动需要重启才生效' + await saveNote(), 'success');
  } catch (e) { fail(e); }
}

// 恢复设置：把设置页上的每一项都填回内置默认值并落盘。
//
// 与「重置」（上游拨号卡里那个，只把 4 个输入框填回默认、要再点保存）不同，
// 这个是**整页**的，而且**直接生效** —— 所以先弹确认框把会变的东西列出来，
// 尤其写明“会取消开机自启”（那会删掉计划任务，属于系统级副作用）。
async function resetSettings() {
  const ok = await confirmBox('恢复默认设置？',
    '会把这页的设置改回默认并立即生效：\n' +
    '· 取消开机自启（删除「计划任务 NetHub」）\n' +
    '· 启动延迟 → 20 秒\n' +
    '· 主题 → 浅色\n' +
    '· hosts 接管 → 关闭，映射条目 → 内置默认\n' +
    '· 上游拨号 → 单次 5 秒 / 总预算 10 秒 / 竞速 300 毫秒 / 预热 2 条\n' +
    '\n链路与路由规则不受影响。', false, '恢复默认');
  if (!ok) return;

  setChecked('setAutostart', false);
  setValue('setAutoDelay', 20);
  setChecked('setHostsManage', false);
  setValue('setHostsEntries', '');
  setValue('setDialTimeout', 5);
  setValue('setDialBudget', 10);
  setValue('setRaceAfter', 300);
  setValue('setWarm', 2);
  applyThemeSoft('light');

  const cbAuto = document.getElementById('setAutostart');
  cbAuto.dataset.busy = '1';            // 别让状态轮询把刚写下的值又按系统状态改回去
  try {
    await call('SetAutostart', false);
    await call('SetTheme', 'light');
    await call('SaveSettings', {
      hostsManage: false, hostsEntries: [], theme: 'light',
      dialTimeout: 5, dialBudget: 10, raceAfter: 300, warmSessions: 2, autostartDelay: 20,
    });
    await loadSettings();               // 条目回落成内置默认（后端在空列表时才给默认）
    toast('已恢复默认设置', '已立即生效（hosts 与中转端口的改动需重启）' + await saveNote(), 'success');
  } catch (e) {
    fail(e);
  } finally {
    delete cbAuto.dataset.busy;
    refreshState();
  }
}

/* ═══════════════ 启动 ═══════════════ */

function wire() {
  // 窗口按钮
  document.getElementById('winMin').onclick = () => R().WindowMinimise();
  document.getElementById('winMax').onclick = () => R().WindowToggleMaximise();
  document.getElementById('winClose').onclick = () => call('HideToTray').catch(() => R().WindowHide());

  // 标签
  document.querySelectorAll('.tab').forEach(t => t.onclick = () => showPage(t.dataset.page));
  window.addEventListener('resize', () => positionTabThumb({ immediate: true }));
  positionTabThumb({ immediate: true });
  // 字体度量定下来后重新量一次（落位，不滑）：否则指示块可能停在旧宽度上
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(() => positionTabThumb({ immediate: true }));
  }
  wireRowDrag('ruleTable', moveRouteTo);
  wireRowDrag('chainTable', moveChainTo);
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
  document.getElementById('themeSeg').addEventListener('click', ev => {
    const b = ev.target.closest('[data-theme]');
    if (b) setTheme(b.dataset.theme);
  });

  // 日志页
  document.getElementById('btnClearLog').onclick = () => {
    document.getElementById('logBox').replaceChildren();
  };
  document.getElementById('btnOpenLog').onclick = () => call('OpenLogDir').catch(fail);
  // 详细日志（Normal / Verbose）：只影响之后写下的行，不碰过滤器、不重启
  async function loadLogVerbose() {
    const cb = document.getElementById('setLogVerbose');
    if (!cb) return;
    try {
      const s = await call('GetSettings');
      if (s) cb.checked = !!s.logVerbose;
    } catch (e) { /* 读不到就维持现状，不打断日志页 */ }
  }
  const cbVerbose = document.getElementById('setLogVerbose');
  if (cbVerbose) cbVerbose.onchange = async (ev) => {
    try {
      await call('SetLogVerbose', ev.target.checked);
      toast(ev.target.checked ? '已打开详细日志' : '已回到精简日志',
        ev.target.checked
          ? '之后会多记：每个直连目标、学到的域名、探测过程等'
          : '只写连接、启停、状态变化与错误',
        'success');
      await loadLogVerbose();
    } catch (e) { fail(e); }
  };
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
  bind('btnHelpRule', 'rule');

  // 连接页
  document.getElementById('btnConnRefresh').onclick = () => loadConns();
  document.getElementById('setCountDirect').onchange = async (ev) => {
    try {
      await call('SetCountDirect', ev.target.checked);
      toast('已保存', (ev.target.checked ? '直连流量从现在起也会被统计' : '直连流量不再经过我们（零开销）') + await saveNote(), 'success');
      await loadCountDirect();
    } catch (e) { fail(e); ev.target.checked = !ev.target.checked; }
  };
  document.getElementById('setQuicBlock').onchange = async (ev) => {
    try {
      await call('SetQuicBlock', ev.target.checked);
      toast('已保存', (ev.target.checked
        ? '本该走隧道的 QUIC 会被拦下（浏览器回落到 TCP，那条路仍走隧道）'
        : 'QUIC 不再经过我们（这部分流量会直接出去）') + await saveNote(), 'success');
      await loadQuicBlock();
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
  // UDP 能力探测（档 1b）：只在点的时候跑（每条链一次探测，最多 4 秒）
  const btnUdpProbe = document.getElementById('btnUdpProbe');
  if (btnUdpProbe) btnUdpProbe.onclick = async () => {
    const out = document.getElementById('udpProbeOut');
    if (out) out.textContent = '正在探测…（逐条链问一次上游，最多 4 秒）';
    try {
      const lines = await call('ProbeUDPRelay');
      if (out) out.textContent = (lines || []).join('\n');
      pushLog({ time: now(), level: 'INFO', text: 'UDP 能力探测完成' });
    } catch (e) {
      if (out) out.textContent = '探测失败：' + ((e && e.message) || e);
    }
  };
  const btnUdpCopy = document.getElementById('btnUdpCopy');
  if (btnUdpCopy) btnUdpCopy.onclick = async () => {
    const out = document.getElementById('udpProbeOut');
    const txt = ((out && out.textContent) || '').trim();
    if (!txt || txt.indexOf('正在探测') === 0) { toast('还没有探测结果', '点一下「开始探测」', 'info'); return; }
    try { await navigator.clipboard.writeText(txt); toast('已复制', '探测结果已复制到剪贴板', 'success'); }
    catch { toast('复制失败', '手动选中上面的文本复制即可', 'warn'); }
  };
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
  document.getElementById('btnTakeover').onclick = async () => {
    if (!await confirmBox('由界面版接管引擎？',
        '会停掉正在运行的 Windows 服务版，然后把引擎交回界面版：\n' +
        '· 服务注册保留（不卸载）—— 下次开机它仍会自己跑\n' +
        '· 停机期间有几百毫秒空窗，TCP 会重传\n' +
        '\n如果你要的是“以后都别再让服务版自己跑”，请用「卸载服务」。', false, '接管')) return;
    try {
      const msg = await call('TakeoverEngine');
      toast('已接管引擎', msg || '', 'success');
    } catch (e) { fail(e); }
    await loadService();
  };
  document.getElementById('btnSvcStart').onclick = async () => {
    if (!await confirmBox('交棒给服务版？',
        '把引擎交给 Windows 服务版（无人登录也能跑）：\n' +
        '· 先停界面版引擎（几百毫秒空窗，TCP 会重传）\n' +
        '· 再启动服务；服务真的跑起来后，界面版会自己退出（托盘图标一并移除）\n' +
        '· 之后再开界面，它会以只读方式启动 —— 点顶栏「接管引擎」可随时抢回来\n' +
        '\n服务没起来的话，界面版会自动把引擎恢复回去。', false, '交棒')) return;
    try {
      const msg = await call('StartServiceHandOver');
      toast('已交棒给服务版', msg || '', 'success');
    } catch (e) { fail(e); }
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
  document.getElementById('btnSaveSettings').onclick = () => saveSettings();
  document.getElementById('btnResetSettings').onclick = () => resetSettings();
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
      // 不用 intVal：它把 0 当成“没填”回落成 20，而 0 在这里是合法值（立即启动）
      const raw = parseInt((document.getElementById('setAutoDelay') || {}).value, 10);
      const sec = Number.isFinite(raw) && raw >= 0 ? raw : 20;
      toast(cbAuto.checked ? '已设置开机自启' : '已取消开机自启',
            cbAuto.checked ? (sec > 0 ? '下次登录后延迟 ' + sec + ' 秒静默启动，不弹 UAC'
                                      : '下次登录后立即静默启动，不弹 UAC') : '', 'success');
    } catch (e) {
      cbAuto.checked = !cbAuto.checked;    // 回滚
      fail(e);
    } finally {
      delete cbAuto.dataset.busy;
      refreshState();
    }
  };

  // 模态框
  document.getElementById('modalOk').onclick = () => {
    // 没给回调（比如纯说明类的「i」弹窗）= 点「确定」就是关闭。
    // 以前这里直接调用 modal.onOk（null）→ 按钮看起来没反应。
    if (modal.onOk) { modal.onOk(); } else { modal.close(); }
  };
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
    if (p && p.classList.contains('is-active')) { loadConns(); loadQuicBlock(); }
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

// saveNote 保存成功后问一句后端的“附加说明”：哪些改动热生效了、哪些还得重启。
// 由后端统一算（见 App.RestartRequired）—— 前端不在本地再判一遍，否则两边必然漂移。
async function saveNote() {
  try {
    const s = await call('LastApplyHint');
    return s ? '　' + s : '';
  } catch (e) { return ''; }
}

/* QUIC 阻断开关 */
async function loadQuicBlock() {
  const cb = document.getElementById('setQuicBlock');
  if (!cb) return;
  let v = null;
  try { v = await call('GetQuicBlock'); } catch (e) { return; }
  if (!v) return;
  cb.checked = !!v.on;
  const info = document.getElementById('quicBlockInfo');
  if (info) {
    // 档 1a：光看开关看不到“到底拦了什么” —— 把包数与最近目标一并摆出来，
    // 现场某个业务不通时一眼能看出“是我拦的”（而不是去翻日志）。
    let seen = '还没拦到过';
    if (v.blocked) {
      seen = '已拦 ' + v.blocked + ' 个包';
      if (v.recent && v.recent.length) seen += '（最近：' + v.recent.join('、') + '）';
    }
    info.textContent = (v.on
      ? '当前：开。本该走隧道的 UDP 443 会被拦下并记一行 quic.block（不再直连漏出）。'
      : '当前：关。QUIC 流量不经过我们（这些目标上的 HTTP/3 会直连出去）。') + ' ' + seen + '。';
  }
}

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
    // 两条规则同名是允许的（不同链表、或照搬别人的配置）—— 但只显示名字时，
    // 看起来会像“一条规则跟自己冲突”，所以同名时把序号和提示都说出来。
    if ((o.earlierName || '') === (o.laterName || '') && o.earlierName) {
      c1.appendChild(el('span', 'dim', '  （两条同名，是第 ' + o.earlier + ' 条和第 ' + o.later + ' 条两条不同的规则）'));
    }
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

/* 上游拨号：重置（只回填输入框。保存仍由用户决定 —— 不在用户没点保存时动线上服务） */
function resetDialDefaults() {
  setValue('setDialTimeout', 5);
  setValue('setDialBudget', 10);
  setValue('setRaceAfter', 300);
  setValue('setWarm', 2);
  toast('已填回默认值', '单次 5s / 总预算 10s / 竞速起跑 300ms / 预热 2 条。点「保存设置」才生效。', 'success');
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
