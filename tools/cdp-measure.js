// 用 CDP 在**真实时间**下测主题切换的同步耗时（headless 的 --virtual-time-budget
// 会把 performance.now() 和 CSS 动画时钟一起冻住，什么也测不出来）。
// 用法：先起 chrome --headless=new --remote-debugging-port=9223 <url>，再 node local/cdp-measure.js
const PORT = 9223;
const sleep = ms => new Promise(r => setTimeout(r, ms));

const MEASURE = `(async () => {
  const box = document.getElementById('logBox');
  const frag = document.createDocumentFragment();
  for (let i = 0; i < 4000; i++) {
    const d = document.createElement('div');
    d.className = 'log-line';
    d.textContent = '09:30:00.123  INFO  relay.done: chain=SITE-A target=192.0.2.217:443 proc=java.exe pid=6120 up=1741 down=11264';
    frag.appendChild(d);
  }
  box.appendChild(frag);
  const root = document.documentElement;
  const out = { nodes: document.getElementsByTagName('*').length, layoutMs: {}, paintMs: {} };
  const raf = () => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));

  async function probe(page) {
    showPage(page);
    await raf();
    // ① 旧写法：加类（整树 style 置脏）后强制一次同步布局 = 我们删掉的那句
    root.classList.add('theme-anim');
    let t = performance.now();
    void root.offsetWidth;
    out.layoutMs[page] = +(performance.now() - t).toFixed(1);
    root.classList.remove('theme-anim');
    void root.offsetWidth;
    // ② 新写法：加类 + 改主题（同一个任务，同步部分应接近 0），
    //    随后量“这一帧真正要做的全部工作”（样式重算 + 布局）
    await raf();
    t = performance.now();
    root.classList.add('theme-anim');
    root.setAttribute('data-theme', page === 'log' ? 'dark' : 'light');
    out.paintMs[page] = +(performance.now() - t).toFixed(1);
    t = performance.now();
    void root.offsetWidth;
    out.layoutMs[page + '-after'] = +(performance.now() - t).toFixed(1);
    await raf();
    root.classList.remove('theme-anim');
    await raf();
  }
  await probe('settings');   // 真实场景：在设置页点主题
  await probe('log');        // 对照：日志页可见时

  // ③ 现在实现下点击一次的真实同步耗时
  showPage('settings');
  await raf();
  const clicks = [];
  for (let k = 0; k < 3; k++) {
    await new Promise(r => setTimeout(r, 900));
    const btn = document.getElementById('btnTheme' + (k % 2 ? 'Dark' : 'Light'));
    const tc = performance.now();
    btn.click();
    clicks.push(+(performance.now() - tc).toFixed(1));
  }
  out.clickSyncMs = clicks;
  out.anim = root.classList.contains('theme-anim');

  // ④ 用户真正看到的东西：点击后逐帧采样页面底色（看开头有没有“死区”）
  root.setAttribute('data-theme', 'light');
  root.classList.remove('theme-anim');
  await new Promise(r => setTimeout(r, 900));
  const samples = [];
  const t0 = performance.now();
  document.getElementById('btnThemeDark').click();
  samples.push([0, getComputedStyle(document.body).backgroundColor]);
  await new Promise(resolve => {
    function tick() {
      const dt = performance.now() - t0;
      samples.push([+dt.toFixed(0), getComputedStyle(document.body).backgroundColor]);
      if (dt < 700) requestAnimationFrame(tick); else resolve();
    }
    requestAnimationFrame(tick);
  });
  out.samples = samples.filter((s, i) => i % 3 === 0 || i < 6);
  return JSON.stringify(out);
})()`;

(async () => {
  let targets = null;
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch('http://127.0.0.1:' + PORT + '/json/list');
      targets = await r.json();
      if (targets && targets.some(t => t.type === 'page' && String(t.url).startsWith('file:'))) break;
    } catch (e) { /* 还没起来 */ }
    await sleep(250);
  }
  const page = targets && targets.find(t => t.type === 'page' && String(t.url).startsWith('file:'));
  if (!page) { console.log('找不到页面目标'); process.exit(1); }

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise(r => { ws.onopen = r; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = e => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  };
  const send = (method, params) => new Promise(res => {
    const i = ++id;
    pending.set(i, res);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  const ev = async expr => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.result && r.result.exceptionDetails) {
      return 'EXC:' + JSON.stringify(r.result.exceptionDetails.exception && r.result.exceptionDetails.exception.description);
    }
    return r.result && r.result.result ? r.result.result.value : JSON.stringify(r);
  };

  const boot = await ev("new Promise(r=>{const t=setInterval(()=>{if(typeof showPage==='function'&&document.getElementById('logBox')){clearInterval(t);r('ready')}},100);setTimeout(()=>{clearInterval(t);r('timeout')},15000)})");
  console.log('boot=' + boot);
  console.log(await ev(MEASURE));
  ws.close();
})();
