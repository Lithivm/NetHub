// 截图用的假数据 —— 只为渲染一张"干净的"界面图，不含任何真实环境信息。
// 用法：把这段注入 frontend/index.html 的 <script src="app.js"></script> 之前。
(function () {
  const LOG = [
    ['09:20:11.041', 'INFO', 'NetHub 启动，配置 C:\\NetHub\\config.yaml'],
    ['09:20:11.058', 'INFO', '配置载入：2 条链，2 条规则'],
    ['09:20:11.203', 'INFO', '托盘: 托盘图标已注册'],
    ['09:20:13.887', 'INFO', '界面已就绪'],
    ['09:20:14.002', 'INFO', '开始自动启动服务…'],
    ['09:20:14.004', 'INFO', '内核过滤器: (outbound and tcp and ((ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.0.0.255) or (ip.DstAddr >= 10.0.1.0 and ip.DstAddr <= 10.0.1.255) or (ip.DstAddr >= 192.168.100.0 and ip.DstAddr <= 192.168.100.255)))'],
    ['09:20:14.115', 'INFO', '✓ 拦截已启动：relay=127.0.0.1:58123，规则 2 条'],
    ['09:20:14.116', 'INFO', '    本地网段直连：192.168.199.0/24  →  直连（不走代理）'],
    ['09:20:14.116', 'INFO', '    内网 A 段：10.0.0.0/24, 10.0.1.0/24  →  链 proxy-a'],
    ['09:20:14.117', 'INFO', '    内网 B 段：192.168.100.0/24  →  链 proxy-b'],
    ['09:20:14.116', 'INFO', '✓ 服务已就绪：已接管 2 条规则，relay 127.0.0.1:58123'],
    ['09:20:21.330', 'INFO', '[直连] 192.168.199.77:445  不走代理'],
    ['09:20:21.441', 'INFO', '[proxy-a] 拦截 10.0.0.10:443  → relay'],
    ['09:20:21.441', 'INFO', '[proxy-a] 已接管 10.0.0.10:443  (来源端口 51422)'],
    ['09:20:22.918', 'INFO', '[proxy-b] 拦截 192.168.100.10:5432  → relay'],
    ['09:20:23.024', 'INFO', '[proxy-b] 已接管 192.168.100.10:5432  (来源端口 51437)'],
    ['09:20:31.507', 'INFO', '[proxy-a] 连接结束 10.0.0.10:443   ↑ 12.4 KB  ↓ 88.1 KB'],
  ];
  const CHAINS = [
    { name: 'proxy-a', forward: 'socks5+tls://your-host-a:10080?auth=***', forwards: ['socks5+tls://your-host-a:10080?auth=***'], strategy: 'failover', probe: '30s', note: '内网 A 段（10.0.0.* / 10.0.1.*）' },
    { name: 'proxy-b', forward: 'socks5+tls://your-host-b1:33001?auth=***', forwards: ['socks5+tls://your-host-b1:33001?auth=***', 'socks5+tls://your-host-b2:33001?auth=***'], strategy: 'round', probe: '30s', note: '内网 B 段（192.168.100.*），两条上游轮询' },
  ];
  const HEALTH = [
    { name: 'proxy-a', strategy: 'failover', probe: '30s', upstreams: [
      { url: 'socks5+tls://your-host-a:10080（带凭据）', known: true, ok: true, latency: '38 ms', checked: '16:25:04', error: '' }] },
    { name: 'proxy-b', strategy: 'round', probe: '30s', upstreams: [
      { url: 'socks5+tls://your-host-b1:33001（带凭据）', known: true, ok: true, latency: '12 ms', checked: '16:25:04', error: '' },
      { url: 'socks5+tls://your-host-b2:33001（带凭据）', known: true, ok: false, latency: '', checked: '16:25:04', error: '连不上 your-host-b2:33001' }] },
  ];
  // 顶栏流量图用的假序列：先填半窗（空曲线看截图没意义，也测不出右对齐），
  // 之后每次 GetTraffic 再推一格 —— 门禁靠它断言“新样本把画布真画动了”。
  const mockTrafficPts = [];
  for (let i = 0; i < 38; i++) {
    const burst = (i > 12 && i < 20) || (i > 28 && i < 31) ? 1 : 0;
    mockTrafficPts.push({
      tunUp: 9000 + (i % 7) * 4200 + burst * 30000,
      tunDown: 40000 + (i % 11) * 26000 + burst * 240000,
      dirUp: 32000,
      dirDown: 180000,
    });
  }
  const ROUTES = [
    { index: 0, enabled: true, name: '本地网段直连', targets: ['192.168.199.0/24'], ports: [], chain: 'direct', direct: true, note: '不走代理，直接连（本机网段 / 局域网邻居常用）' },
    { index: 0, enabled: true, name: '按域名走', targets: ['main.example.com', 'opm.example.com'], ports: [], chain: 'proxy-a', note: CHAINS[0].note, hostResolves: [ { host: 'main.example.com', ips: ['192.0.2.217'], age: '2m0s', stale: false, failed: false, lastErr: '' }, { host: 'opm.example.com', ips: [], age: '', stale: false, failed: true, lastErr: 'lookup opm.example.com: no such host' } ] },
    { index: 1, enabled: true, name: "排除更新端口", targets: ["203.0.113.0/24"], ports: ["7680"], chain: "direct", direct: true, note: "不走代理，直接连（本机网段 / 局域网邻居常用）", shadowed: ["203.0.113.0/24"] },
    { index: 2, enabled: true, name: '内网 A 段', targets: ['10.0.0.0/24', '10.0.1.0/24'], ports: ['443', '5432', '8000-9000'], chain: 'proxy-a', note: CHAINS[0].note },
    { index: 3, enabled: false, name: '内网 B 段', targets: ['192.168.100.0/24'], chain: 'proxy-b', note: CHAINS[1].note },
    { index: 4, enabled: true, name: '内网 C 段', targets: ['172.16.8.0/24'], chain: 'proxy-a', note: CHAINS[0].note },
    { index: 5, enabled: true, name: '数据库段', targets: ['10.0.2.0/24', '10.0.2.16/32', '10.0.2.18/32'], chain: 'proxy-b', note: CHAINS[1].note },
    { index: 6, enabled: false, name: '监控与日志', targets: ['192.168.50.0/24'], chain: 'proxy-b', note: CHAINS[1].note },
    { index: 7, enabled: true, name: '单点主机（只吃 H3 的系统）', targets: ['172.16.9.21/32', '172.16.9.35/32'], chain: 'proxy-a', note: CHAINS[0].note, allowQuic: true },
  ];
  const STATE = {
    poolWarm: 3, poolHits: 12,
    running: true, relay: '127.0.0.1:58123', totalConns: 1284, activeConns: 7,
    configPath: 'C:\\NetHub\\config.yaml', logPath: 'C:\\NetHub\\nethub.log',
    theme: 'light', hostsPath: 'C:\\Windows\\System32\\drivers\\etc\\hosts', hostsInFile: false,
    autostart: true, autoDetail: '计划任务 NetHub（已启用）',
    driverBlocked: false, driverPath: 'C:\\NetHub\\WinDivert64.sys',
  };
  const SETTINGS = { hostsManage: false, hostsEntries: ['10.0.0.10 app.example.com'], theme: 'light', dialTimeout: 5, dialBudget: 10, logLevel: 'normal', countDirect: false };
  const SERVICE_STATE = { state: 'not installed', installed: false, known: true, elevated: true, autoStart: false, autoStartKnown: true };
  const CLASH = {
    allCorrect: true, publicOk: true, mode: 'none',
    headline: '系统代理未开启 —— 没有泄漏面。',
    verdict: '内网数据全部走我们自己的隧道。',
    hosts: [
      { host: 'app.example.com', correct: true, reachable: true, kind: 'HTTP 200' },
      { host: '10.0.0.10', correct: true, reachable: true, kind: 'TCP 443' },
    ],
    coverage: { checked: ['app.example.com', '10.0.0.1', '192.168.100.1'], missed: [] },
  };
  const M = {
    // 告警内容由**后端**决定（GetState.notices）→ 前端只渲染。
    // 用 __mockNotices 模拟后端的输出（形状与 webui/notices.go 的 Notice 一致）。
    // __mockState 让测试夹具临时改 state 字段（例如模拟"启动中"）；平时是 undefined，行为不变。
    GetState: () => Object.assign({}, STATE, window.__mockState || {}, { notices: window.__mockNotices || [] }), GetChains: () => CHAINS, GetRoutes: () => ROUTES,
    GetLogs: () => LOG.map(([time, level, text]) => ({ time, level, text })),
    GetSettings: () => SETTINGS, ClashCheck: () => CLASH,
    // 链路页的“探测中”状态（window.__mockProbing = true 时）：proxy-a 变成
    // “从没探到过 + 正在探”—— 这正是用户报的那个瞬间（切进来看到的是灰点，
    // 1~2 秒后自己变成 38 ms，于是不知道要不要手点）。
    GetChainHealth: () => HEALTH.map(h => (window.__mockProbing && h.name === 'proxy-a')
      ? { ...h, probing: true,
          upstreams: h.upstreams.map(u => ({ ...u, known: false, ok: false, latency: '', checked: '', error: '' })) }
      : h),
    ProbeChains: () => null,
    // 告警条测试用：默认不报问题（截图要干净）；探针把 window.__mockClashMissed 置 true 就能测那条横幅。
    ClashCoverage: () => (window.__mockClashMissed
      ? { ok: false, missed: ['10.0.0.1', 'app.example.com', '192.168.100.1'], checked: ['app.example.com', '10.0.0.1', '192.168.100.1'] }
      : { ok: true, missed: [], checked: ['app.example.com', '10.0.0.1', '192.168.100.1'] }),
    GetService: () => SERVICE_STATE,
    SimulateTargets: () => ({
      summary: '共 2 项输入、5 条连接：链 proxy-a 3，链 proxy-b 1，直连（不走代理） 1',
      counts: [{ action: '链 proxy-a', n: 3 }, { action: '链 proxy-b', n: 1 }, { action: '直连（不走代理）', n: 1 }],
      hints: [
        '不跟重定向、不做 TLS 握手 —— 这里判的是浏览器发出的第一条连接',
        '名字按「先查 hosts、再查本机 DNS」解析；本工具只做 IPv4（AAAA 会被答空，所以浏览器不会走 IPv6）',
        '未写协议时，浏览器先试 http 还是 https 取决于它的 HTTPS-First 与 HSTS，我们不去猜 —— 两个端口都列出来了',
        '浏览器可能先试 QUIC（UDP 443），它会被拦下并回落到这里列的 TCP 连接（除非该规则勾了「不拦 QUIC」）',
      ],
      rows: [
        { input: 'http://main.example.com/', host: '192.0.2.217', port: 80, source: 'hosts 条目', ok: true, rule: '示例链路 A', ruleNo: 1, action: '链 proxy-a', chain: 'proxy-a' },
        { input: 'http://main.example.com/', host: '192.0.2.218', port: 80, source: 'hosts 条目', ok: true, rule: '示例链路 A', ruleNo: 1, action: '链 proxy-a', chain: 'proxy-a', note: '同一域名解析到多个地址，浏览器会同时试' },
        { input: 'main.example.com', host: '192.0.2.217', port: 443, source: 'hosts 条目', ok: true, rule: '示例链路 A', ruleNo: 1, action: '链 proxy-a', chain: 'proxy-a', note: '未写协议：浏览器先试哪个取决于 HTTPS-First/HSTS' },
        { input: 'main.example.com', host: '192.0.2.217', port: 80, source: 'hosts 条目', ok: true, rule: '示例链路 A', ruleNo: 1, action: '链 proxy-a', chain: 'proxy-a' },
        { input: 'https://no-such-host.example.com/', host: 'no-such-host.example.com', port: 443, source: '仅域名', ok: true, rule: 'site-b 链路', ruleNo: 2, action: '链 proxy-b', chain: 'proxy-b', note: '本机解析不到真实地址 —— 实际连接由上游解析' },
        { input: '10.0.0.0/24', host: '10.0.0.0/24', source: '直接输入', ok: true, rule: '本地直连', ruleNo: 3, action: '直连（不走代理）', chain: 'direct', note: '网段抽样 16 点' },
        { input: '乱写的东西', ok: false, err: '无法识别：要 IP、网段、域名或 URL（如 http://main.example.com/）' },
      ],
    }),

    ListBackups: () => ['config-20260918-164800.123.yaml', 'config-20260918-163522.456.yaml', 'config-20260918-091207.789.yaml'],
    // 巡检状态（诊断页「业务目标巡检」卡）：window.__mockPatrol=true 时表示
    // “正在巡检、还没有结果”—— 空表上“正在巡检”与“还没有可巡检的目标”长得一模一样，
    // 而前者告诉用户“再等一秒”，后者才是“去干别的”。
    GetTargetHealth: () => ({
      probing: !!window.__mockPatrol,
      count: window.__mockPatrol ? 3 : 0,
      targets: window.__mockPatrol ? [] : [
        { target: '192.0.2.217:443', chain: 'proxy-a', ok: false, latency: '', error: 'socks5+tls://your-host-a:10080：socks CONNECT 被拒: host unreachable', checked: '17:02:11' },
        { target: '198.51.100.99:443', chain: 'proxy-b', ok: true, latency: '24 ms', error: '', checked: '17:02:11' },
      ],
    }),
    ProbeTargetsNow: () => null,
    GetConns: () => ({
      total: 1284, active: 4, perChain: { 'proxy-a': 812, 'proxy-b': 402, direct: 70 },
      // 速率（字节/秒）：引擎每秒采样一次，界面直接读（见 internal/engine/rateLoop）
      rateUp: 40000, rateDown: 120000,
      // 前三条是**同一目标、同一进程**的并行连接（一个 magic-api 页面就会开 6 条）——
      // 界面应当合并成一行 ×3，点开才看得到每条的本地端口。
      list: [
        { target: '192.0.2.217:443', action: '隧道', chain: 'proxy-a', sport: 51804, ageSec: 2, proc: 'HISClient.exe', pid: 8804, ruleNo: 1, ruleName: '示例链路 A', started: '16:16:44', dur: '2s', up: 1741, down: 11264, packets: 12, upBps: 3000, downBps: 9000, state: '进行中', error: '' },
        { target: '192.0.2.217:443', action: '隧道', chain: 'proxy-a', sport: 51805, ageSec: 2, proc: 'HISClient.exe', pid: 8804, ruleNo: 1, ruleName: '示例链路 A', started: '16:16:44', dur: '2s', up: 900, down: 4096, packets: 8, upBps: 1500, downBps: 4000, state: '进行中', error: '' },
        { target: '192.0.2.217:443', action: '隧道', chain: 'proxy-a', sport: 51806, ageSec: 1, proc: 'HISClient.exe', pid: 8804, ruleNo: 1, ruleName: '示例链路 A', started: '16:16:45', dur: '1s', up: 300, down: 1024, packets: 4, upBps: 800, downBps: 2000, state: '进行中', error: '' },
        { target: '198.51.100.99:443', action: '隧道', chain: 'proxy-b', sport: 51810, ageSec: 1, proc: 'java.exe', pid: 6120, ruleNo: 2, ruleName: 'site-b 链路', started: '16:16:44', dur: '1s', up: 1741, down: 1024, packets: 6, state: '进行中', error: '' },
        { target: '192.168.199.1:445', action: '直连', chain: 'direct', sport: 51812, ageSec: 8, proc: 'explorer.exe', pid: 3320, ruleNo: 3, ruleName: '本地直连', started: '16:17:02', dur: '8s', up: 512, down: 0, packets: 7, state: '进行中', error: '' },
        { target: '10.9.9.9:22', action: '阻断', chain: 'block', sport: 51814, ageSec: 0, proc: '', pid: 0, ruleNo: 4, ruleName: '阻断运维端口', started: '16:17:05', dur: '0s', up: 0, down: 0, packets: 2, state: '已阻断', error: '' },
        { target: '10.0.0.9:443', action: '隧道', chain: 'proxy-a', sport: 51816, ageSec: 12, proc: 'Navicat.exe', pid: 9911, ruleNo: 1, ruleName: '示例链路 A', started: '16:15:30', dur: '12s', up: 0, down: 0, packets: 0, state: '失败', error: 'socks5+tls://your-host:10080：连代理失败: i/o timeout' },
        { target: '172.16.9.21:5432', action: '隧道', chain: 'proxy-a', sport: 51818, ageSec: 192, proc: 'pgAdmin4.exe', pid: 5540, ruleNo: 6, ruleName: '数据库段', started: '16:14:02', dur: '3m12s', up: 204800, down: 8388608, packets: 940, state: '已结束', error: '' },
      ],
    }),
    LocalSubnets: () => ['192.168.199.0/24', '172.26.160.0/20'],
    // 链路结论（诊断页「链路自检」卡顶部的一句话）：形状要与 engine.Verdict 一致。
    // 故意给 error 档 —— 红路径（含建议与逐条）才是要钉住的那条。
    GetVerdict: () => ({
      level: 'error',
      head: '上游能连上，但 2 个内网业务目标连不通',
      sub: '本机到上游这一段是好的 —— 问题在上游那一侧到客户内网。',
      detail: [
        '✗ 链 proxy-a：上游可用，但 2 个内网目标不可达',
        '✓ 链 proxy-b：上游 1/1 可用',
      ],
      advice: [
        '把下面的目标（IP:端口）发给上游管理员，核对上游侧的路由与访问策略。',
        '也确认业务本身在跑（数据库/服务没停、端口没变）。',
      ],
    }),
    // 接管状态（诊断页）：形状要与 engine.RuntimeStatus 完全一致；
    // 带 1 条 warning —— 界面必须**照着它**渲染，不能是写死的“一切正常”。
    GetRuntimeStatus: () => ({
      running: true, relay: '127.0.0.1:58123', uptime: '6h12m', uptimeSec: 22320,
      kernel: { main: true, dyn: true, inject: true, socket: true, reflect: true, ranges: 12, bytes: 1640, peers: [], direct: false, quicBlock: true },
      names: { count: 20, stale: 4, failed: 0, newestSec: 3, wildcards: true, takeover: true, fakeUsed: 3, fakeCap: 65534, fakeRange: '198.19.0.0/16' },
      conns: { total: 726, active: 2, perChain: { 'proxy-a': 724, 'proxy-b': 2 }, procKnown: 10, procUnknown: 1, procPorts: 104, procPids: 2 },
      rules: { total: 7, ranges: 12, shadowed: ['第 2 条「排除更新端口」（1 个目标被覆盖）'] },
      warnings: [{ kind: 'rules.shadowed', severity: 'warn', text: '1 条规则有目标被前面的规则完全覆盖（永远不会生效）' }],
    }),
    GetKernelDetail: () => ({
      ranges: ['203.0.113.0 - 203.0.113.255（任意端口）'], dynRanges: [],
      filter: '(outbound and tcp and ((ip.DstAddr >= 203.0.113.0 and ip.DstAddr <= 203.0.113.255)))', dynFilter: '',
    }),
    GetCountDirect: () => ({ on: !!SETTINGS.countDirect }),
    SetCountDirect: (on) => { SETTINGS.countDirect = !!on; return null; },
    // 日志档位滑块：mock 要**记住**切换结果 —— 界面切完会再读一次设置核验，
    // 不回写就永远跳回初值（滑块看起来像“点了没反应”）。
    SetLogLevel: (lv) => { SETTINGS.logLevel = lv; return null; },
    // 档 1b：UDP 能力探测（诊断页按钮）——一好一坏，两种结论都能看到
    ProbeUDPRelay: () => ([
      '本版本不转发 UDP（QUIC 只拦不转）—— 这里只探上游有没有这个能力。目标 114.114.114.114:53：',
      '✓ 链 proxy-a（socks5+tls://your-host-a:10080）：UDP 中继可用，往返 12ms',
      '✗ 链 proxy-b（socks5+tls://your-host-b:10084）：UDP ASSOCIATE 已被接受（bnd=172.17.0.2:39946），但真实往返没有回包：i/o timeout',
    ]),
    // 档 1a：拦了多少包 + 最近拦了谁（界面直接显示）
    // 历史连接（已结束连接的存档）：界面「历史连接」展开区按需拉。
    // 刻意给三种状态（正常结束 / 失败带原因 / 阻断），好让门禁能断言过滤与失败原因展示。
    GetConnsHistory: () => ({ keep: 300, list: [
      { target: '198.51.100.99:443', action: '隧道', chain: 'proxy-b', sport: 51233, proc: 'chrome.exe', pid: 4455, ruleNo: 3, ruleName: 'site-b 链路', started: '16:10:02', ended: '16:10:05', durSec: 3, agoSec: 12, up: 2048, down: 8192, packets: 9, state: '已结束', err: '' },
      { target: '192.0.2.217:443', action: '隧道', chain: 'proxy-a', sport: 51240, proc: 'DF.HIS.exe', pid: 8804, ruleNo: 1, ruleName: '示例链路 A', started: '16:09:40', ended: '16:09:41', durSec: 1, agoSec: 33, up: 900, down: 0, packets: 3, state: '失败', err: '连代理失败: i/o timeout' },
      { target: '10.9.9.9:22', action: '阻断', chain: 'block', sport: 51241, proc: '', pid: 0, ruleNo: 4, ruleName: '阻断运维端口', started: '16:09:30', ended: '16:09:30', durSec: 0, agoSec: 43, up: 0, down: 0, packets: 2, state: '已阻断', err: '' },
    ] }),
    ClearConnsHistory: () => null,
    // 「统计」页：形状要与 engine.StatPage 一致（多了会渲染成 undefined，少了看不出来）。
    // 刻意给两类可区分的东西：一个有域名的目标（行内要带实际地址）、一个查不到进程的“未知”。
    GetStats: (scope) => ({
      scope: scope || 'run',
      conns: 726, active: 2, failed: 3,
      up: 8_400_000, down: 62_000_000,
      chain: 720, direct: 4, blocked: 2,
      uptime: '6h12m', since: '09:58:02',
      keysApps: 4, keysTargets: 7, topN: 20, cap: 512, evicted: 0,
      note: '「直连流量统计」关着 —— 直连的连接根本没进内核过滤器，这里看不到（打开那个开关才有）',
      apps: [
        { name: 'chrome.exe', conns: 402, active: 2, failed: 1, up: 3_100_000, down: 41_000_000, upBps: 4200, downBps: 26_000, avgBps: 96_000, durSec: 22320, lastAgo: 1 },
        { name: 'DF.HIS.exe', conns: 268, active: 0, failed: 2, up: 4_900_000, down: 20_400_000, upBps: 0, downBps: 0, avgBps: 78000, durSec: 21000, lastAgo: 46 },
        { name: 'magic-api.exe', conns: 52, active: 0, failed: 0, up: 380_000, down: 600_000, upBps: 0, downBps: 0, avgBps: 9000, durSec: 9000, lastAgo: 320, ports: '3306' },
        { name: '未知（系统/受保护进程）', conns: 4, active: 0, failed: 0, up: 20_000, down: 0, upBps: 0, downBps: 0, avgBps: 400, durSec: 120, lastAgo: 900 },
      ],
      targets: [
        { name: 'proxy-a.hospital.example', ip: '192.0.2.217', ports: '443,8443', conns: 512, active: 2, failed: 1, up: 6_200_000, down: 52_000_000, upBps: 4200, downBps: 26_000, avgBps: 104_000, durSec: 22320, lastAgo: 1 },
        { name: '203.0.113.237', ports: '5432', conns: 96, active: 0, failed: 0, up: 1_800_000, down: 8_400_000, upBps: 0, downBps: 0, avgBps: 61000, durSec: 18000, lastAgo: 12 },
        { name: '203.0.113.166', ports: '6446', conns: 74, active: 0, failed: 2, up: 320_000, down: 1_100_000, upBps: 0, downBps: 0, avgBps: 21000, durSec: 15000, lastAgo: 90 },
        { name: '192.0.2.220', ports: '9056', conns: 31, active: 0, failed: 0, up: 60_000, down: 480_000, upBps: 0, downBps: 0, avgBps: 12000, durSec: 8000, lastAgo: 240 },
        { name: '198.51.100.99', ports: '80,443', conns: 12, active: 0, failed: 0, up: 20_000, down: 20_000, upBps: 0, downBps: 0, avgBps: 3000, durSec: 5000, lastAgo: 620 },
        { name: '192.0.2.194', ports: '5000', conns: 1, active: 0, failed: 0, up: 1000, down: 0, upBps: 0, downBps: 0, avgBps: 100, durSec: 2, lastAgo: 1800 },
        { name: '10.9.9.9', ports: '22', conns: 1, active: 0, failed: 1, up: 0, down: 0, upBps: 0, downBps: 0, avgBps: 0, durSec: 1, lastAgo: 3600 },
      ],
    }),
    ResetStats: () => null,
    // 顶栏流量图：**每次调用都往前推一格**（底部还有历史数据），
    // 这样门禁能断言“新样本真的把画布画动了”，而不是只断言 canvas 存在。
    GetTraffic: () => {
      // 隧道与直连分开给（后端就是这么发的）：直连那部分要不要算，由前端的 countDirect 决定
      mockTrafficPts.push({
        tunUp: 9000 + (mockTrafficPts.length % 7) * 4200,
        tunDown: 40000 + (mockTrafficPts.length % 11) * 26000,
        dirUp: 32000,
        dirDown: 180000,
      });
      if (mockTrafficPts.length > 60) mockTrafficPts.shift();
      return {
        series: mockTrafficPts.slice(),
        countDirect: !!SETTINGS.countDirect,
        window: 60,
        running: true,
      };
    },
    GetQuicBlock: () => ({ on: true, blocked: 42, recent: ['192.0.2.217:443', '203.0.113.77:443'] }),
    SelfTest: () => null, HideToTray: () => null, SetTheme: () => null, Restart: () => null,
    MoveRoute: () => null, MoveChain: () => null, SetRouteEnabled: () => null, SortRoutes: () => false,
  };
  // ⚠ 桥的形状必须与 frontend/app.js 保持一致：现在是 `window.go.webui.Bridge.Call(fn, args)`
  // （旧的是 `window.go.webui.Backend[fn](...args)`）。
  // 这一行曾经长期停在旧形状 —— 后果不是报错，而是**恰好在页面没起来时报绿灯**：
  // app.js 取 `B()` 得到 undefined → boot() 直接返回不接线 → 一个错都没收集到 →
  // check-ui.ps1 的 `errs.length ? ... : (t ? "boot:"+t : "OK")` 就报 OK（2026-10-14 实测）。
  // 改桥形状时同步这一行，并确认 check-ui.ps1 打印的是 `boot:<状态文本>` 而不是光秃秃的 OK。
  const Backend = new Proxy(M, {
    get: (t, k) => t[k] || (() => null),   // 没定义的方法一律返回 null，不炸
  });
  window.go = { webui: {
    Backend,
    Bridge: { Call: (fn, args) => Promise.resolve(Backend[fn](...(args || []))) },
  } };
  window.runtime = {
    EventsOn: () => () => {}, WindowHide: () => {}, WindowMinimise: () => {},
    WindowToggleMaximise: () => {}, Quit: () => {},
  };
  // 等界面渲染完切到「路由规则」页（截图主角是规则表）
  window.addEventListener('load', () => setTimeout(() => {
    const t = document.querySelector('.tab[data-page="rule"]');
    if (t) t.click();
  }, 500));
})();
