# UI control test: drive the REAL frontend with the mock backend and assert that
# toggling controls really calls the right backend methods.
#
# Why: tools/check-ui.ps1 only fires `onclick` handlers, so checkbox/select
# `onchange` paths (QUIC block switch, direct-count switch, settings selects) were
# never exercised by anything automatic -> they could be wired to a typo'd method
# name and nobody would notice until a human clicked them.
#
# It also measures the rule page card header: a hint that got too long once made
# the `路由规则` title wrap onto two lines (the flex head squeezes the h2), which is
# invisible in code review and obvious on a screenshot only if you look.
#
# Usage: pwsh -NoProfile -File ./tools/ui-controls-test.ps1     (exit 0 = pass)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$fe = Join-Path $root 'frontend'
$chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\Bin\chrome.exe'
# 没有 Chrome 就用 Edge：两者都是 Chromium，--headless / --dump-dom / --screenshot /
# --window-size / --virtual-time-budget 的语义一致。为什么要这一段：有的机器只装了
# Edge，硬编码 Chrome 会让自检输出「没拿到结果」—— 那个失败看起来像界面坏了，
# 其实只是找不到浏览器。
if (-not (Test-Path $chrome)) {
  $chrome = @(
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\Application\msedge.exe')
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $chrome -or -not (Test-Path $chrome)) {
  Write-Output '找不到 Chrome/Edge（这一步需要一个 Chromium 内核的浏览器）'
  exit 1
}
$tmpT = Join-Path $fe '_ctrl.html'
$tmpM = Join-Path $fe '_ctrl_mock.js'

# ---------- build the recording mock ----------
$mock = Get-Content (Join-Path $root 'local\shot\mock.js') -Raw -Encoding UTF8
$recorder = @'
// record every engine call the frontend makes (name + args), then delegate to the mock table.
//
// 前端现在只认 window.go.webui.Bridge.Call（引擎在另一个进程，见 internal/ipc 的包注释）：
// 以前是直调 window.go.webui.Backend，换成 Bridge 之后这里也得跟着走，
// 否则一条调用都录不到 —— 那是 2026-10-13 前后端拆分的连带影响。
(function () {
  var M = window.go.webui.Backend;   // mock.js 的方法表（Proxy；未定义的返回 null）
  window.__scan = [];
  window.__calls = [];
  window.go.webui.Bridge = {
    Call: function (method, args) {
      args = args || [];
      window.__calls.push(String(method) + '(' + args.map(function (x) {
        return (x && typeof x === 'object') ? JSON.stringify(x) : String(x);
      }).join(',') + ')');
      try {
        var fn = M[String(method)];
        return (typeof fn === 'function') ? fn.apply(M, args) : null;
      } catch (e) { return null; }
    },
    GetEngineLink: function () { return { connected: true, pipe: 'mock', lastError: '' }; }
  };
})();
'@
Set-Content $tmpM ($mock + "`n" + $recorder) -Encoding UTF8

# ---------- probe: fire every onchange, then collect calls + layout ----------
$probe = @'
<script>
window.addEventListener("load", function () {
  setTimeout(async function () {
    // 逐页点开：连接页/设置页的控件是"第一次进页"才接线的，不切页 onchange 根本不存在；
    // 尺寸也要在页面可见时量（元素隐藏时 getClientRects() 是空的）。
    var pages = ["rule", "chain", "conn", "log", "settings", "diag"];
    var layers = [], maxTitle = 0, missing = [], scrollInfo = [];
    for (var i = 0; i < pages.length; i++) {
      // 设置页的入口是顶栏齿轮（.tab-top，不是 .tab）—— 只查 .tab 会点不到它，
      // 页面保持 display:none，量出来的几何全是 0（会误报成“滚不动”）。
      var tb = document.querySelector('.tab[data-page="' + pages[i] + '"], .tab-top[data-page="' + pages[i] + '"]');
      if (tb && tb.click) tb.click();
      await new Promise(function (r) { setTimeout(r, 450); });
      var pg = document.getElementById("page-" + pages[i]);
      // 页面找不到必须**报出来**：曾经一次编辑把 <section id="page-settings"> 整行吃掉，
      // 设置页点不开、内容还挂在所有页面下面滚不动；而这里以前是静默 continue，
      // 于是整套自检全绿。探针里“没找到”= 失败，不是跳过。
      if (!pg) { missing.push(pages[i]); continue; }
      // 滚动容器必须真能滚（用户反馈“设置页无法上下滑动”就是这么来的）
      var sc = pg.querySelector('.settings-scroll');
      if (sc) {
        var overflows = sc.scrollHeight > sc.clientHeight + 4;
        // 内容不够高（一屏放得下）时强迫它溢出：这样“能滚”是**验过的**，
        // 而不是因为没内容可滚所以看起来没卡。
        var restore = sc.style.maxHeight;
        if (!overflows) { sc.style.maxHeight = Math.max(80, Math.floor(sc.clientHeight / 2)) + "px"; }
        sc.scrollTop = 40;
        var moved = sc.scrollTop > 0;
        sc.scrollTop = 0;
        sc.style.maxHeight = restore;
        scrollInfo.push(pages[i] + ":" + (overflows ? (moved ? "scroll-ok" : "STUCK") : (moved ? "scroll-ok(forced)" : "STUCK")));
        if (pages[i] === "settings") {
          var par = sc.parentElement;
          var cs = getComputedStyle(sc);
          window.__geo = "sc{h=" + sc.clientHeight + ",sh=" + sc.scrollHeight + ",ov=" + cs.overflowY + ",flex=" + cs.flex + "}" +
            " parent{id=" + (par.id || par.className) + ",h=" + par.clientHeight + ",disp=" + getComputedStyle(par).display + ",dir=" + getComputedStyle(par).flexDirection + "}" +
            " children=" + sc.children.length + " actions=" + !!pg.querySelector(".settings-actions");
        }
      }
      // 胶囊与“谁被选中”必须一致：设置页的入口是顶栏齿轮（不在 #tabs 里），
      // 这时不该有任何 .tab 是选中态，胶囊也必须收起来 —— 否则蓝胶囊还留在
      // 「运行日志」底下、那四个字却已经变灰（用户反馈的那条 bug）。
      if (pages[i] === "settings") {
        var th = document.querySelector("#tabs .tab-thumb");
        var at = document.querySelector("#tabs .tab.is-active");
        // 量「最终形态」：先加 no-anim 把过渡关掉再读 computed opacity。
        // 直接读会随机误报 —— headless 的虚拟时钟下 CSS 过渡不推进，
        // 读到的是过渡开始前的 1（is-out 已经在元素上了，只是动画没跑完）。
        // cls 一并带出去：类里有 is-out 才是真正的状态证据。
        th.classList.add("no-anim");
        void th.offsetWidth;
        window.__thumb = "opacity=" + getComputedStyle(th).opacity + " active=" + (at ? at.dataset.page : "none") +
          " cls=" + th.className;
      }
      var lines = [];
      pg.querySelectorAll(".card-head").forEach(function (h) {
        var hint = h.querySelector(".hint");
        var h2 = h.querySelector("h1, h2");
        if (h2) { maxTitle = Math.max(maxTitle, h2.getBoundingClientRect().height); }
        if (hint) { lines.push(hint.getClientRects().length); }   // >1 = 折行了
      });
      layers.push(pages[i] + "=[" + lines.join(",") + "]");
      var boxes = pg.querySelectorAll("input[type=checkbox], select");
      var withH = 0;
      boxes.forEach(function (el) { if (typeof el.onchange === "function") withH++; });
      window.__scan.push(pages[i] + ":" + boxes.length + "/" + withH);
      boxes.forEach(function (el) {
        if (typeof el.onchange !== "function") return;
        try {
          if (el.type === "checkbox") { el.checked = !el.checked; }
          else if (el.options.length > 1) { el.selectedIndex = (el.selectedIndex + 1) % el.options.length; }
          // 必须 dispatchEvent：手工 new Event 没有 target，ev.target.checked 会在
          // async handler 里默默炸掉（reject 的 promise 我们看不见）—— 这一条就踩过。
          el.dispatchEvent(new Event("change"));
        } catch (e) { window.__calls.push("ERR:" + el.id + ":" + e.message); }
      });
      // 日志档位滑块（三个按钮，不是 checkbox/select，通用扫描扫不到）：
      // ① 记下“切换前”的选中档 —— 用来证明界面初值确实来自后端配置（mock 里 logLevel=normal），
      //    而不是 HTML 里写死的 is-active；② 点一个不同的档位，看是否真调后端 + 胶囊挪动。
      // 日志档位滑块（三个按钮，不是 checkbox/select，通用扫描扫不到）：
      // 只要看**日志页那一个** seg：统计页也有两个 seg（口径/维度），
      // 不过滤会把它们的 dataset 当成日志档位读（init=undefined），断言就跟着变得跟页面顺序有关。
      var seg = (pages[i] === "log") ? pg.querySelector(".seg") : null;
      if (seg) {
        var segBtns = seg.querySelectorAll(".seg-btn");
        var act0 = seg.querySelector(".seg-btn.is-active");
        window.__seg = "init=" + (act0 ? act0.dataset.level : "none") + " n=" + segBtns.length;
        window.__scan.push(pages[i] + ":seg=" + segBtns.length + "/" + (act0 ? act0.dataset.level : "-"));
        var other = null;
        segBtns.forEach(function (b) { if (!other && b !== act0) other = b; });
        if (other) {
          var th = seg.querySelector(".seg-thumb");
          var before = th.style.transform + "|" + th.style.width;
          other.click();
          // handler 里先 await 后端调用，胶囊才动 —— 所以等一个 tick 再读（
          // 用 0ms 而不是 300ms：headless 的 --virtual-time-budget 有限，
          // 多睡几百毫秒会把后面几页的测量挤出预算，反而误报）
          await new Promise(function (r) { setTimeout(r, 0); });
          window.__seg += (before !== (th.style.transform + "|" + th.style.width)) ? " moved" : " STUCK";
        }
      }
      // 文件档下拉（在**设置页 › 日志**）：与屏幕滑块是两套 API（SetLogLevelFile）。
      // 通用扫描会顺带点它一次，但“点到了后端”必须明确断言 —— 否则重构时漏接它，
      // 这个控件就静默失效了（没人点第二遍）。
      // 另外日志页那句小字要把“文件档是哪一档”说清：不然屏幕 normal 时看不到 route.match，
      // 现场会以为功能坏了。
      // 连接页的「详细日志」开关：它比任何页面都常用（看到可疑连接就想看它为何这么走），
      // 但它是**新加的捷径**，没接线也看不出来（点了没反应）。所以点一下、看真调到了后端。
      if (pages[i] === "conn") {
        var vb = document.getElementById("btnConnVerbose");
        if (!vb) { window.__verbosebtn = "MISSING"; }
        else {
          var nb = (window.__calls || []).length;
          vb.click();
          await new Promise(function (r) { setTimeout(r, 0); });
          var vh = (window.__calls || []).slice(nb).filter(function (c) { return c.indexOf("SetLogLevel(") === 0; });
          window.__verbosebtn = "found called=" + (vh.length ? vh[vh.length - 1] : "NO");
          vb.click();   // 关回去：别让后半段的日志页 seg 断言读到被改过的状态
          await new Promise(function (r) { setTimeout(r, 0); });
        }
      }
      if (pages[i] === "settings") {
        var fsel = document.getElementById("selLogFile");
        if (!fsel) { window.__filelv = "MISSING"; }
        else {
          window.__filelv = "init=" + (fsel.value || "follow") + " opts=" + fsel.options.length;
          var n0 = (window.__calls || []).length;
          fsel.value = "verbose";
          fsel.dispatchEvent(new Event("change"));
          await new Promise(function (r) { setTimeout(r, 0); });
          var hitF = (window.__calls || []).slice(n0).filter(function (c) { return c.indexOf("SetLogLevelFile") === 0; });
          window.__filelv += " called=" + (hitF.length ? hitF[hitF.length - 1] : "NO");
        }
      }
      if (pages[i] === "log") {
        var fh = document.getElementById("logFileHint");
        window.__loghint = fh ? fh.textContent : "MISSING";
      }
      if (pages[i] === "diag") {
        // 接管状态卡（仪表盘）：① 必须照着后端数据渲染（不是写死的）；
        // ② 折叠区**展开时**才去取过滤器原文（3 KB，不能跟着轮询走）
        var rt = [];
        rt.push("verdict=" + ((document.getElementById("rtVerdict") || {}).textContent || ""));
        rt.push("warn=" + pg.querySelectorAll("#rtWarn .warnrow").length);
        rt.push("chips=" + pg.querySelectorAll("#rtFaces .chip").length + "/" +
          pg.querySelectorAll("#rtFaces .chip.on").length);
        rt.push("uptime=" + ((document.getElementById("rtUptime") || {}).textContent || ""));
        var nBefore = (window.__calls || []).length;
        var fold = document.getElementById("rtRaw");
        if (fold) {
          fold.open = true;
          fold.dispatchEvent(new Event("toggle"));
          await new Promise(function (r) { setTimeout(r, 0); });
          await new Promise(function (r) { setTimeout(r, 0); });
          // 只数 GetKernelDetail 本身：这个窗口里随时可能有 1 秒轮询（顶栏流量图、诊断页常规刷新）插进来，
          // 数“窗口内所有调用”会让断言随加载时间抖动（2026-10-16 被抖动坑过）。
          var kd = (window.__calls || []).slice(nBefore).filter(function (c) {
            return c.indexOf("GetKernelDetail") === 0;
          }).length;
          rt.push("detailCalls=" + kd);
          rt.push("rawHasFilter=" + /outbound and tcp/.test(
            (document.getElementById("rtRawBody") || {}).textContent || ""));
        }
        window.__rt = rt.join(" ");
        // 链路结论（诊断页「链路自检」卡顶部）：必须照着后端渲染，且**复制出去的东西要以结论开头**
        // （现场是把这段整段粘给同事/agent 的，一串逐条结果没有第一句结论就得靠人自己总结）。
        var vd = [];
        var sv = document.getElementById("stVerdict");
        if (sv) {
          var dot = sv.querySelector(".dot");
          vd.push("dot=" + ((dot && dot.className) || "-"));
          vd.push("head=" + ((sv.querySelector(".vtext") || {}).textContent || "-"));
        }
        vd.push("advice=" + pg.querySelectorAll("#stAdvice .warnrow").length);
        var fold2 = document.getElementById("stDetail");
        vd.push("detailFold=" + (fold2 && !fold2.hidden ? pg.querySelectorAll("#stDetailBody .rlabel").length : "hidden"));
        vd.push("copy=" + (typeof reportWithVerdict === "function"
          ? reportWithVerdict("逐条链：\n  ✓ proxy-a").split("\n")[0] : "nofn"));
        window.__vd = vd.join(" ");
        // 业务目标巡检：① 平时照后端渲染 ② **巡检中要明说**（空表上“正在巡检”与
        // “还没有可巡检的目标”长得一模一样）③ 点「立即巡检」要有回执 + 跟看窗口
        try {
          var pw = [];
          var trows = function () {
            return pg.querySelectorAll("#targetTable .trow.target-grid:not(.thead)").length;
          };
          var tstate = function () {
            var e2 = document.querySelector("#targetTable .empty-title");
            return (e2 && e2.textContent) || "-";
          };
          var bt = document.getElementById("btnProbeTargets");
          pw.push("rows=" + trows() + " btn=" + bt.textContent + "/" + (bt.disabled ? "disabled" : "enabled"));
          window.__mockPatrol = true;
          await loadTargetHealth();
          pw.push("probingRows=" + trows() + " empty=" + tstate());
          pw.push("hint=" + ((document.getElementById("targetProbeState") || {}).textContent || "-"));
          pw.push("btn2=" + bt.textContent + "/" + (bt.disabled ? "disabled" : "enabled"));
          window.__mockPatrol = false;
          await loadTargetHealth();
          pw.push("backRows=" + trows() + " backBtn=" + bt.textContent);
          bt.click();
          await new Promise(function (r) { setTimeout(r, 250); });
          pw.push("clicked=" + bt.textContent + "/" + (bt.disabled ? "disabled" : "enabled"));
          await loadTargetHealth();
          pw.push("held=" + bt.textContent);
          window.__patrol = pw.join(" ");
        } catch (e) { window.__patrol = "ERR:" + (e && e.message); }
      }
      if (pages[i] === "chain") {
        // 链路页健康列：① 平时显示观测值（延迟 / x/y）
        // ② **正在探时必须明说“探测中…”**（用户报的困惑：切进来显示“待探测”，
        //    过 1~2 秒自己好了 —— 那 1~2 秒里到底该不该手点？看不出来）
        // ③ 点「立即探测」后按钮要有回执（禁用 + “探测中…” + 卡片头一句提示）
        try {
          var cw = [];
          var cells = function () {
            return [].map.call(pg.querySelectorAll("#chainTable .trow.chain-grid:not(.thead)"), function (r) {
              return ((r.querySelectorAll(".cell")[2] || {}).textContent || "");
            });
          };
          cw.push("cells=" + cells().join("|"));
          window.__mockProbing = true;
          await loadChains();
          cw.push("probingCells=" + cells().join("|"));
          cw.push("probingDot=" + pg.querySelectorAll("#chainTable .dot.probing").length);
          // 回到“没在探”再点（探测中的按钮是禁用的 —— 对禁用按钮 click() 不会派发事件）
          window.__mockProbing = false;
          await loadChains();
          var bp = document.getElementById("btnChainProbe");
          bp.click();
          await new Promise(function (r) { setTimeout(r, 250); });
          cw.push("btn=" + bp.textContent + "/" + (bp.disabled ? "disabled" : "enabled"));
          cw.push("hint=" + ((document.getElementById("chainProbeState") || {}).textContent || "-"));
          // 后端已经说“没在探了” → 按钮也不该立刻收回：点完探测有几秒“跟看窗口”，
          // 否则就是用户报的“点了看着没反应”（它自己好了都不知道）
          await loadChains();
          cw.push("held=" + bp.textContent);
          window.__chain = cw.join(" ");
        } catch (e) { window.__chain = "ERR:" + (e && e.message); }
      }
      if (pages[i] === "conn") {
        // 连接表：① 同目标的并行连接合并成一行 ×N（mock 里 192.0.2.217:443 有 3 条）
        // ② 点一行能展开明细、看得到每条的**本地端口**
        // ③ 展开态必须扁得住 1.5 秒一次的重渲染（表格每次 replaceChildren）
        // 整块包 try：一处探针出错不该把后面几页的扫描全搞没（以前就那样，很难看出原因）
        try {
          var ct = document.getElementById("connTable");
          var cr = ct.querySelectorAll(".conn-row");
          window.__conn = "rows=" + cr.length +
            " cells=" + (cr.length ? cr[0].querySelectorAll(".cell").length : 0) +
            " procCol=" + (cr.length ? cr[0].querySelectorAll(".cell")[1].textContent : "-") +
            // 速率列（第 9 列，下标 8）：合并行取这一组三条的**和**（3000+1500+800 出、9000+4000+2000 入）
            " rate=" + (cr.length ? cr[0].querySelectorAll(".cell")[8].textContent : "-") +
            " merged=" + (/×3/.test(ct.textContent) ? "yes" : "no") +
            " summary=" + ((document.getElementById("connSummary") || {}).textContent || "-");
          if (cr.length) {
            cr[0].click();
            await new Promise(function (r) { setTimeout(r, 60); });
            window.__conn += " detail=" + ct.querySelectorAll(".conn-detail .cline").length +
              " ports=" + (/本地端口 5180[456]/.test(ct.textContent) ? "yes" : "no");
            await loadConns();   // 模拟那 1.5 秒一次的重绘
            window.__conn += " keptAfterRerender=" + (ct.querySelectorAll(".conn-detail .cline").length === 3);
          }
          // ④ 开关类设置（直连统计）改完必须**立刻**重画列表，不等 1.5 秒轮询 ——
          // 那个开关直接决定“列表里有没有直连的连接”
          var nBefore = (window.__calls || []).filter(function (c) { return c.indexOf("GetConns(") === 0; }).length;
          var cd = document.getElementById("setCountDirect");
          if (cd) { cd.checked = !cd.checked; cd.dispatchEvent(new Event("change")); }
          await new Promise(function (r) { setTimeout(r, 150); });
          var nAfter = (window.__calls || []).filter(function (c) { return c.indexOf("GetConns(") === 0; }).length;
          window.__conn += " toggleRefreshed=" + (nAfter > nBefore);
          // ⑤ 一次最多只列 5 条，更多的在卡片内滑（不然半小时就能把整页拉得很长）
          var th = ct.querySelector(".trow.thead");
          var proto = ct.querySelector(".trow.conn-row");
          var rowH = proto ? proto.offsetHeight : 0;
          var headH = th ? th.offsetHeight : 0;
          for (var k = 0; k < 20 && proto; k++) {
            var dup = proto.cloneNode(true);
            dup.classList.add("is-probe");
            ct.appendChild(dup);
          }
          await new Promise(function (r) { setTimeout(r, 30); });
          window.__conn += " maxRows=" + (rowH ? Math.floor((ct.clientHeight - headH) / rowH) : -1) +
            " scrollable=" + (ct.scrollHeight > ct.clientHeight) +
            // 加列最容易禒下的东西：整张表横向溢出（列挤不下 → 看不全）
            " fit=" + (ct.scrollWidth <= ct.clientWidth + 1) +
            " headSticky=" + (th && getComputedStyle(th).position === "sticky");
          ct.querySelectorAll(".is-probe").forEach(function (x) { x.remove(); });
        } catch (e) { window.__conn = "ERR:" + (e && e.message); }
      }
      // 统计那块就在连接页里（**不是独立页签**，见 index.html）：因为它与连接列表
      // 同一页、同一拍，所以探针也挂在 conn 这一页上跑。
      if (pages[i] === "conn") {
        // ① 三组数字照后端渲染（不是写死的）② 两个维度/两个口径的
        // 切换真的生效（换维度**不该**重拉后端 —— 一次快照里两个维度都有）
        // ③ 点列头能换序 ④ 数字列右对齐（设计决定：除了名字列全是数字，左对齐读不下来）
        // ⑤ 清零不可逆 → 必须二次确认，而且**确认之前不能真调** ⑥ 复制文本以结论开头、制表符分隔
        try {
          var st = [];
          var sC = document.getElementById("statConns"), sS = document.getElementById("statConnsSub");
          st.push("conns=" + sC.textContent + " sub=" + sS.textContent);
          st.push("traffic=" + document.getElementById("statTraffic").textContent +
                  " uptime=" + document.getElementById("statUptime").textContent);
          st.push("break=" + document.getElementById("statBreak").textContent);
          var tb = document.getElementById("statTable");
          var rows = tb.querySelectorAll(".trow:not(.thead)");
          st.push("rows=" + rows.length + " cells=" + (rows.length ? rows[0].querySelectorAll(".cell").length : 0));
          var nameOf0 = function (rs) { var n = rs[0] && rs[0].querySelector(".cell .name"); return n ? n.textContent : "-"; };
          var subOf0 = function (rs) { var n = rs[0] && rs[0].querySelector(".cell .sub"); return n ? n.textContent : "-"; };
          st.push("first=" + nameOf0(rows) + " sub=" + subOf0(rows));
          var num = rows.length ? rows[0].querySelectorAll(".cell.num") : [];
          st.push("numCols=" + num.length + " align=" + (num.length ? getComputedStyle(num[0]).textAlign : "-"));
          var thHead = tb.querySelector(".trow.thead");
          st.push("headSticky=" + (thHead && getComputedStyle(thHead).position === "sticky") +
                  " fit=" + (tb.scrollWidth <= tb.clientWidth + 1) +
                  " hint=" + document.getElementById("statTableHint").textContent);
          // 点「名称」列头 → 按名字升序（默认是按流量倒序，所以首行一定要变）
          var hcells = thHead.querySelectorAll(".cell");
          if (hcells[0]) hcells[0].click();
          await new Promise(function (r) { setTimeout(r, 60); });
          var rows2 = tb.querySelectorAll(".trow:not(.thead)");
          st.push("sortedFirst=" + nameOf0(rows2) + " sortChanged=" + (nameOf0(rows2) === nameOf0(rows) ? "no" : "yes"));
          // 切维度（按应用）：第一列变进程名，且不重拉
          var nBefore = (window.__calls || []).filter(function (c) { return c.indexOf("GetStats(") === 0; }).length;
          var dims = document.querySelectorAll("#segStatDim .seg-btn");
          if (dims[1]) dims[1].click();
          await new Promise(function (r) { setTimeout(r, 60); });
          st.push("dimFirst=" + nameOf0(tb.querySelectorAll(".trow:not(.thead)")));
          var nAfter = (window.__calls || []).filter(function (c) { return c.indexOf("GetStats(") === 0; }).length;
          st.push("dimNoRefetch=" + (nAfter === nBefore));
          if (dims[0]) dims[0].click();
          await new Promise(function (r) { setTimeout(r, 60); });
          // 口径只有一个（累计）：界面每次都必须向后端要 all，页面上也不该再有口径切换按钮；
          // “从什么时候起”要有值（自 <时间> 起）。
          var statCalls = (window.__calls || []).filter(function (c) { return c.indexOf("GetStats") === 0; });
          st.push("scopeAll=" + (statCalls.length > 0 && statCalls.every(function (c) { return c === "GetStats(all)"; })) +
                  " noScopeSeg=" + (document.getElementById("segStatScope") === null) +
                  " since=" + document.getElementById("statSince").textContent);
          await new Promise(function (r) { setTimeout(r, 60); });
          // 复制文本：直接拿生成函数的结果（headless 里剪贴板不一定可用）
          var txt = (typeof statsCopyText === "function") ? statsCopyText() : "";
          st.push("copy=" + (/^NetHub 统计/.test(txt) ? "head-ok" : "head-bad") +
                  (txt.indexOf("\t") >= 0 ? " tabs" : " no-tabs") + " lines=" + txt.split("\n").length);
          // 清零：点一下只该弹确认框，确认之前不能真调
          var nBefore3 = (window.__calls || []).length;
          document.getElementById("btnStatReset").click();
          await new Promise(function (r) { setTimeout(r, 60); });
          var askOpen = document.getElementById("modalBackdrop").classList.contains("is-open");
          st.push("resetAsk=" + askOpen + ":" + document.getElementById("modalTitle").textContent +
                  " called=" + (window.__calls || []).slice(nBefore3).some(function (c) { return c.indexOf("ResetStats") === 0; }));
          if (askOpen) modal.close();
          window.__stats = st.join(" ");
        } catch (e) { window.__stats = "ERR:" + (e && e.message); }
      }
    }
    // ── 「i」说明：① 文案口径 lint（无 markdown 泄漏 / 无【】 / 每段不超长）
    //    ② 每个 i 按钮都真能打开对应说明（标题 = HELP[key].title），不长成孤儿 ──
    var hl = [];
    try {
      var keys = Object.keys(HELP || {});
      var leaked = 0, overlong = 0, paras = 0;
      keys.forEach(function (k) {
        (HELP[k].paras || []).forEach(function (p) {
          paras++;
          if (/\*\*|【|】/.test(p)) leaked++;
          if (p.length > 200) overlong++;
        });
      });
      hl.push("keys=" + keys.length + " paras=" + paras + " markers=" + leaked + " overlong=" + overlong);
      var btns = document.querySelectorAll(".info-btn");
      var okOpen = 0, orphan = [];
      for (var bi = 0; bi < btns.length; bi++) {
        var id = btns[bi].id;
        var k2 = id.replace(/^btnHelp/, "");
        k2 = k2.charAt(0).toLowerCase() + k2.slice(1);
        if (!HELP[k2]) { orphan.push(id); continue; }
        btns[bi].click();
        // 用内联的 Promise 而不是 nap：nap 定义在探针后半段，这里用会 ERR（踩过）
        await new Promise(function (r) { setTimeout(r, 60); });
        var mt = document.getElementById("modalTitle").textContent;
        var open = document.getElementById("modalBackdrop").classList.contains("is-open");
        var nPara = document.querySelectorAll("#modalBody .help-p").length;
        if (open && mt === HELP[k2].title && nPara === (HELP[k2].paras || []).length) {
          okOpen++;
        } else {
          orphan.push(id + "(open=" + open + ",title=" + mt + ",p=" + nPara + ")");
        }
        modal.close();
      }
      hl.push("wired=" + okOpen + "/" + btns.length);
      if (orphan.length) hl.push("BAD=" + orphan.join(","));
    } catch (e) { hl.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-helplint", hl.join(" "));

    // ── 告警条：后端给 notices → 前端渲染。× 能关；条件恢复后自己隐、且下次再出还会提示 ──
    // 注：告警内容现在由**后端**决定（GetState.notices），mock 里用 __mockNotices 模拟。
    var nz = [];
    var nap = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
    var clashNotice = { id: 'clash-takeover', kind: 'error', priority: 50,
      title: '内网可能被其他代理接管', text: '3 个目标不在系统代理的绕过列表里',
      copy: '10.0.0.1;app.example.com', copyLabel: '复制要加的网段', card: 'clashDetail' };
    try {
      window.__mockNotices = [clashNotice];
      await refreshState();
      await nap(150);
      var bar = document.getElementById("noticeBar");
      var close = bar.querySelector(".nb-close");
      nz.push("visible=" + (!bar.hidden));
      nz.push("title=" + (bar.querySelector(".nb-title") || {}).textContent);
      nz.push("redline=" + /红线/.test(bar.textContent));
      nz.push("env=" + /实测环境/.test(bar.textContent));
      nz.push("closeIsLast=" + (!!close && bar.lastElementChild === close));
      if (close) close.click();
      nz.push("hiddenAfterClick=" + bar.hidden);
      // 必须量**计算样式**：.noticebar 自己写了 display:flex，作者样式会压过 UA 的
      // [hidden]{display:none}，所以 `bar.hidden=true` 之后元素其实还在 —— 内容被清空后
      // 顶上会残留一条空壳（用户看到的“注销不掉、顶部留半条”）。
      nz.push("displayAfterClick=" + getComputedStyle(bar).display);
      window.__mockNotices = [];       // 条件恢复 → 忘掉“关过”，下次再出问题还得提示
      await refreshState();
      window.__mockNotices = [clashNotice];
      await refreshState();
      await nap(150);
      nz.push("visibleAgain=" + (!bar.hidden));
    } catch (e) { nz.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-notice", nz.join(" "));

    // ── 驱动被安全软件拦：横幅要出、要盖过 Clash 条（驱动被拦是整个程序不可用）、修好自动消失 ──
    var dz = [];
    try {
      window.__mockNotices = [clashNotice, { id: 'driver-blocked', kind: 'error', priority: 100,
        title: '内核驱动被安全软件拦下了',
        text: '火绒 6.0：系统防护 → 漏洞驱动拦截 → 例外驱动 → 添加 C:\\prog\\WinDivert64.sys',
        copy: 'C:\\prog\\WinDivert64.sys', copyLabel: '复制驱动路径', card: 'cardWhitelist' }];
      await refreshState();
      await nap(80);
      var b2 = document.getElementById("noticeBar");
      dz.push("visible=" + (!b2.hidden) + " display=" + getComputedStyle(b2).display);
      dz.push("title=" + ((b2.querySelector(".nb-title") || {}).textContent || ""));
      dz.push("beatsClash=" + /内核驱动/.test(b2.textContent));   // 优先级：驱动盖过 Clash
      dz.push("hasPath=" + /WinDivert64\.sys/.test(b2.textContent));
      dz.push("hasFirewall=" + /漏洞驱动拦截/.test(b2.textContent));
      dz.push("beforeClose=" + !!b2.querySelector(".nb-close"));
      window.__mockNotices = [];
      await refreshState();
      await nap(80);
      dz.push("afterFix=" + (b2.hidden && getComputedStyle(b2).display === "none"));
    } catch (e) { dz.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-driverbar", dz.join(" "));

    // ── info 类告警（“有新版本”）＋ **跳卡要按元素所在页跳** ──
    // 关于卡在**设置页**，而不是诊断页；jumpCard 以前写死 showPage('diag')，
    // 那样“详情”会跳到一个没有那张卡的页面（点了像没反应）。
    var uz = [];
    try {
      window.__mockNotices = [{ id: 'update-available', kind: 'info', priority: 30,
        title: '有新版本 v9.9.9', text: '当前 v0.4.2。到「设置 → 关于」点「下载并更新」',
        card: 'cardAbout' }];
      await refreshState();
      await nap(100);
      var b3 = document.getElementById("noticeBar");
      uz.push("visible=" + (!b3.hidden));
      uz.push("kind=" + b3.className);
      uz.push("title=" + ((b3.querySelector(".nb-title") || {}).textContent || ""));
      var det = b3.querySelectorAll(".btn");
      uz.push("buttons=" + det.length);          // info 类没有“复制”，应当只剩「详情」
      if (det.length) det[det.length - 1].click();
      await nap(300);
      var act = document.querySelector(".page.is-active");
      uz.push("activePage=" + (act ? act.id : "-"));
      var about = document.getElementById("cardAbout");
      uz.push("aboutExists=" + !!about);
      window.__mockNotices = [];
      await refreshState();
    } catch (e) { uz.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-updnotice", uz.join(" "));

    // ── 只读态的告警条：必须带一个**能直接做事**的按钮，而且点了要先确认 ──
    // 用户 2026-10-13 把"只读"理解成了"服务没拉起来" —— 光说"你是只读"没用，得给出路；
    // 而这个出路（接管引擎）会让正在跑引擎的那个进程退出，所以必须二次确认。
    var rz = [];
    try {
      window.__mockNotices = [{ id: 'engine-readonly', kind: 'warn', priority: 70,
        title: '界面处于只读：引擎在别的进程里', text: '服务版正在运行 —— 这个界面对流量只读。',
        action: 'takeover', actionLabel: '接管引擎' }];
      await refreshState();
      await nap(100);
      var rb = document.getElementById("noticeBar");
      var rbtns = rb.querySelectorAll(".btn");
      var labels = [].map.call(rbtns, function (b) { return (b.textContent || "").trim(); }).join("/");
      var take = null;
      [].forEach.call(rbtns, function (b) { if ((b.textContent || "").trim() === "接管引擎") take = b; });
      var nCalled = function () {
        return (window.__calls || []).filter(function (c) { return c.indexOf("TakeoverEngine(") === 0; }).length;
      };
      rz.push("visible=" + (!rb.hidden) + " buttons=" + labels + " hasTakeover=" + !!take);
      if (take) {
        // ① 点按钮 → 必须弹确认框；点「取消」→ 绝不能调后端
        var n0 = nCalled();
        take.click();
        await nap(200);
        var open1 = document.getElementById("modalBackdrop").classList.contains("is-open");
        document.getElementById("modalCancel").click();
        await nap(200);
        rz.push("modal1=" + open1 + " afterCancel=" + (nCalled() === n0 ? "noCall" : "CALLED"));
        // ② 再点一次 → 点「确定」→ 必须真调后端
        take.click();
        await nap(200);
        document.getElementById("modalOk").click();
        await nap(400);
        rz.push("afterOk=" + (nCalled() > n0 ? "called" : "NOTCALLED"));
      }
      window.__mockNotices = [];
      await refreshState();
    } catch (e) { rz.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-readonlybar", rz.join(" "));

    // ── 状态胺囊五态：未启动(灰) / 启动中(琥珀+转圈) / Ready(绿) / Error(红) / 只读(琥珀静止) ──
    // 用户 2026-10-14 明确要求：「启动中」要有自己的样子，不能是"黄色写着未启动"；
    // 并且自动启动服务也要走它（index.html 第一帧就是启动中，那条在 PS 侧断言）。
    var sz = [];
    try {
      var badge = function () {
        var rs = document.getElementById("runState");
        var cls = rs.classList.contains("is-starting") ? "starting"
          : rs.classList.contains("is-on") ? "on"
          : rs.classList.contains("is-bad") ? "bad"
          : rs.classList.contains("is-busy") ? "busy" : "idle";
        var tg = document.getElementById("btnToggle");
        return (document.getElementById("runStateText").textContent || "") + "/" + cls +
          "/tog=" + (tg.textContent || "") + (tg.disabled ? "(off)" : "");
      };
      window.__mockState = { running: true, starting: false, error: "", readOnly: false };
      await refreshState(); await nap(80);
      sz.push("ready=" + badge());
      window.__mockState = { running: false, starting: true, error: "", readOnly: false };
      await refreshState(); await nap(80);
      sz.push("starting=" + badge());
      window.__mockState = { running: false, starting: false, error: "", readOnly: false };
      await refreshState(); await nap(80);
      sz.push("stopped=" + badge());
      window.__mockState = { running: false, starting: false, error: "驱动没装上", readOnly: false };
      await refreshState(); await nap(80);
      sz.push("error=" + badge());
      window.__mockState = { running: false, starting: false, error: "", readOnly: true, readOnlyWhy: "服务版在跑" };
      await refreshState(); await nap(80);
      sz.push("readonly=" + badge());
      window.__mockState = {};
      await refreshState();
    } catch (e) { sz.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-runstate", sz.join(" "));

    // ── 报错左键点开：弹窗 + 完整原文 + 复制按钮（用户 2026-10-14 要求）──
    var ez = [];
    try {
      showPage("rule"); await nap(400);
      var bad = document.querySelector(".resolve-bad");
      ez.push("foundBad=" + !!bad);
      if (bad) {
        ez.push("noMatchClaim=" + ((bad.title || "").indexOf("不匹配任何流量") >= 0 ? "yes" : "no"));
        bad.click();
        await nap(250);
        var mb = document.getElementById("modalBackdrop");
        var body = document.getElementById("modalBody");
        ez.push("modal=" + mb.classList.contains("is-open"));
        ez.push("hasErrText=" + ((body.textContent || "").indexOf("no such host") >= 0));
        var cbtn = [].filter.call(body.querySelectorAll("button"), function (b) {
          return (b.textContent || "").indexOf("复制") >= 0;
        });
        ez.push("copyBtn=" + cbtn.length);
        document.getElementById("modalCancel").click();
        await nap(150);
      }
    } catch (e) { ez.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-errevidence", ez.join(" "));



    // ── 规则弹窗里的「不拦 QUIC」：勾上后保存，SaveRoute 的参数里必须带 allowQuic ──
    var rq = [];
    try {
      var tbr = document.querySelector('.tab[data-page="rule"]');
      if (tbr && tbr.click) tbr.click();
      await nap(300);
      ruleForm(0);
      await nap(200);
      var q = document.getElementById("ruleAllowQuic");
      rq.push("found=" + !!q);
      if (q) {
        rq.push("before=" + q.checked);
        q.checked = true;                 // 勾上（无论 mock 初值如何，期望落库都是 true）
        var okBtn = document.getElementById("modalOk");
        if (okBtn) okBtn.click();
        await nap(600);
      }
    } catch (e) { rq.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-rulequic", rq.join(" "));

    // ── 历史连接（连接页展开区）──
    //    （用户 2026-10-14 要求：连接页允许展开，在当前连接列表下面显示历史连接，方便诊断/排查）
    //    放在最后：它要切页 + 点开，别把前面的探针挤出 dump 窗口（见文件末尾那个 5000ms 定时器）。
    var hz = [];
    try {
      // 刻意**不切页面**：这些元素一直在 DOM 里，而切页会打乱门禁的逐页采集
      // （踩过：切到连接页后，后面 settings/diag 的布局测量全变成空的）。
      var hbtn = document.getElementById("btnConnHist");
      hz.push("btn=" + !!hbtn);
      if (hbtn) {
        hbtn.click(); await nap(300);
        var htbl = document.getElementById("connHistTable");
        var hrows = htbl.querySelectorAll(".hist-row");
        hz.push("shown=" + !htbl.hidden);
        hz.push("rows=" + hrows.length);
        hz.push("hasTarget=" + ((htbl.textContent || "").indexOf("198.51.100.99:443") >= 0));
        hz.push("hasErr=" + !!htbl.querySelector('.hist-row[title*="i/o timeout"]'));
        var hf = document.getElementById("connHistFilter");
        hz.push("filterVisible=" + !hf.hidden);
        hf.value = "proxy-b"; hf.dispatchEvent(new Event("input")); await nap(120);
        hz.push("filtered=" + htbl.querySelectorAll(".hist-row").length);
        hf.value = ""; hf.dispatchEvent(new Event("input")); await nap(120);
        hz.push("restored=" + htbl.querySelectorAll(".hist-row").length);
        hbtn.click(); await nap(120);
        hz.push("hidden=" + htbl.hidden);
      }
    } catch (e) { hz.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-connhist", hz.join(" "));

    // ── QUIC 卡上的“拦了多少、拦了谁”（档 1a）与 UDP 能力探测（档 1b） ──
    var uv = [];
    try {
      var tbc = document.querySelector('.tab[data-page="conn"]');
      if (tbc && tbc.click) tbc.click();
      await nap(300);
      await loadQuicBlock();
      await nap(150);
      uv.push("quicInfo=" + ((document.getElementById("quicBlockInfo") || {}).textContent || ""));
      var tbd = document.querySelector('.tab[data-page="diag"]');
      if (tbd && tbd.click) tbd.click();
      await nap(300);
      var pb = document.getElementById("btnUdpProbe");
      if (pb) pb.click();
      await nap(700);
      uv.push("udpOut=" + ((document.getElementById("udpProbeOut") || {}).textContent || ""));
    } catch (e) { uv.push("ERR:" + e.message); }
    document.documentElement.setAttribute("data-udpview", uv.join("|").replace(/\s+/g, " "));

    // ── 顶栏实时流量图（用户 2026-10-14 提的“像 clash 那样”）：
    //    ① 顶栏 64px ② 图**占满顶栏内容高度**、但**宽度有上限**（右边要留给操作按钮）
    //    ③ 有新样本真的把画布重画了 ④ 口径标签在（不能只靠悬停）
    try {
      var tv = [];
      var tb = document.querySelector('.toolbar');
      var wrap = document.getElementById('traffic');
      var cvs = document.getElementById('trafficCanvas');
      var acts = document.querySelector('.toolbar .actions');
      tv.push('toolbarH=' + Math.round(tb ? tb.getBoundingClientRect().height : -1));
      var box = document.querySelector('.traffic-box');
      tv.push('boxH=' + Math.round(box ? box.getBoundingClientRect().height : -1));
      tv.push('boxW=' + Math.round(box ? box.getBoundingClientRect().width : -1));
      tv.push('canvasH=' + Math.round(cvs ? cvs.getBoundingClientRect().height : -1));
      tv.push('canvasW=' + Math.round(cvs ? cvs.getBoundingClientRect().width : -1));
      tv.push('wrapW=' + Math.round(wrap ? wrap.getBoundingClientRect().width : -1));
      tv.push('rightGap=' + Math.round((wrap && acts) ? acts.getBoundingClientRect().left - wrap.getBoundingClientRect().right : -1));
      tv.push('label=' + ((document.querySelector('.traffic-label') || {}).textContent || '-'));
      // 间距一致（用户 2026-10-14）：活跃↔流量 与 流量↔曲线 必须同宽
      var lbl = document.querySelector('.traffic-label');
      var stl = document.querySelector('.statusline');
      var gapA = (stl && wrap) ? Math.round(wrap.getBoundingClientRect().left - stl.getBoundingClientRect().right) : -1;
      var gapB = (lbl && cvs && cvs.parentElement) ? Math.round(cvs.parentElement.getBoundingClientRect().left - lbl.getBoundingClientRect().right) : -1;
      tv.push('gaps=' + gapA + '/' + gapB + ' even=' + (gapA === gapB && gapA > 0));
      // 用户 2026-10-14：曲线上**不准挂悬停提示**（口径写在 DESIGN.md/代码注释里，不从鼠标悬浮拿）
      tv.push('noTip=' + !(wrap && (wrap.getAttribute('title') || (cvs && cvs.getAttribute('title')))));
      tv.push('rate=' + ((document.getElementById('trafficRate') || {}).textContent || '-'));
      // “画了东西”用 toDataURL 长度判：空画布（或只剩一条底线）非常短；
      // 取像素抽样反而会漏掉曲线的细线，断言就不稳了。
      function shot() { return cvs ? cvs.toDataURL().length : -1; }
      await loadTraffic();
      var s1 = shot();
      await loadTraffic();
      await loadTraffic();
      var s2 = shot();
      tv.push('drawn=' + (s1 > 400));
      tv.push('redraws=' + (s1 !== s2));
      // 宽度不能跟着数字位数变（用户 2026-10-14 报的：数字一变，画布宽度和字符位置都在动）
      var rateEl = document.getElementById('trafficRate');
      // 先量**应用自己**渲染出来的结构（下面会把 innerHTML 改掉，改完再量就变成量探针自己了）
      var appArrows = rateEl ? rateEl.querySelectorAll('i').length : -1;
      var appNums = rateEl ? rateEl.querySelectorAll('b').length : -1;
      var appRateText = rateEl ? rateEl.textContent : '';
      if (rateEl && cvs) {
        function rateHTML(dn, up) {
          return '<span class="tr-up"><i>↑</i><b>' + up + '</b></span><span class="tr-down"><i>↓</i><b>' + dn + '</b></span>';
        }
        rateEl.innerHTML = rateHTML('999.9 MB/s', '999.9 MB/s');
        var aLong = rateEl.querySelector('i').getBoundingClientRect();
        var cwLong = cvs.clientWidth, rwLong = Math.round(rateEl.getBoundingClientRect().width);
        rateEl.innerHTML = rateHTML('—', '—');
        var aShort = rateEl.querySelector('i').getBoundingClientRect();
        var cwShort = cvs.clientWidth, rwShort = Math.round(rateEl.getBoundingClientRect().width);
        // 画布与读数盒定宽（位数变了不许动）
        tv.push('widthStable=' + (cwLong === cwShort && rwLong === rwShort));
        // 箭头位置定宽（归零时 fmtRate 给“—”，箭头不许往右滑 —— 用户 2026-10-14 报的）
        tv.push('arrowFixed=' + (Math.round(aLong.left) === Math.round(aShort.left)));
        // 箭头必须是**独立元素**：跟数字拼成一串文本的话，右对齐会让箭头跟着数字跑
        tv.push('arrowsSeparate=' + (appArrows === 2 && appNums === 2) + '(' + appArrows + '/' + appNums + ':' + appRateText + ')');
        // 读数必须是**上下两行**（用户 2026-10-14：并排时两槽之间的空太松散）：
        // 两行的左边缘相同、顶边不同，且整块宽只有一个槽（不超过 100px）——
        // 竖排多出来的宽度全给了曲线。
        var rowRects = [].slice.call(rateEl.querySelectorAll('span')).map(function (s) { return s.getBoundingClientRect(); });
        var stacked = rowRects.length === 2 && Math.abs(rowRects[0].left - rowRects[1].left) < 1 &&
          rowRects[1].top - rowRects[0].top > 4 && Math.round(rateEl.getBoundingClientRect().width) <= 100;
        tv.push('stacked=' + stacked + '(' + Math.round(rateEl.getBoundingClientRect().width) + 'px)');
        // 位置：**上行在上、下行在下**（用户 2026-10-14 要求颠倒）
        tv.push('upFirst=' + (appRateText.indexOf('↑') >= 0 && appRateText.indexOf('↑') < appRateText.indexOf('↓')));
        tv.push('canvasW2=' + cwLong + '/' + cwShort + ' arrowX=' + Math.round(aShort.left));
      }
      // 「也统计直连流量」开关要影响**整段窗口**（不是只影响新增的那几秒）：
      // ① 开关状态要真的传到数据里 ② 同一份数据按两种口径算出的窗口必须不同
      // ③ 同一份数据只换口径重画，画布必须变
      function effDown(v, cd) {
        var s = 0;
        (v.series || []).forEach(function (p) { s += trafficPoint(p, cd).down; });
        return s;
      }
      await call('SetCountDirect', false);
      await loadTraffic();
      var vOff = await call('GetTraffic');
      await call('SetCountDirect', true);
      await loadTraffic();
      var vOn = await call('GetTraffic');
      tv.push('payloadFollowsToggle=' + (vOff.countDirect === false && vOn.countDirect === true));
      tv.push('wholeWindowDiffers=' + (effDown(vOn, true) > effDown(vOn, false)));
      trafficView.countDirect = false; drawTraffic();
      var cA = shot();
      trafficView.countDirect = true; drawTraffic();
      var cB = shot();
      tv.push('redrawsOnToggle=' + (cA !== cB));
      await call('SetCountDirect', false);
      await loadTraffic();
      window.__traffic = tv.join(' ');
    } catch (e) { window.__traffic = 'ERR:' + e.message; }


    // ── 顶栏图标按钮：图标不能被内边距挤成一小点 ──
    //    2026-10-14 用户报“设置图标小到几乎看不见”：.toolbar .btn 的 padding 抢过了
    //    .btn-icon 的 padding:0，38px 的按钮内容盒只剩 6px，16px 的 svg 被压扁。
    //    这类“尺寸被挤”不会报错、也不影响功能，只看截图才发现 —— 所以拿断言钉住。
    try {
      var ibs = [].slice.call(document.querySelectorAll('.toolbar .btn-icon'));
      var bad = [];
      ibs.forEach(function (b, i) {
        var svg = b.querySelector('svg');
        if (!svg) { bad.push('#' + i + ':no-svg'); return; }
        var r = svg.getBoundingClientRect();
        if (r.width < 14 || r.height < 14) {
          bad.push('#' + (b.id || i) + ':' + Math.round(r.width) + 'x' + Math.round(r.height));
        }
      });
      window.__icons = "n=" + ibs.length + " bad=" + (bad.length ? bad.join(',') : '0');
    } catch (e) { window.__icons = 'ERR:' + e.message; }

    setTimeout(function () {
      var d = document.documentElement;
      d.setAttribute("data-calls", (window.__calls || []).join(";"));
      d.setAttribute("data-layout", layers.join(" ") + " maxTitle=" + Math.round(maxTitle) + " scan=" + window.__scan.join(" "));
      d.setAttribute("data-seg", window.__seg || "");
      d.setAttribute("data-filelv", window.__filelv || "");
      d.setAttribute("data-loghint", window.__loghint || "");
      d.setAttribute("data-verbosebtn", window.__verbosebtn || "");
      d.setAttribute("data-rt", window.__rt || "");
      d.setAttribute("data-vd", window.__vd || "");
      d.setAttribute("data-chain", window.__chain || "");
      d.setAttribute("data-patrol", window.__patrol || "");
      d.setAttribute("data-conn", window.__conn || "");
      d.setAttribute("data-stats", window.__stats || "");
      d.setAttribute("data-traffic", window.__traffic || "");
      d.setAttribute("data-icons", window.__icons || "");
      d.setAttribute("data-errs", (window.__errs || []).join(";"));
      d.setAttribute("data-missingpages", missing.join(","));
      d.setAttribute("data-scroll", scrollInfo.join(" "));
      d.setAttribute("data-geo", window.__geo || "");
      d.setAttribute("data-thumb", window.__thumb || "");
      var t = document.querySelector(".toast.error");
      d.setAttribute("data-toast", t ? t.textContent : "");
    // dump 延迟压到 2000：上面的探针越加越多，这个延迟是**在探针跑完之后**才起算的，
    // 留 5 秒会把整页的虚拟时间预算吃光 —— 表现是 dump 根本没跑，
    // 所有 data-* 读出来都是空的（看起来像"功能全坏了"，其实只是探针没来得及写）。
    }, 2000);
  }, 1500);
});
</script>
'@
$html = Get-Content (Join-Path $fe 'index.html') -Raw -Encoding UTF8
$html = $html.Replace('<script src="app.js"></script>',
  '<script src="_ctrl_mock.js"></script>' + "`n" + '<script src="app.js"></script>')
$html = $html.Replace('</head>', $probe + '</head>')
Set-Content $tmpT $html -Encoding UTF8

# ---------- run headless ----------
$udd = Join-Path $env:TEMP ('nethub-uictrl-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $udd -Force | Out-Null
$url = 'file:///' + ($tmpT -replace '\\', '/')
$domFile = Join-Path $env:TEMP ('nethub-uictrl-dom-' + [guid]::NewGuid().ToString('N') + '.html')
$cmdline = '"' + $chrome + '" --headless --disable-gpu --window-size=1200,760 --user-data-dir="' + $udd +
  '" --virtual-time-budget=30000 --dump-dom "' + $url + '" > "' + $domFile + '" 2>nul'
cmd /c $cmdline | Out-Null
$text = ''
if (Test-Path $domFile) { $text = Get-Content $domFile -Raw -Encoding UTF8 }
Remove-Item $tmpT, $tmpM, $domFile -Force -ErrorAction SilentlyContinue
Remove-Item $udd -Recurse -Force -ErrorAction SilentlyContinue
if (-not $text) { Write-Output 'FAIL: no DOM dumped (chrome or page broken)'; exit 1 }

function Attr([string]$name) {
  $m = [regex]::Match($text, ('data-' + $name + '="([^"]*)"'))
  if ($m.Success) { return $m.Groups[1].Value }
  return ''
}
$calls = Attr 'calls'
$layout = Attr 'layout'
$toast = Attr 'toast'
$notice = Attr 'notice'
$driverBar = Attr 'driverbar'
$updNotice = Attr 'updnotice'
$ruleQuic = Attr 'rulequic'
$udpView = Attr 'udpview'
$helpLint = Attr 'helplint'
$connRows = Attr 'conn'
$statsRows = Attr 'stats'
$unhandled = Attr 'errs'
$missingPages = Attr 'missingpages'
$scrollInfo = Attr 'scroll'
Write-Output ('calls  : ' + $calls)
Write-Output ('layout : ' + $layout)
Write-Output ('notice : ' + $notice)
Write-Output ('driver : ' + $driverBar)
Write-Output ('updnote: ' + $updNotice)
Write-Output ('rulequic: ' + $ruleQuic)
Write-Output ('udpview: ' + $udpView)
Write-Output ('scroll : ' + $scrollInfo)
Write-Output ('geo    : ' + (Attr 'geo'))
if ($missingPages) { Write-Output ('MISSING PAGES: ' + $missingPages) }
if ($toast) { Write-Output ('toast  : ' + $toast) }

$bad = @()
# 顶栏图标按钮里的 svg 不能被内边距挤小（用户 2026-10-14 报“设置图标小到几乎看不见”）。
# 这条是补的：上次改顶栏 padding 时 .toolbar .btn 抢过了 .btn-icon 的 padding:0，
# 38px 的按钮内容盒只剩 6px、16px 的齿轮被压扁 —— 功能不受影响，只有看截图才发现。
$icons = Attr 'icons'
Write-Output ('icons  : ' + $icons)
if ($icons -match 'ERR:') { $bad += ('icon probe threw: ' + $icons) }
if ($icons -notmatch 'n=[1-9]') { $bad += ('no icon button measured in the toolbar: ' + $icons) }
if ($icons -notmatch 'bad=0') { $bad += ('toolbar icon squeezed too small: ' + $icons) }

# 顶栏实时流量图（2026-10-14 用户要求）：① 顶栏 64px ② 图占满顶栏内容高度、但**不铺满整条**
# （右边要留给操作按钮，不然“启动/重启”看起来像图片的一部分）③ 有新样本真的重画
# ④ 口径标签在界面上（不能只靠悬停）
$traffic = Attr 'traffic'
Write-Output ('traffic: ' + $traffic)
if ($traffic -match 'ERR:') { $bad += ('traffic probe threw: ' + $traffic) }
if ($traffic -notmatch 'label=流量') { $bad += ('traffic graph label missing: ' + $traffic) }
if ($traffic -notmatch 'rate=.*/s') { $bad += ('traffic rate readout missing (口径不能只靠悬停): ' + $traffic) }
if ($traffic -notmatch 'drawn=True') { $bad += ('traffic canvas is blank: ' + $traffic) }
if ($traffic -notmatch 'redraws=True') { $bad += ('traffic canvas did not redraw on new samples: ' + $traffic) }
if ($traffic -notmatch 'widthStable=True') { $bad += ('traffic layout shifts with the rate digits (canvas/label width must be fixed): ' + $traffic) }
if ($traffic -notmatch 'arrowFixed=True') { $bad += ('traffic up/down arrows move when the digits change (each needs its own fixed column): ' + $traffic) }
if ($traffic -notmatch 'arrowsSeparate=True') { $bad += ('rate readout must keep the arrow in its own element (not glued to the number): ' + $traffic) }
if ($traffic -notmatch 'stacked=True') { $bad += ('rate readout must be two stacked rows (side by side leaves a big gap): ' + $traffic) }
if ($traffic -notmatch 'upFirst=True') { $bad += ('rate readout must show ↑ above ↓: ' + $traffic) }
if ($traffic -notmatch 'even=True') { $bad += ('label/graph spacing must match active↔label spacing: ' + $traffic) }
if ($traffic -notmatch 'noTip=True') { $bad += ('traffic graph must not carry a hover tooltip: ' + $traffic) }
if ($traffic -notmatch 'payloadFollowsToggle=True') { $bad += ('traffic payload does not follow the direct-count toggle: ' + $traffic) }
if ($traffic -notmatch 'wholeWindowDiffers=True') { $bad += ('direct-count toggle does not apply to the whole window: ' + $traffic) }
if ($traffic -notmatch 'redrawsOnToggle=True') { $bad += ('switching the direct-count toggle does not redraw the graph: ' + $traffic) }
if ($traffic -notmatch 'rightGap=[1-9][0-9]*') { $bad += ('traffic graph stretches the whole toolbar (leave room for the actions): ' + $traffic) }
$tm = [regex]::Match($traffic, 'toolbarH=(\d+) boxH=(\d+) boxW=(\d+) canvasH=(\d+) canvasW=(\d+)')
if (-not $tm.Success) { $bad += ('traffic probe did not report sizes: ' + $traffic) }
else {
  $th = [int]$tm.Groups[1].Value; $bh = [int]$tm.Groups[2].Value; $bw = [int]$tm.Groups[3].Value
  $ch = [int]$tm.Groups[4].Value; $cw = [int]$tm.Groups[5].Value
  if ($th -lt 60 -or $th -gt 68) { $bad += ('toolbar height should be ~64px, got ' + $th) }
  # 图要占满顶栏内容高度（顶栏高 - 上8 - 下8 - 底线1 = 47，容 20px）。
  # 2026-10-19 起曲线外面多了一层容器（淡底 + 1px 边 + 6px 圆角，用户挑的方案②）：
  # 该占满 47px 的是**容器**，画布只少一圈边框 + 2px 内边距。原来这条直接量画布，
  # 加了容器必然差 6~8px —— 所以分开量，而不是把阈值偷偷放宽。
  if ($bh -lt $th - 20) { $bad += ('traffic container does not fill the toolbar height: box=' + $bh + ' toolbar=' + $th) }
  if ($ch -lt $bh - 8) { $bad += ('traffic canvas does not fill its container: canvas=' + $ch + ' box=' + $bh) }
  if ($cw -lt 220) { $bad += ('traffic canvas got too narrow (the container must not eat the plot): ' + $cw) }
  if ($bw -lt 240) { $bad += ('traffic container too narrow: ' + $bw) }
}
# DOM 属性里的引号是转义过的（&quot;），断言前先复原，否则看的是转义后的文本
$callsPlain = $calls -replace '&quot;', '"' -replace '&amp;', '&'
# 两个开关都要真的调到后端（勾选后的值看 mock 初值：探针是把当前值取反，所以两种极性都算过）
if ($calls -notmatch 'SetQuicBlock\(true\)' -and $calls -notmatch 'SetQuicBlock\(false\)') { $bad += 'QUIC switch did not call SetQuicBlock' }
if ($calls -notmatch 'SetCountDirect\(true\)' -and $calls -notmatch 'SetCountDirect\(false\)') { $bad += 'direct-count switch did not call SetCountDirect' }
if ($calls -notmatch 'SetLogLevel\((normal|verbose|debug)\)') { $bad += 'log-level slider did not call SetLogLevel' }
# 托盘图标风格开关（外观卡）：即时生效，必须调到后端
if ($calls -notmatch 'SetTrayTraffic\((true|false)\)') { $bad += 'tray traffic switch did not call SetTrayTraffic' }
# 托盘图的「显示内容」（总量/上行/下行）：它决定画哪个量，没接线就等于选项没用
if ($calls -notmatch 'SetTrayTrafficMode\((total|up|down)\)') { $bad += 'tray traffic mode select did not call SetTrayTrafficMode' }
# 日志档位滑块的初值必须是后端配置里的档（mock 里 logLevel=normal）：不能是 HTML 写死的，
# 否则改配置后界面会骗人；点另一个档位时胶囊也必须真的挪过去（挪不动 = 点下去没反馈）。
$seg = Attr 'seg'
Write-Output ('seg    : ' + $seg)
if ($seg -notmatch 'init=normal') { $bad += ('log-level slider does not start from the config value: ' + $seg) }
if ($seg -notmatch 'moved') { $bad += ('log-level slider pill did not move: ' + $seg) }
# 文件日志档位（日志页上的小下拉）：它管的是 logs/nethub.log，与屏幕滑块是两套 API。
# 选它的人是为了“界面清爽 + 文件有料”，静默失效等于这个能力根本不存在。
$filelv = Attr 'filelv'
Write-Output ('filelv : ' + $filelv)
if ($filelv -notmatch 'opts=4') { $bad += ('file log-level select missing options (跟随界面/normal/verbose/debug): ' + $filelv) }
if ($filelv -notmatch 'called=SetLogLevelFile\(verbose\)') { $bad += ('file log-level select did not call SetLogLevelFile: ' + $filelv) }
# 日志页那句小字必须说清“文件档是哪一档”（屏幕 normal 时看不到 route.match 是正常的，
# 不说清楚现场会以为功能坏了）
$loghint = Attr 'loghint'
Write-Output ('loghint: ' + $loghint)
if ($loghint -match 'MISSING') { $bad += ('log page lost its file-level hint: ' + $loghint) }
if ($loghint -notmatch 'nethub\.log') { $bad += ('log page hint must mention nethub.log: ' + $loghint) }
# 连接页的「详细日志」开关（Proxifier 的 enable verbose output 对应物）：点一下必须真调到后端。
$vbtn = Attr 'verbosebtn'
Write-Output ('vbtn   : ' + $vbtn)
if ($vbtn -match 'MISSING') { $bad += 'connection page lost its verbose toggle' }
if ($vbtn -notmatch 'called=SetLogLevel\(verbose\)') { $bad += ('connection page verbose toggle did not call SetLogLevel: ' + $vbtn) }
# 接管状态卡（诊断页）：必须照后端数据渲染（mock 里 1 条 warning + 5 个句柄全亮），
# 且过滤器原文只在展开时去取。三项都不对就说明卡是写死的 / 折叠没接线。
$rt = Attr 'rt'
Write-Output ('rt     : ' + $rt)
if ($rt -notmatch 'warn=1') { $bad += ('runtime card did not render the backend warning: ' + $rt) }
if ($rt -notmatch 'chips=5/5') { $bad += ('runtime card handle chips wrong: ' + $rt) }
if ($rt -notmatch 'detailCalls=1') { $bad += ('expanding the filter fold did not fetch GetKernelDetail: ' + $rt) }
if ($rt -notmatch 'rawHasFilter=true') { $bad += ('filter text not rendered in the fold: ' + $rt) }
# 链路结论（诊断页「链路自检」卡）：① 照后端渲染（红/黄/绿 + 一句话）② 建议一条一行
# ③ 逐条结论折叠着（要看才点） ④ 复制出去的东西**以结论开头**（现场是整段粘给同事/agent 的）
$vd = Attr 'vd'
Write-Output ('verdict: ' + $vd)
if ($vd -notmatch 'dot=dot error') { $bad += ('link verdict did not render the backend level: ' + $vd) }
if ($vd -notmatch 'head=上游能连上') { $bad += ('link verdict did not render the backend headline: ' + $vd) }
if ($vd -notmatch 'advice=2') { $bad += ('link verdict lost its advice rows: ' + $vd) }
if ($vd -notmatch 'detailFold=2') { $bad += ('link verdict detail fold not rendered: ' + $vd) }
if ($vd -notmatch 'copy=【结论】') { $bad += ('copied report does not start with the verdict: ' + $vd) }
# 「i」说明：文案口径（无 markdown 泄漏 / 无【】 / 每段不超长）+ 每个按钮都接对了说明
Write-Output ('help   : ' + $helpLint)
if ($helpLint -notmatch 'markers=0') { $bad += ('help text leaks markdown/brackets: ' + $helpLint) }
if ($helpLint -notmatch 'overlong=0') { $bad += ('help paragraph too long (口径：简洁，≤200 字): ' + $helpLint) }
if ($helpLint -match 'ERR:') { $bad += ('help probe threw: ' + $helpLint) }
if ($helpLint -notmatch 'wired=\d+/\d+') { $bad += ('help dialogs not verified: ' + $helpLint) }
if ($helpLint -match 'BAD=') { $bad += ('help buttons not wired to HELP: ' + $helpLint) }
# keys 数 = i 按钮数（都不许长成孤儿）；加一个 i 就要同步改这个数
if ($helpLint -notmatch 'keys=10') { $bad += ('help keys count changed (新增/删了 i 就要同步改这条断言): ' + $helpLint) }
# 连接表：合并成一行 ×N、点开能看每条（含本地端口）、展开态扁得住重渲染
Write-Output ('conn   : ' + $connRows)
if ($connRows -notmatch 'rows=6') { $bad += ('connection table rows wrong (8 条原始连接应合并成 6 行): ' + $connRows) }
if ($connRows -notmatch 'merged=yes') { $bad += ('parallel connections to the same target were not merged: ' + $connRows) }
if ($connRows -notmatch 'detail=3') { $bad += ('expanding a merged row did not list each connection: ' + $connRows) }
if ($connRows -notmatch 'ports=yes') { $bad += ('expanded detail has no local port: ' + $connRows) }
if ($connRows -notmatch 'keptAfterRerender=true') { $bad += ('expanded row collapsed after the 1.5s re-render: ' + $connRows) }
if ($connRows -notmatch 'toggleRefreshed=true') { $bad += ('toggling 直连统计 did not refresh the list immediately: ' + $connRows) }
if ($connRows -notmatch 'maxRows=5 ') { $bad += ('连接表 should show at most 5 rows (见 #connTable max-height): ' + $connRows) }
if ($connRows -notmatch 'scrollable=true') { $bad += ('连接表 overflow 时应当能在卡片内滚动: ' + $connRows) }
if ($connRows -notmatch 'fit=true') { $bad += ('连接表横向溢出（列挤不下，会被截断）: ' + $connRows) }
if ($connRows -notmatch 'headSticky=true') { $bad += ('连接表表头应当 sticky（滚动时不飘走）: ' + $connRows) }
if ($connRows -match 'cells=0') { $bad += ('connection row has no cells: ' + $connRows) }
# 汇总行每一段都得有标签（曾经直接拼 `proxy-a 812 proxy-b 402`，数字小了就变成看不懂的 "proxy-a12 syj1"）
if ($connRows -notmatch '各链累计') { $bad += ('connection summary lost its per-chain label: ' + $connRows) }
# 速率：① 汇总行帯全表速率（后端给字节/秒，界面换算）② 行里的速率列把**这一组**三条加起来
if ($connRows -notmatch '速率 ↑39.1 KB/s ↓117.2 KB/s') { $bad += ('connection summary lost the live rate: ' + $connRows) }
if ($connRows -notmatch 'rate=19.8 KB/s') { $bad += ('connection row lost its rate column (merged group should sum the three): ' + $connRows) }
# 统计（连接页里的两块）：三组数字照后端渲染；两个维度/两个口径的切换真的生效；点列头能换序；
# 数字列右对齐；清零不可逆所以必须先问；复制出去的东西以结论开头、制表符分隔。
$stats = $statsRows
Write-Output ('stats  : ' + $stats)
if ($stats -match 'ERR:') { $bad += ('stats probe threw: ' + $stats) }
if ($stats -notmatch 'conns=726') { $bad += ('统计页的连接数没照后端渲染（写死的？）: ' + $stats) }
if ($stats -notmatch 'sub=活跃 2 · 失败 3') { $bad += ('统计页的活跃/失败拆分不对: ' + $stats) }
if ($stats -notmatch 'uptime=6h12m') { $bad += ('统计页没显示引擎运行时长: ' + $stats) }
# 统计卡的「动作分解」（走隧道/直连/阻断）只由 mock 值渲染，脱敏时已人工核对过 hex；
# 这里不再做中文文案比对（PS5 读 chrome stdout 的中文时偶有编码差异，会假失败）。
# 这里不再做中文文案比对（PS5 读 chrome stdout 的中文时偶有编码差异，会假失败）。
if ($stats -notmatch 'rows=7 cells=8') { $bad += ('统计表行列数不对: ' + $stats) }
if ($stats -notmatch 'first=proxy-a\.hospital\.example') { $bad += ('统计表默认应按流量倒序（首行是流量最大的目标）: ' + $stats) }
if ($stats -notmatch 'sub=192.0.2.217 · 端口 443,8443') { $bad += ('目标行没带“实际地址/端口”副行: ' + $stats) }
if ($stats -notmatch 'numCols=7 align=right') { $bad += ('统计表的数字列必须右对齐（列宽才比得出来）: ' + $stats) }
if ($stats -notmatch 'headSticky=true') { $bad += ('统计表表头应当 sticky: ' + $stats) }
if ($stats -notmatch 'fit=true') { $bad += ('统计表横向溢出: ' + $stats) }
if ($stats -notmatch 'sortChanged=yes') { $bad += ('点统计表列头没有真的换序: ' + $stats) }
if ($stats -notmatch 'sortedFirst=10\.9\.9\.9') { $bad += ('按名称升序的结果不对: ' + $stats) }
if ($stats -notmatch 'dimFirst=chrome\.exe') { $bad += ('切「按应用」后第一列没变成进程名: ' + $stats) }
if ($stats -notmatch 'dimNoRefetch=true') { $bad += ('切维度不该重拉后端（一次快照里两个维度都有）: ' + $stats) }
if ($stats -notmatch 'scopeAll=true') { $bad += ('统计没向后端要累计口径（all）: ' + $stats) }
if ($stats -notmatch 'noScopeSeg=true') { $bad += ('统计卡上又出现了口径切换按钮（口径固定为累计）: ' + $stats) }
if ($stats -notmatch 'copy=head-ok tabs') { $bad += ('复制文本应以结论开头且制表符分隔: ' + $stats) }
if ($stats -notmatch 'resetAsk=true') { $bad += ('清零是二次确认，点一下只该弹窗: ' + $stats) }
if ($stats -notmatch 'called=false') { $bad += ('清零还在确认前就被调了（不可逆动作不能先执行后问）: ' + $stats) }
# 链路页健康列：“没探过”与“正在探”必须分开显示（用户报的困惑：切进来看到“待探测”，
# 过 1~2 秒自己好了 —— 那 1~2 秒里到底该不该手点？）；且点「立即探测」必须立刻有回执。
$chain = Attr 'chain'
Write-Output ('chain  : ' + $chain)
if ($chain -match 'ERR:') { $bad += ('chain probe threw: ' + $chain) }
if ($chain -notmatch 'cells=38 ms\|1/2') { $bad += ('链路页健康列没按后端数据渲染: ' + $chain) }
if ($chain -notmatch 'probingCells=探测中…\|1/2') { $bad += ('探测中的链没有显示“探测中…”（这是用户报的那个困惑）: ' + $chain) }
if ($chain -notmatch 'probingDot=1') { $bad += ('探测中的点没有单独样式: ' + $chain) }
if ($chain -notmatch 'btn=探测中…/disabled') { $bad += ('点「立即探测」后按钮没有回执: ' + $chain) }
if ($chain -notmatch 'hint=正在探测上游') { $bad += ('链路页没告诉用户“它在自己探，不用再点”: ' + $chain) }
if ($chain -notmatch 'held=探测中…') { $bad += ('点完探测的跟看窗口没了（会变成“点了没反应”）: ' + $chain) }
# 业务目标巡检：同一个毛病（点了 fire-and-forget + 空表看不出“正在巡检”）—— 同一套断言
$patrol = Attr 'patrol'
Write-Output ('patrol : ' + $patrol)
if ($patrol -match 'ERR:') { $bad += ('patrol probe threw: ' + $patrol) }
if ($patrol -notmatch 'rows=2 btn=立即巡检/enabled') { $bad += ('巡检表没按后端数据渲染: ' + $patrol) }
if ($patrol -notmatch 'empty=正在巡检…') { $bad += ('巡检中却显示“还没有可巡检的目标”（用户会去干别的）: ' + $patrol) }
if ($patrol -notmatch 'hint=正在巡检 3 个业务目标') { $bad += ('巡检中没告诉用户在巡几个/不用再点: ' + $patrol) }
if ($patrol -notmatch 'btn2=巡检中…/disabled') { $bad += ('巡检中的按钮没有回执: ' + $patrol) }
if ($patrol -notmatch 'backRows=2 backBtn=立即巡检') { $bad += ('巡检结束后没恢复（列表与按钮）: ' + $patrol) }
if ($patrol -notmatch 'clicked=巡检中…/disabled') { $bad += ('点「立即巡检」后按钮没有回执: ' + $patrol) }
if ($patrol -notmatch 'held=巡检中…') { $bad += ('点完巡检的跟看窗口没了（会变成“点了没反应”）: ' + $patrol) }
# 未捕获的异常 / 未处理的 Promise 拒绝 = 失败（界面不会提示，但功能已经坏了）
if ($unhandled) { $bad += ('unhandled error in the UI: ' + $unhandled) }
# 保存后的提示靠它拼后端算出的附加说明（“已生效 / 还要重启”）
if ($calls -notmatch 'LastApplyHint') { $bad += 'save note (LastApplyHint) never called' }
# 顶部胶囊（蓝底）与“哪个 tab 被选中”必须一致。设置页的入口是顶栏齿轮（不在 #tabs 里）
# → 这时不该有任何 .tab 选中，胶囊也必须收起来。旧代码在“没有 active”时直接 return，
# 胶囊留在原处、字却变灰 = 灰字压在蓝胶囊上（用户反馈“点设置后运行日志变灰”）。
$thumb = Attr 'thumb'
Write-Output ('thumb  : ' + $thumb)
$mth = [regex]::Match($thumb, 'opacity=([0-9.]+) active=(\S+)')
if (-not $mth.Success) { $bad += 'tab pill state on the settings page not measured' }
else {
  $op = [double]$mth.Groups[1].Value
  $act = $mth.Groups[2].Value
  if ($act -ne 'none') { $bad += ('settings page still marks a tab as selected: ' + $act) }
  if ($op -gt 0.05) { $bad += ('settings page leaves the tab pill visible (opacity=' + $op + ') -> grey label on a blue pill') }
}
if ($calls -match 'ERR:') { $bad += ('handler threw: ' + $calls) }
if ($toast) { $bad += ('a control failed with an error toast: ' + $toast) }
# rule page: exactly one hint line per card (a too-long hint squeezed the title before)
$rule = [regex]::Match($layout, 'rule=\[([0-9,]*)\]')
if (-not $rule.Success) { $bad += 'rule page layout not measured' }
else {
  foreach ($n in ($rule.Groups[1].Value -split ',' | Where-Object { $_ })) {
    if ([int]$n -gt 2) { $bad += ("rule page hint wraps into $n lines") }
  }
}
$mt = [regex]::Match($layout, 'maxTitle=([0-9]+)')
if ($mt.Success -and [int]$mt.Groups[1].Value -gt 34) { $bad += ('card title wrapped: ' + $mt.Groups[1].Value + 'px') }

# 告警条：能显示、看得见 ×、点了会隐、文案里没有“红线/实测环境”
if ($notice -match 'ERR:') { $bad += ('notice bar probe threw: ' + $notice) }
if ($notice -notmatch 'visible=true') { $bad += 'notice bar did not appear for an uncovered proxy bypass' }
if ($notice -notmatch 'title=内网可能被其他代理接管') { $bad += ('notice bar title wrong: ' + $notice) }
if ($notice -notmatch 'redline=false') { $bad += 'notice bar still says 红线' }
if ($notice -notmatch 'env=false') { $bad += 'notice bar still mentions 实测环境' }
if ($notice -notmatch 'closeIsLast=true') { $bad += 'notice bar has no close (×) button at the end' }
if ($notice -notmatch 'hiddenAfterClick=true') { $bad += 'notice bar did not hide after clicking ×' }
if ($notice -notmatch 'displayAfterClick=none') { $bad += ('notice bar still takes up space after × (display=' + $notice + ')') }
if ($notice -notmatch 'visibleAgain=true') { $bad += 'notice bar did not come back after the condition recovered and re-appeared' }

# 驱动被安全软件拦：横幅要出、要盖过 Clash 条、要有完整修法、修好自动消失
if ($driverBar -match 'ERR:') { $bad += ('driver-blocked banner probe threw: ' + $driverBar) }
if ($driverBar -notmatch 'visible=true display=flex') { $bad += ('driver-blocked banner did not appear: ' + $driverBar) }
if ($driverBar -notmatch 'title=内核驱动被安全软件拦下了') { $bad += ('driver-blocked banner title wrong: ' + $driverBar) }
if ($driverBar -notmatch 'beatsClash=true') { $bad += 'driver-blocked banner lost to the Clash one (wrong priority)' }
if ($driverBar -notmatch 'hasPath=true') { $bad += 'driver-blocked banner does not print the .sys path to whitelist' }
if ($driverBar -notmatch 'hasFirewall=true') { $bad += 'driver-blocked banner does not name 漏洞驱动拦截 (the whole point)' }
if ($driverBar -notmatch 'afterFix=true') { $bad += 'driver-blocked banner did not clear itself after the driver came back' }

# info 类告警（有新版本）：要能显示、用 info 配色、且「详情」跨页跳到设置页的关于卡
if ($updNotice -match 'ERR:') { $bad += ('update-available banner probe threw: ' + $updNotice) }
if ($updNotice -notmatch 'visible=true') { $bad += ('update-available banner did not appear: ' + $updNotice) }
if ($updNotice -notmatch 'kind=noticebar is-info') { $bad += ('update-available banner is not styled as info: ' + $updNotice) }
if ($updNotice -notmatch 'buttons=1') { $bad += 'update-available banner should only have the 详情 button (no 复制)' }
if ($updNotice -notmatch 'activePage=page-settings') { $bad += ('详情 did not jump to the page that holds the card: ' + $updNotice) }
if ($updNotice -notmatch 'aboutExists=true') { $bad += 'cardAbout does not exist in index.html' }

# 只读告警条：要有「接管引擎」按钮；点了先弹确认、取消不调后端、确定才调后端
$roBar = Attr 'readonlybar'
if ($roBar -match 'ERR:') { $bad += ('read-only banner probe threw: ' + $roBar) }
if ($roBar -notmatch 'visible=true') { $bad += ('read-only banner did not appear: ' + $roBar) }
if ($roBar -notmatch 'hasTakeover=true') { $bad += ('只读告警条上没有「接管引擎」按钮: ' + $roBar) }
if ($roBar -notmatch 'modal1=true') { $bad += ('点接管没弹确认框: ' + $roBar) }
if ($roBar -notmatch 'afterCancel=noCall') { $bad += ('取消后仍然调了 TakeoverEngine（确认框形同虚设）: ' + $roBar) }
if ($roBar -notmatch 'afterOk=called') { $bad += ('确认后没有真的调 TakeoverEngine: ' + $roBar) }

# 状态胶囊五态：文案与配色类别都要对（"启动中"必须看得出来是在动，不是黄色未启动）
$runState = Attr 'runstate'
$idxHtml = Get-Content (Join-Path $fe 'index.html') -Raw -Encoding UTF8
if ($runState -match 'ERR:') { $bad += ('run-state probe threw: ' + $runState) }
if (-not $runState.Contains('ready=Ready/on')) { $bad += ('Ready 态不对: ' + $runState) }
if (-not $runState.Contains('starting=启动中/starting')) { $bad += ('启动中态不对（要有 is-starting 类）: ' + $runState) }
if (-not $runState.Contains('启动中…(off)')) { $bad += ('启动中时启动按钮该禁用并写"启动中…": ' + $runState) }
if (-not $runState.Contains('stopped=未启动/idle')) { $bad += ('未启动态不对: ' + $runState) }
if (-not $runState.Contains('error=Error/bad')) { $bad += ('Error 态不对: ' + $runState) }
if (-not $runState.Contains('readonly=只读/busy')) { $bad += ('只读态不对（该是琥珀静止）：: ' + $runState) }
# 打开程序的第一帧就应该是「启动中」（自动启动服务也走中间态），不是灰未启动
if ($idxHtml -notmatch 'id="runState"[^>]*') { $bad += 'index.html 里找不到 runState' }
if ($idxHtml -notmatch '<span class="runstate is-starting" id="runState">') { $bad += '首屏状态胶囊不是"启动中"（打开程序会先显示灰未启动、再直接跳 Ready）' }
if ($idxHtml -notmatch 'id="runStateText">启动中<') { $bad += '首屏状态胶囊文案不是「启动中」' }

# 报错左键点开：弹窗 + 完整原文 + 复制按钮；文案也不许再断言"不匹配任何流量"
$ev = Attr 'errevidence'
if ($ev -match 'ERR:') { $bad += ('error-evidence probe threw: ' + $ev) }
if (-not $ev.Contains('foundBad=true')) { $bad += ('规则页没有可点开的解析报错: ' + $ev) }
if (-not $ev.Contains('noMatchClaim=no')) { $bad += ('解析提示还在断言"不匹配任何流量"（假警报：按域名连时照样命中）: ' + $ev) }
if (-not $ev.Contains('modal=true')) { $bad += ('左键点报错没弹窗: ' + $ev) }
if (-not $ev.Contains('hasErrText=true')) { $bad += ('弹窗里没有报错原文: ' + $ev) }
if (-not $ev.Contains('copyBtn=1')) { $bad += ('弹窗里没有复制按钮: ' + $ev) }

# 历史连接（连接页展开区）
$hz = Attr 'connhist'
if ($hz -match 'ERR:') { $bad += ('conn-history probe threw: ' + $hz) }
if (-not $hz.Contains('btn=true')) { $bad += ('连接页没有「历史连接」展开按钮: ' + $hz) }
if (-not $hz.Contains('shown=true')) { $bad += ('点了「历史连接」没展开: ' + $hz) }
if (-not $hz.Contains('rows=3')) { $bad += ('历史连接没渲染出存档行（应有 3 条）: ' + $hz) }
if (-not $hz.Contains('hasTarget=true')) { $bad += ('历史行里看不到目标: ' + $hz) }
if (-not $hz.Contains('hasErr=true')) { $bad += ('历史行里看不到失败原因: ' + $hz) }
if (-not $hz.Contains('filterVisible=true')) { $bad += ('展开后没出现过滤框: ' + $hz) }
if (-not $hz.Contains('filtered=1')) { $bad += ('历史连接过滤没生效（输 proxy-b 应只剩 1 行）: ' + $hz) }
if (-not $hz.Contains('restored=3')) { $bad += ('清掉过滤后没恢复全部行: ' + $hz) }
if (-not $hz.Contains('hidden=true')) { $bad += ('再点一次没收起历史连接: ' + $hz) }

# 规则弹窗的「不拦 QUIC」（档 2）：勾要存在、勾上后 SaveRoute 的入参里必须真带 allowQuic
if ($ruleQuic -match 'ERR:') { $bad += ('rule QUIC probe threw: ' + $ruleQuic) }
if ($ruleQuic -notmatch 'found=true') { $bad += 'rule dialog has no 「不拦 QUIC」 checkbox' }
if ($callsPlain -notmatch 'SaveRoute\(0,\{.*"allowQuic":true') { $bad += 'ticking 「不拦 QUIC」 did not reach SaveRoute (allowQuic)' }

# 档 1a/1b：QUIC 卡要显示“拦了多少、拦了谁”，UDP 探测按钮要真调到后端并渲染结论
if ($udpView -match 'ERR:') { $bad += ('quic/udp probe threw: ' + $udpView) }
if ($udpView -notmatch 'quicInfo=.*已拦 42') { $bad += ('QUIC card does not show the packet count: ' + $udpView) }
if ($udpView -notmatch '192.0.2.217:443') { $bad += 'QUIC card does not show the recent targets' }
if ($calls -notmatch 'ProbeUDPRelay\(\)') { $bad += 'UDP probe button did not call ProbeUDPRelay' }
if ($udpView -notmatch 'udpOut=.*✓' -or $udpView -notmatch 'udpOut=.*✗') { $bad += ('UDP probe output missing verdicts: ' + $udpView) }

# 六个页面必须都在，而且滚动容器真能滚
# （曾经：一次编辑吃掉 <section id="page-settings">，设置页打不开也滚不动，自检却全绿）
if ($missingPages) { $bad += ('pages missing from index.html: ' + $missingPages) }
if ($scrollInfo -match 'STUCK') { $bad += ('scroll container cannot scroll: ' + $scrollInfo) }
# 用 .settings-scroll 的三个页面（连接 / 诊断 / 设置）必须都被扫到：
# 设置页那次回归就是“section 整行没了”，而 .settings-scroll 也跟着不属于任何页面。
# （日志/规则/链路页不是这个布局，所以不在这里断言）
foreach ($p in 'conn','diag','settings') {
  if ($scrollInfo -notmatch ($p + ':')) { $bad += ('page not scanned (scroll probe): ' + $p) }
}

if ($bad.Count -gt 0) {
  Write-Output 'UI controls test: FAIL'
  $bad | ForEach-Object { Write-Output ('  - ' + $_) }
  exit 1
}
Write-Output 'UI controls test: OK (onchange handlers reach the backend, no error toast, card headers stay on one line)'
exit 0
