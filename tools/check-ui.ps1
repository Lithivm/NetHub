# 界面自检：用假数据（tools/shot/mock.js）把前端真跑一遍，抓两类错：
#   1) 动态：boot() 有没有抛错、已接线的 onclick 调不调得通
#   2) 静态：调用了但整个文件里没有定义的函数（例如漏写一个 resetDialDefaults）
#
# 为什么必须要它：前端引用一个不存在的函数时，界面只弹一句"初始化失败"，
# 而 JS 直到执行到那一行才报错 —— 光读代码看不出来（今天就栽过两次）。
#
# 用法： pwsh -NoProfile -File ./tools/check-ui.ps1      （退出码 0 = 通过）
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
$tmpT = Join-Path $fe '_check.html'
$tmpM = Join-Path $fe '_check_mock.js'

# ───────── ① 静态：调用了但没定义的函数 ─────────
$js = Get-Content (Join-Path $fe 'app.js') -Raw -Encoding UTF8
$called = [regex]::Matches($js, '(?<![\w.$])([A-Za-z_][A-Za-z0-9_]*)\s*\(') |
  ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
$defined = [regex]::Matches($js, '(?:function\s+([A-Za-z_][A-Za-z0-9_]*)|(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=|([A-Za-z_][A-Za-z0-9_]*)\s*:)') |
  ForEach-Object {
    if ($_.Groups[1].Value) { $_.Groups[1].Value }
    elseif ($_.Groups[2].Value) { $_.Groups[2].Value }
    else { $_.Groups[3].Value }
  } | Sort-Object -Unique
# 函数参数也算已定义（如 function btn(text, cls, fn)、箭头函数 (res) => 或 e =>）
$params = [regex]::Matches($js, 'function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)') |
  ForEach-Object { $_.Groups[1].Value -split ',' }
$arrow = [regex]::Matches($js, '(?:^|[,;{(]\s*)([A-Za-z0-9_,\s]*)\)?\s*=>') |
  ForEach-Object { $_.Groups[1].Value -split ',' }
$params = @($params + $arrow) |
  ForEach-Object { $_ -replace '\s', '' } |
  Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*$' }
$defined = @($defined + $params | Sort-Object -Unique)
# 下面的名字是启发式误报，不是真的漏写（方法调用 / 出现在字符串里的示例文本）
$knownNoise = @('base64', 'close', 'open', 'console', 'document', 'window', 'JSON', 'Math',
  # DOM 方法名：写成 `el.closest("...")` 这种形式时会被当成“调用了一个函数”，其实不是我们的函数
  'closest', 'scrollIntoView', 'replaceChildren', 'getElementById', 'querySelector', 'querySelectorAll',
  'addEventListener', 'appendChild', 'setAttribute', 'getAttribute', 'remove', 'contains', 'focus', 'click',
  # CSS 函数名，出现在字符串里（如 style.transform = 'translateY(...)'）—— 不是 JS 调用
  'translateY', 'translateX', 'translate', 'translate3d', 'scale', 'rotate', 'calc', 'color-mix', 'var', 'url', 'rgba', 'rgb', 'bezier', 'cubic-bezier')
# 关键字与浏览器/JS 内建
$builtin = @('if','for','while','switch','return','typeof','catch','function','new','await','async','do','else','in','of','delete','void','instanceof','yield','super','this','class','try','throw','case','default','break','continue','var','let','const','import','export','extends',
  'alert','confirm','prompt','fetch','parseInt','parseFloat','isNaN','isFinite','encodeURIComponent','decodeURIComponent','setTimeout','setInterval','clearInterval','clearTimeout','requestAnimationFrame','queueMicrotask','structuredClone','btoa','atob','getComputedStyle','ResizeObserver','String','Number','Boolean','Array','Object','JSON','Math','Date','RegExp','Map','Set','Promise','Error','Symbol','BigInt','Intl','Event','CustomEvent','URL','URLSearchParams','Blob','File','FileReader','TextEncoder','TextDecoder','Image','Audio','WebSocket','Worker','HTMLElement','Node','Element','Document','Window','Proxy','Reflect','WeakMap','WeakSet')
$missing = @($called | Where-Object { $defined -notcontains $_ -and $builtin -notcontains $_ -and $knownNoise -notcontains $_ })
if ($missing.Count -gt 0) {
  Write-Output ('界面自检：失败 -> 调用了但没定义的函数：' + ($missing -join ', '))
  exit 1
}

# ───────── ①b 结构：标签成对 + tab↔页面 一一对应 ─────────
# 为什么要有这一条：v0.4.2 那次就是“替换文本漏了一行开标签”——
# `<section class="page" id="page-settings">` 被吃掉 → 设置页点不开、内容成了不属于任何页的
# 孤儿，而**标签不平衡本身不会报错**，只是行为变了；上一版自检只查“点得通”，于是全绿放行。
# 这类错误光读代码看不出来，必须让机器拿文本和 DOM 对一遍。
$htmlRaw = Get-Content (Join-Path $fe 'index.html') -Raw -Encoding UTF8
$void = @('area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr')
$opened = @{}
$closed = @{}
foreach ($mm in [regex]::Matches($htmlRaw, '<([a-zA-Z][a-zA-Z0-9]*)((?:\s[^>]*)?)>')) {
  if ($mm.Value.EndsWith('/>')) { continue }               # 自闭合（SVG 的 <path/> 之类）
  $t = $mm.Groups[1].Value.ToLower()
  if ($void -contains $t) { continue }
  $opened[$t] = [int]$opened[$t] + 1
}
foreach ($mm in [regex]::Matches($htmlRaw, '</([a-zA-Z][a-zA-Z0-9]*)\s*>')) {
  $t = $mm.Groups[1].Value.ToLower()
  $closed[$t] = [int]$closed[$t] + 1
}
$structBad = @()
foreach ($t in (@($opened.Keys) + @($closed.Keys) | Sort-Object -Unique)) {
  if ([int]$opened[$t] -ne [int]$closed[$t]) {
    $structBad += ($t + ' 开' + [int]$opened[$t] + '/闭' + [int]$closed[$t])
  }
}
# tab 与页面必须一一对应：有 tab 没页面 = 点了没反应；有页面没 tab = 用户进不去
$tabPages = [regex]::Matches($htmlRaw, 'data-page="([a-z]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
$secPages = [regex]::Matches($htmlRaw, 'id="page-([a-z]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
$onlyTab = @($tabPages | Where-Object { $secPages -notcontains $_ })
$onlySec = @($secPages | Where-Object { $tabPages -notcontains $_ })
if ($onlyTab.Count) { $structBad += ('有 tab 但没 section: ' + ($onlyTab -join ',')) }
if ($onlySec.Count) { $structBad += ('有 section 但没 tab: ' + ($onlySec -join ',')) }
if ($structBad.Count -gt 0) {
  Write-Output ('界面自检：失败 -> 结构：' + ($structBad -join '；'))
  exit 1
}

# ───────── ② 动态：跑一遍页面 ─────────
Copy-Item (Join-Path $root 'tools\shot\mock.js') $tmpM -Force
$html = Get-Content (Join-Path $fe 'index.html') -Raw -Encoding UTF8
$html = $html.Replace('<script src="app.js"></script>',
  '<script src="_check_mock.js"></script>' + "`n" + '<script src="app.js"></script>')
$probe = @'
<script>
window.addEventListener("load", function(){ setTimeout(function(){
  var errs = [];
  document.querySelectorAll("[id]").forEach(function(el){
    if (/win(Close|Min|Max)|btnQuit/.test(el.id)) return;   // 别真关窗/退出
    if (typeof el.onclick !== "function") return;
    try { el.onclick(new Event("click")); }
    catch(e) { if (e instanceof ReferenceError) errs.push(el.id + ":" + e.message); }
  });
  // ── 结构断言（DOM 级）：上面那套文本级检查看不见“内容到底挂在哪个父节点下”──
  // v0.4.2 的“设置页点不开”在这里会被直接拓住：内容成了不属于任何 .page 的孤儿。
  var st = [];
  var tabs = [].slice.call(document.querySelectorAll('[data-page]')).map(function (e) { return e.dataset.page; });
  var pages = [].slice.call(document.querySelectorAll('section.page')).map(function (s) { return s.id.replace(/^page-/, ''); });
  tabs.forEach(function (t) { if (pages.indexOf(t) < 0) st.push('有 tab 但没页面: ' + t); });
  pages.forEach(function (p) { if (tabs.indexOf(p) < 0) st.push('有页面但没 tab: ' + p); });
  var mn = document.querySelector('main');
  if (!mn) { st.push('找不到 <main>'); }
  else {
    [].slice.call(mn.children).forEach(function (c) {
      if (!(c.tagName === 'SECTION' && c.classList.contains('page'))) {
        st.push('main 下有孤儿元素: ' + c.tagName + '.' + (c.className || ''));
      }
    });
    document.querySelectorAll('section.page').forEach(function (s) {
      if (s.parentElement !== mn) { st.push('页面不在 main 里: ' + s.id); }
    });
  }
  if (st.length) { errs.push('结构: ' + st.join('；')); }
  // 正信号：桥在 + 引擎状态刷过一轮。
  // 为什么必须加（2026-10-14 实测）：以前的判据是 `errs.length ? errs : (t ? "boot:"+t : "OK")` ——
  // 而页面**根本没 boot** 时既没有可接线的 onclick、也没有 .toast.error，
  // 于是 errs 为空、t 为 null → **报 OK**。即「干净启动」与「压根没启动」给出同一个绿灯。
  // 起因：tools/shot/mock.js 的桥形状停在旧版 `window.go.webui.Backend`，
  // 而 app.js 现在取 `window.go.webui.Bridge` → B() 得到 undefined → boot() 直接返回。
  if (!(window.go && window.go.webui && window.go.webui.Bridge)) {
    errs.push('界面桥没注入（window.go.webui.Bridge 不存在）—— 多半是 tools/shot/mock.js 的桥形状与 app.js 不一致了');
  }
  var rs = document.querySelector('.runstate');
  if (!rs || !/is-(on|bad|busy|starting|off)/.test(rs.className || '')) {
    errs.push('引擎状态条没刷过（.runstate 上没有任何 is-* 状态）—— boot() 大概提前返回了');
  }
  var t = document.querySelector(".toast.error");
  document.documentElement.setAttribute("data-err",
    errs.length ? errs.join(" | ") : (t ? ("boot:" + t.textContent) : "OK"));
}, 1500); });
</script>
'@
$html = $html.Replace('</head>', $probe + '</head>')
Set-Content $tmpT $html -Encoding UTF8

# 独立 user-data-dir：用户自己的 Chrome 开着时，headless 复用配置会直接退出
$udd = Join-Path $env:TEMP ('nethub-uicheck-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $udd -Force | Out-Null
$url = 'file:///' + ($tmpT -replace '\\', '/')
$domFile = Join-Path $env:TEMP ('nethub-uicheck-dom-' + [guid]::NewGuid().ToString('N') + '.html')
# 用 cmd 重定向拿 stdout：PowerShell 直接 & $chrome 抓不到它的输出
$cmdline = '"' + $chrome + '" --headless --disable-gpu --user-data-dir="' + $udd +
  '" --virtual-time-budget=5000 --dump-dom "' + $url + '" > "' + $domFile + '" 2>nul'
cmd /c $cmdline | Out-Null
$text = ''
if (Test-Path $domFile) { $text = Get-Content $domFile -Raw -Encoding UTF8 }
Remove-Item $tmpT, $tmpM, $domFile -Force -ErrorAction SilentlyContinue
Remove-Item $udd -Recurse -Force -ErrorAction SilentlyContinue

if (-not $text) {
  Write-Output '界面自检：没拿到结果（Chrome 或页面本身有问题）'
  exit 1
}
$m = [regex]::Match($text, 'data-err="([^"]*)"')
if (-not $m.Success) {
  Write-Output '界面自检：没拿到结果（探针没执行？）'
  exit 1
}
if ($m.Groups[1].Value -eq 'OK') {
  Write-Output '界面自检：OK（boot 无错、已接线的 handler 调得通、没有未定义的函数调用）'
  exit 0
}
Write-Output ('界面自检：失败 -> ' + $m.Groups[1].Value)
exit 1
