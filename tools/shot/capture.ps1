# 用假数据（tools/shot/mock.js）把前端渲染出来截图，生成 docs/screenshot.png。
# 用法： pwsh -NoProfile -File ./tools/shot/capture.ps1 [页面名]   （默认 rule）
param([string]$Page = 'rule', [string]$Out = '', [string]$Size = '1180,720', [int]$Scale = 1, [string]$Click = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # tools/shot -> tools -> 项目根
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

$tmp = Join-Path $fe '_shot.html'
$tmpMock = Join-Path $fe '_shot_mock.js'
$html = Get-Content (Join-Path $fe 'index.html') -Raw -Encoding UTF8
$html = $html.Replace('<script src="app.js"></script>',
  '<script src="_shot_mock.js"></script>' + "`n" + '<script src="app.js"></script>')
# mock.js 只提供 window.go.webui.Backend；前端现在走 Bridge.Call（引擎在另一个进程）——
# 不包这一层的话所有数据都拉不到，截图会是空页（2026-10-14 才发现：这份工具从前端拆分那天就已经废了）。
$mockRaw = Get-Content (Join-Path $PSScriptRoot 'mock.js') -Raw -Encoding UTF8
$bridge = @'
(function () {
  var M = window.go.webui.Backend;
  window.go.webui.Bridge = {
    Call: function (method, args) {
      args = args || [];
      try { var fn = M[String(method)]; return (typeof fn === 'function') ? fn.apply(M, args) : null; }
      catch (e) { return null; }
    },
    GetEngineLink: function () { return { connected: true, pipe: 'mock', lastError: '' }; }
  };
})();
'@
Set-Content $tmpMock ($mockRaw + "`n" + $bridge) -Encoding UTF8
$probe = @"
<script>
window.addEventListener("load", function(){
  setTimeout(function(){
    // 截图时关掉过渡/动画：headless 的虚拟时间不驱动 CSS transition，
    // 不禁的话会拍到“动画刚开始”的一帧（例如选中 tab 的字还是灰的）。
    var st = document.createElement("style");
    st.textContent = "*{transition:none !important;animation:none !important}";
    document.head.appendChild(st);
    try { showPage("$Page"); } catch(e){ document.title = "shot-err:" + e.message; }
    // -Click：截之前先点一下某个元素（例如 .resolve-bad 看报错弹窗）
    // -Click：截之前先点一下某个元素（例如 .resolve-bad 看报错弹窗）。
    // 要重试：页面渲染 + mock 数据到位需要时间，一次 querySelector 常常还找不到。
    var clickSel = __CLICKSEL__;
    if (clickSel) {
      var tries = 0;
      var t = setInterval(function () {
        tries++;
        // -Click 支持两种写法：CSS 选择器（点它）或 js:开头（直接跑一段，便于给弹窗截图）
        if (clickSel.indexOf("js:") === 0) {
          try { eval(clickSel.slice(3)); } catch (e) { document.title = "click-js-err:" + e.message; }
          clearInterval(t);
          return;
        }
        var el = document.querySelector(clickSel);
        if (el) { el.click(); clearInterval(t); }
        else if (tries > 25) { clearInterval(t); document.title = "click-not-found:" + clickSel; }
      }, 200);
    }
  }, 700);
});
</script>
"@
$ClickJson = ($Click | ConvertTo-Json -Compress)   # JS 字符串字面量，引号已转义
$probe = $probe.Replace("__CLICKSEL__", $ClickJson)
$html = $html.Replace('</head>', $probe + '</head>')
Set-Content $tmp $html -Encoding UTF8

$udd = Join-Path $env:TEMP ('nethub-shot-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $udd -Force | Out-Null
$url = 'file:///' + ($tmp -replace '\\', '/')
$out = if ($Out) { $Out } else { Join-Path $root 'docs\screenshot.png' }
& $chrome --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=$Scale `
  --user-data-dir="$udd" --window-size=$Size --virtual-time-budget=8000 `
  --screenshot="$out" $url | Out-Null

Remove-Item $tmp, $tmpMock -Force -ErrorAction SilentlyContinue
Remove-Item $udd -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $out) { Write-Output ("已生成 " + $out + " (" + (Get-Item $out).Length + " bytes)") }
else { Write-Output '截图失败：没有产出文件'; exit 1 }
