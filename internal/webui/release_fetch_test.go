package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 这两条零配额的路（302 拿 tag、HTML 拿包与摘要）解析错了不是报错，而是
// "悄悄换一条路走"或"拿到别的资产的摘要"——都是现场难查的形态，逐条钉住。

func TestLatestTagViaRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/Lithivm/NetHub/releases/tag/v0.7.0", http.StatusFound)
	}))
	defer srv.Close()
	restore := releasesLatestURL
	releasesLatestURL = srv.URL + "/Lithivm/NetHub/releases/latest"
	defer func() { releasesLatestURL = restore }()

	tag, err := latestTagViaRedirect()
	if err != nil {
		t.Fatalf("解析 302 失败：%v", err)
	}
	if tag != "v0.7.0" {
		t.Fatalf("tag = %q，想要 v0.7.0", tag)
	}
}

// 没重定向（比如被门户/代理拦了返回 200 的页面）时必须报错 ——
// 绝不能从页面里"猜"一个版本号出来。
func TestLatestTagViaRedirectNoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>proxy login page</html>"))
	}))
	defer srv.Close()
	restore := releasesLatestURL
	releasesLatestURL = srv.URL + "/Lithivm/NetHub/releases/latest"
	defer func() { releasesLatestURL = restore }()

	if tag, err := latestTagViaRedirect(); err == nil {
		t.Fatalf("没有重定向却拿到了 tag=%q", tag)
	}
}

// 真实发布页的资产片段（2026-10-16 抓的 v0.7.0，裁掉无关标签，保留解析依赖的两处：
// href="/OWNER/REPO/releases/download/TAG/NAME" 与
// clipboard-copy id="clipboard-button-sha256:<64hex>" aria-label="Copy to clipboard digest for NAME"）。
const assetsHTMLFixture = `<div class="Box">
 <ul>
  <li class="Box-row d-flex">
   <span>
    <svg class="octicon"></svg>
    <a href="/Lithivm/NetHub/releases/download/v0.7.0/NetHub.zip" rel="nofollow" class="wb-break-all">
      <span class="text-bold">NetHub.zip</span>
    </a>
   </span>
   <div>
    <span class="Truncate-text">sha256:5121d6abc3b3b47781c90979ee62a9faa5dc9c7a94a056c64b289f6d4fd29791</span>
    <clipboard-copy id="clipboard-button-sha256:5121d6abc3b3b47781c90979ee62a9faa5dc9c7a94a056c64b289f6d4fd29791" aria-label="Copy to clipboard digest for NetHub.zip" value="sha256:5121d6abc3b3b47781c90979ee62a9faa5dc9c7a94a056c64b289f6d4fd29791" class="Button--invisible">
     <svg></svg>
    </clipboard-copy>
   </div>
  </li>
  <li class="Box-row d-flex">
   <span>
    <a href="/Lithivm/NetHub/releases/download/v0.7.0/NetHub.zip.sha256" rel="nofollow">
      <span class="text-bold">NetHub.zip.sha256</span>
    </a>
   </span>
   <div>
    <clipboard-copy id="clipboard-button-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" aria-label="Copy to clipboard digest for NetHub.zip.sha256" value="sha256:0123" class="Button--invisible">
     <svg></svg>
    </clipboard-copy>
   </div>
  </li>
  <li class="Box-row d-flex">
   <span>
    <a href="/Lithivm/NetHub/releases/download/v0.7.0/Source.tar.gz" rel="nofollow">
      <span class="text-bold">Source.tar.gz</span>
    </a>
   </span>
   <div>
    <clipboard-copy id="clipboard-button-sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" aria-label="Copy to clipboard digest for Source.tar.gz" value="sha256:ffff" class="Button--invisible">
     <svg></svg>
    </clipboard-copy>
   </div>
  </li>
 </ul>
</div>`

func TestAssetsViaHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/releases/expanded_assets/") {
			t.Errorf("请求的地址不对：%s", r.URL.Path)
		}
		if !strings.HasSuffix(r.URL.Path, "/v0.7.0") {
			t.Errorf("tag 没拼进地址：%s", r.URL.Path)
		}
		_, _ = w.Write([]byte(assetsHTMLFixture))
	}))
	defer srv.Close()
	restore := releasesAssetsURL
	releasesAssetsURL = srv.URL + "/Lithivm/NetHub/releases/expanded_assets/"
	defer func() { releasesAssetsURL = restore }()

	assets, err := assetsViaHTML("v0.7.0")
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	// 只要更新包：.sha256 与源码包都不该混进来（否则 pickAsset 可能选错文件）
	if len(assets) != 1 {
		t.Fatalf("想要 1 个 zip 资产，得到 %d 个：%+v", len(assets), assets)
	}
	a := assets[0]
	if a.Name != "NetHub.zip" {
		t.Fatalf("包名 = %q", a.Name)
	}
	if a.URL != srv.URL+"/Lithivm/NetHub/releases/download/v0.7.0/NetHub.zip" &&
		!strings.HasSuffix(a.URL, "/Lithivm/NetHub/releases/download/v0.7.0/NetHub.zip") {
		t.Fatalf("下载地址 = %q", a.URL)
	}
	const want = "5121d6abc3b3b47781c90979ee62a9faa5dc9c7a94a056c64b289f6d4fd29791"
	if a.SHA256 != want {
		t.Fatalf("摘要串了：%q", a.SHA256)
	}
}

func TestAssetsViaHTMLNoZIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<a href="/o/r/releases/download/v1/Source.tar.gz">Source.tar.gz</a>`))
	}))
	defer srv.Close()
	restore := releasesAssetsURL
	releasesAssetsURL = srv.URL + "/o/r/releases/expanded_assets/"
	defer func() { releasesAssetsURL = restore }()

	if _, err := assetsViaHTML("v1"); err == nil {
		t.Fatal("没有 zip 资产时应当报错（让上层回退 API），而不是返回空列表")
	}
}

func TestReleaseDownloadURL(t *testing.T) {
	got := releaseDownloadURL("v0.7.0", "NetHub.zip")
	want := "https://github.com/Lithivm/NetHub/releases/download/v0.7.0/NetHub.zip"
	if got != want {
		t.Fatalf("拼出来的地址是 %q，想要 %q", got, want)
	}
}
