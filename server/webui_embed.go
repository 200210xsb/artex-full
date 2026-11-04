//go:build embedui

package server

import (
	"compress/gzip"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// webuiDist holds the statically-exported frontend (built with
// `cd web && npm run build:static`, then copied into server/webui/dist). Compiled
// into the binary only when building with `-tags embedui`. The `all:` prefix is
// required so Next's `_next/` asset dir (leading underscore) is included.
//
//go:embed all:webui/dist
var webuiDist embed.FS

// webuiHandler serves the embedded SPA. Public (no JWT) — auth is enforced
// client-side and on /api. Serves the exported per-route index.html files and
// falls back to index.html so client-side routing still resolves unknown paths.
func (s *Server) webuiHandler() http.Handler {
	root, err := fs.Sub(webuiDist, "webui/dist")
	if err != nil {
		panic(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		// _next/static 下的文件名是构建期生成的稳定 ID，不是内容哈希：同一个文件名
		// 在两次构建之间内容会变。之前按 immutable 缓存一年，导致前端更新后浏览器
		// 一直用旧 chunk（页面行为对不上源码、改了看不到）。改成必须回源校验，
		// 命中的是 304，代价很小。
		if strings.HasPrefix(r.URL.Path, "/_next/static/") {
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		}
		// 1) exact file (assets: _next/*, favicon.ico, ...)
		// 2) route dir → <p>/index.html (trailingSlash export)
		// 3) <p>.html
		// 4) SPA 兜底 → index.html（交给客户端路由）
		for _, cand := range []string{p, p + "/index.html", p + ".html"} {
			if strings.HasSuffix(cand, ".html") {
				if serveHTMLWithBuildTag(w, r, root, cand) {
					return
				}
				continue
			}
			if serveFileIfExists(w, r, root, cand) {
				return
			}
		}
		if !serveHTMLWithBuildTag(w, r, root, "index.html") {
			http.NotFound(w, r)
		}
	})
	return gzipStatic(h)
}

// compressible 判断按扩展名是否值得 gzip（woff2/图片本身已经压过）。
// 无扩展名的路径（/、/function/devices/ 这类 SPA 路由）返回的是 HTML，也要压。
func compressible(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case "", ".js", ".css", ".html", ".json", ".svg", ".txt", ".ico":
		return true
	}
	return false
}

// gzipResponseWriter 边写边压，并去掉 ServeFile 预置的 Content-Length。
type gzipResponseWriter struct {
	http.ResponseWriter
	gz       *gzip.Writer
	wroteHdr bool
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if !g.wroteHdr {
		g.wroteHdr = true
		g.Header().Del("Content-Length")
		g.Header().Set("Content-Encoding", "gzip")
		g.Header().Add("Vary", "Accept-Encoding")
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.wroteHdr {
		g.WriteHeader(http.StatusOK)
	}
	return g.gz.Write(b)
}

// gzipStatic 给文本类静态资源加 gzip：Next 导出的 JS 有 5MB+，公网首屏很慢。
func gzipStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") || !compressible(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		gz := gzip.NewWriter(w)
		defer func() { _ = gz.Close() }()
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, gz: gz}, r)
	})
}

// webuiClearSiteDataOnce 控制是否在 HTML 响应上发 Clear-Site-Data: "cache"。
//
// 为什么需要它：_next/static 的文件名不含内容哈希，同一个名字在两次构建之间内容
// 会变。0.3.30 以前的响应头是 immutable（一年），浏览器一旦缓存过就一年不再回源；
// 光把响应头改成 no-cache 对那批老缓存无效——它们根本不会来问。
//
// 为什么不用「给资源引用加 ?v=<版本>」这种老办法（0.3.30 就是这么干的）：
// HTML 里的地址带了 ?v=，而 flight 载荷（RSC 文本）里引用的是**不带** ?v= 的地址。
// 同一个 chunk 因此变成两个 URL、两份缓存，运行时按载荷里的地址去拿时，命中的是
// 用户浏览器里那份老的 immutable 缓存——加载到的 chunk 和当前构建对不上，客户端
// 路由的 transition 永远提交不了，表现就是侧边栏点了没反应、只能手输地址。
// 线上 A/B 实测：去掉 ?v= 后点击立刻恢复正常。
//
// 现在改成：资源地址保持干净（不带版本号），_next/static 一律回源校验；
// 再在 HTML 上发一次 Clear-Site-Data: "cache"，把浏览器里那份老的 immutable 缓存
// 整个清掉。清完之后就是正常的「每次校验」行为，不再需要版本号。
//
// 这个开关发一个版本就够：0.3.35 / 0.3.36 各发过一次，老的 immutable 缓存已经
// 清干净，从 0.3.37 起关掉——再发下去只是让用户每次都白掉一次缓存。
var webuiClearSiteDataOnce = false

// serveHTMLWithBuildTag 读 HTML 并返回。
//
// 注意这里**不再**给静态资源引用加 ?v=，原因见 webuiClearSiteDataVer 的说明：
// 加了版本号会让 HTML 与 flight 载荷引用到两个不同的 chunk 地址，旧缓存混进来，
// 客户端路由会点不动。资源新鲜度改由「_next/static 回源校验 + 一次性清缓存」保证。
func serveHTMLWithBuildTag(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) bool {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return false
	}
	out := data
	// 兜底：静态资源引用上不许再带 ?v=（带了就和 flight 载荷里的地址对不上，
	// 旧 chunk 混进来，客户端路由会点不动）。见 webui_assets.go 的说明。
	out = webuiStripAssetVersion(out)
	// 用 http://用户:密码@host:port 打开时，凭据会留在 document.baseURI 里，把页面
	// 内所有相对 URL 的 fetch 打死——Next 客户端路由点不动、登录 POST 报「无法连接
	// 到后端服务」都是这一个原因。插一段探针让页面自己换回干净 URL。
	out = webuiInjectBaseURIFix(out)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// HTML 必须每次回源校验，否则新版本入口页本身也可能被缓存住。
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	if webuiClearSiteDataOnce {
		// 清掉浏览器里存了很久的 immutable 静态资源缓存，发一次即可。
		w.Header().Set("Clear-Site-Data", `"cache"`)
	}
	_, _ = w.Write(out)
	return true
}

// serveFileIfExists serves name from fsys when it exists as a regular file.
func serveFileIfExists(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	st, statErr := f.Stat()
	_ = f.Close()
	if statErr != nil || st.IsDir() {
		return false
	}
	http.ServeFileFS(w, r, fsys, name)
	return true
}
