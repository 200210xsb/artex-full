//go:build embedui

package server

import (
	"compress/gzip"
	"embed"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
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

// webuiAssetRefRE 匹配 HTML 里指向构建产物的绝对路径（js / css）。
var webuiAssetRefRE = regexp.MustCompile(`/_next/static/[A-Za-z0-9._/-]+\.(?:js|css)`)

// serveHTMLWithBuildTag 读 HTML，给静态资源引用补 ?v=<BuildVersion> 再返回。
//
// 为什么需要：_next/static 的文件名不含内容哈希，同一个名字在两次构建之间内容会变。
// 浏览器一旦按旧的 immutable 头缓存过（历史上确实是这么发的），光把响应头改掉不会
// 让它重新拉取——只有 URL 变了才会。带上版本号相当于每次发布换一次资源地址，
// 老缓存自动失效，用户不用手动强刷。
func serveHTMLWithBuildTag(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) bool {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return false
	}
	ver := strings.TrimSpace(BuildVersion)
	if ver == "" {
		ver = "dev"
	}
	suffix := "?v=" + url.QueryEscape(ver)
	out := webuiAssetRefRE.ReplaceAllFunc(data, func(m []byte) []byte {
		if strings.Contains(string(m), "?") {
			return m
		}
		return append(append([]byte{}, m...), []byte(suffix)...)
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// HTML 必须每次回源校验，否则新版本入口页本身也可能被缓存住。
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
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
