package server

import (
	"bytes"
	"regexp"
)

// webuiAssetRefRE 匹配 HTML 里指向构建产物的绝对路径（js / css），连同它后面可能
// 带的查询串——不把查询串吃进匹配范围的话，剥离时看不到 "?v="。
var webuiAssetRefRE = regexp.MustCompile(`/_next/static/[A-Za-z0-9._/-]+\.(?:js|css)(?:\?[^"'<> 	]*)?`)

// webuiStripAssetVersion 把 HTML 里静态资源引用上的 ?v= 版本标记去掉。
//
// 为什么必须去掉：加了版本号之后，HTML 引用的地址和 flight 载荷（RSC 文本）里
// 引用的地址不是同一个 URL，同一个 chunk 变成两份缓存。运行时按载荷里的地址去拿
// 时，命中的往往是用户浏览器里那份按 immutable 存了很久的旧 chunk——加载到的代码
// 和当前构建对不上，客户端路由的 transition 提交不了，表现就是侧边栏点不动、
// 只能手输地址整页刷新。
//
// 这里保留一层「兜底剥离」：万一以后有人又把版本号注入加回来，serve 时也会被
// 这里抹掉，不会再退化成点不动。资源新鲜度由「_next/static 回源校验 + 一次性
// Clear-Site-Data 清缓存」保证。
func webuiStripAssetVersion(html []byte) []byte {
	return webuiAssetRefRE.ReplaceAllFunc(html, func(m []byte) []byte {
		if i := bytes.Index(m, []byte("?v=")); i >= 0 {
			return m[:i]
		}
		return m
	})
}

// webuiAssetHasVersionTag 报告 HTML 里是否还带 ?v= 版本标记（回归守护用）。
func webuiAssetHasVersionTag(html []byte) bool {
	return webuiStripAssetVersion(html) != nil && !bytes.Equal(webuiStripAssetVersion(html), html)
}
