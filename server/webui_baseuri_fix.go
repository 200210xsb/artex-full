package server

import "bytes"

// webuiBaseURIFixScript 修「用 http://用户:密码@host:port/ 打开控制台，侧边栏点不动、
// 登录还提示无法连接到后端服务」的问题。
//
// 机理：地址栏里带 user:pass@ 时，浏览器会把凭据保留在 document.baseURI 里（虽然
// location.href / location.origin 已被剥干净）。而 Fetch 规范禁止从「含凭据的 URL」
// 构造请求，所以页面里任何相对路径的 new Request("/xxx") / fetch("/xxx") 都会抛
//
//	TypeError: Request cannot be constructed from a URL that includes credentials
//
// Next 的客户端路由（<Link> / router.push）正是 fetch(相对URL, {RSC:1}) 拉 RSC 数据，
// 于是表现为：点菜单毫无反应、只能手输地址整页刷新（document 导航不走这条限制）；
// 登录页 POST /api/auth/login 同样是相对 URL，于是又打出「无法连接到后端服务」。
//
// 修法：进页面先看 document.baseURI 的主机段里有没有 userinfo（`scheme://xxx@host`
// 这种形态）。有就用 origin + path + search + hash 拼一个干净 URL 换过去——这几项
// 都不含凭据。浏览器对 Basic 凭据有会话级缓存，换过去不会二次弹框。
//
// 为什么用正则看 baseURI、而不是探 new Request("/") 抛不抛错：Request 抛错的原因
// 可能不止一种（将来别的规范限制也算），正则只认「baseURI 确实带 userinfo」这一件
// 事，不会误伤。也不能拿 location.href 判断——浏览器早把 href 里的凭据剥掉了，
// 拿它做客只会永远探不出来（这一点踩过）。
//
// 为什么不是「每个标签页只修一次」：那样用户在同一个标签页里点书签、又进了一次带
// 凭据的地址，自愈就被 sessionStorage 挡掉了（实测确实复现）。现在每次都判断，
// 而判断条件本身幂等——baseURI 干净时正则不匹配，什么都不做，所以也不会成环。
// sessionStorage 只留一个次数上限兜底，防的是浏览器把干净 URL 又还原成带凭据的
// 病态情况（0 次 → 1 次 → 2 次后就放手，绝不无限重载）。
const webuiBaseURIFixScript = `<script>(function(){try{` +
	`var b=document.baseURI||"";` +
	`if(!/^[a-z][a-z0-9+.-]*:\/\/[^\/@]*@/i.test(b))return;` +
	`var k="artex:cleanurl",n=parseInt(sessionStorage.getItem(k)||"0",10);` +
	`if(n>2)return;sessionStorage.setItem(k,String(n+1));` +
	`location.replace(location.origin+location.pathname+location.search+location.hash)` +
	`}catch(e){}})();</script>`

// webuiInjectBaseURIFix 把上面的探针脚本插进 <head> 开头之后：要早于 Next 的
// module 脚本执行，否则 hydration 里的首次路由/请求可能已经先失败了。
// 找不到 <head> 时原样返回（Next 导出的每一页都有 head，这里只是不冒险乱插）。
func webuiInjectBaseURIFix(html []byte) []byte {
	if bytes.Contains(html, []byte("artex:cleanurl")) {
		return html // 已经插过（防止上游重复调用导致脚本跑两遍）
	}
	pos := webuiHeadEnd(html)
	if pos < 0 {
		return html
	}
	out := make([]byte, 0, len(html)+len(webuiBaseURIFixScript))
	out = append(out, html[:pos]...)
	out = append(out, webuiBaseURIFixScript...)
	out = append(out, html[pos:]...)
	return out
}

// webuiHeadEnd 返回 <head ...> 开标签结束后的偏移（即插入点），没有则 -1。
func webuiHeadEnd(html []byte) int {
	i := bytes.Index(html, []byte("<head"))
	if i < 0 {
		return -1
	}
	j := bytes.IndexByte(html[i:], '>')
	if j < 0 {
		return -1
	}
	return i + j + 1
}
