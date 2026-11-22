package server

import (
	"net/http"
)

// llmHuntPage 把旧的独立页重定向到 SPA 里的正式页面。
//
// 曾经这里放了一份**自包含**的 HTML（不依赖前端 bundle），后来功能被并入 SPA
// （/function/llm-hunt），那份副本就停在初版再没更新过：字段比 SPA 少
// （没有 allow_auth / auto_verify / repeat / hunt_leaks），于是它悄悄吃到服务端
// 的"默认口令探测默认开"默认值，行为与用户看到的 SPA 不一致；界面也缺了后来
// 加的多维筛选、状态区分、导出等。留着两份 UI 只会继续漂移，所以这里改成跳转，
// 保留旧书签可用。
func (s *Server) llmHuntPage(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/function/llm-hunt", http.StatusFound)
}
