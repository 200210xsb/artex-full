package agent

import "strings"

// 本文件提供「按实例追加系统提示词」的钩子。
//
// 背景:系统提示词正文(段 [A])是【按 agent 角色】全局的 —— planner/worker/
// mainagent 各一份,可以在 agent 管理页里编辑。但任务级的额外指引(例如
// 「本任务用 mobile 专项 agent」)是【按任务实例】的,不能进全局正文,
// 否则会把一个任务的专项要求泄漏到所有任务。
//
// 因此这里给每个 agent 实例一个可选的追加钩子:
//   - 不设置(nil)或返回空串 => 系统提示词一字不改,行为与从前完全一致。
//   - 返回非空 => 以「\n\n」+ 追加内容 的形式拼到系统提示词正文末尾。
//
// 追加内容的长度控制由实现方负责(见 server 侧 taskAgentGuideBlock)。

// PromptAppendixFn 返回追加到系统提示词末尾的补充段落。
// 返回空串(或纯空白)表示不追加。
type PromptAppendixFn func() string

// appendPromptAppendix 把附录拼到系统提示词正文末尾。
// 空附录不改原提示词 —— 保证未绑定专项 agent 的任务行为与从前完全一致。
func appendPromptAppendix(body string, fn PromptAppendixFn) string {
	if fn == nil {
		return body
	}
	extra := fn()
	if strings.TrimSpace(extra) == "" {
		return body
	}
	return body + "\n\n" + extra
}

// RenderStoredPrompt 渲染库里存的提示词正文,用的是【自定义 assistant agent】
// 那一套变量 ({{.DataDir}} / {{.Now}})。渲染失败(模板里引用了目录外的变量)
// 时回退到原文,保证坏模板也能产出可用的指引文本,不会把任务提示词搞崩。
func RenderStoredPrompt(tmpl string, dataDir string) string {
	if strings.TrimSpace(tmpl) == "" {
		return ""
	}
	if out, err := renderTmpl(tmpl, chatVars{DataDir: dataDir, Now: nowStr()}); err == nil {
		return out
	}
	return tmpl
}
