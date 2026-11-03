package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// 本文件实现「任务可指定用哪个专用 agent」。
//
// 数据面:tasks.agent_key(可空)。NULL = 不绑定,任务继续用系统内置 agent 集
// (goals/planner/worker/mainagent),提示词行为与引入本特性之前【逐字一致】。
//
// 运行时:任务绑定了专项 agent 后,引擎在组装该任务的 planner/worker/main 系统
// 提示词时,把该 agent 的【当前提示词】
// (agents.current_prompt_id -> agent_prompts.template_text)作为一段
// 「本次任务专项指引」【追加】到提示词末尾。不替换任何原有提示词。
//
// 本文件只提供能力与片段;server.go 里的路由注册与 createTask 的请求字段改动,
// 见交付报告中的「待粘贴片段」。

// maxTaskAgentGuideRunes 限制「本次任务专项指引」的长度上限。
// 专项 agent 的提示词可能有几百 KB,全量塞进上下文会挤爆窗口、拖慢每个轮次。
// 超长则截断,并在段末注明「已截断」,让模型知道内容不完整。
const maxTaskAgentGuideRunes = 4000

// taskAgentGuideCacheTTL 是专项指引的缓存时长。
// 改 agent 提示词后最多 TTL 秒内生效(避免每个 agent 轮次都去查库)。
const taskAgentGuideCacheTTL = 20 * time.Second

// pgListTaskAgents 返回可绑定到任务的专项 agent 列表。
// GET /api/task-agents
func (s *Server) pgListTaskAgents(w http.ResponseWriter, _ *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	agents, err := pg.ListTaskAgents()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

// validateTaskAgentKey 校验请求里的 agent_key,返回归一化后的 key。
// 空串 = 不绑定专项 agent(默认,保持原行为)。校验失败返回带中文说明的错误,
// 调用方按 400 返回(不静默忽略)。
func (s *Server) validateTaskAgentKey(raw *string) (string, error) {
	normalized, err := db.NormalizeTaskAgentKey(db.AgentKeyString(raw))
	if err != nil {
		return "", errors.New("专项 agent 不合法：只允许小写字母、数字和下划线，且以字母开头")
	}
	if normalized == "" {
		return "", nil
	}
	if s == nil || s.m == nil || s.m.pg == nil {
		return "", errors.New("管理后台数据源(PostgreSQL)未连接，无法校验专项 agent")
	}
	if _, _, err := s.m.pg.ResolveTaskAgent(normalized); err != nil {
		switch {
		case errors.Is(err, db.ErrTaskAgentNotFound):
			return "", fmt.Errorf("专项 agent 不存在：%s", normalized)
		case errors.Is(err, db.ErrTaskAgentDisabled):
			return "", fmt.Errorf("专项 agent 已停用：%s", normalized)
		case errors.Is(err, db.ErrTaskAgentInvalid):
			return "", errors.New("专项 agent 不合法：只允许小写字母、数字和下划线，且以字母开头")
		}
		return "", err
	}
	return normalized, nil
}

// optionalAgentKey 把归一化后的 agent key 转成可空指针:空串 => nil(不绑定)。
func optionalAgentKey(key string) *string {
	if key == "" {
		return nil
	}
	return &key
}

// taskAgentGuideBlock 组装「本次任务专项指引」段落。
// 段落用明确的分隔标记包起来,便于模型识别边界,也便于人工在会话里核对。
// prompt 为空(agent 没有可用提示词)时返回空串 = 不追加任何内容。
func taskAgentGuideBlock(agentKey, agentName, prompt string) string {
	body := strings.TrimSpace(prompt)
	if body == "" {
		return ""
	}
	truncated := false
	if runes := []rune(body); len(runes) > maxTaskAgentGuideRunes {
		body = string(runes[:maxTaskAgentGuideRunes])
		truncated = true
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("=== 本次任务专项指引（来自 agent: %s）===", agentKey))
	b.WriteString("\n")
	if agentName != "" {
		b.WriteString(fmt.Sprintf("专项 agent：%s\n", agentName))
	}
	b.WriteString("以下是本任务绑定的专项 agent 的当前提示词，作为【追加指引】附加在本系统提示词末尾。\n")
	b.WriteString("它只补充、不替换上面的通用规则；若与上面的规则冲突，以上面的规则为准。\n\n")
	b.WriteString(body)
	if truncated {
		b.WriteString(fmt.Sprintf("\n\n（专项指引原文过长，已截断至 %d 字）", maxTaskAgentGuideRunes))
	}
	b.WriteString("\n=== 专项指引结束 ===")
	return b.String()
}

// taskAgentGuideEntry 是专项指引的缓存条目。
type taskAgentGuideEntry struct {
	guide     string
	fetchedAt time.Time
}

// taskAgentGuideCache 按 agent key 缓存已组装的专项指引。
// 进程级缓存即可:指引只依赖 agent 的当前提示词,短 TTL 内重查代价很低。
var taskAgentGuideCache = struct {
	mu      sync.Mutex
	entries map[string]taskAgentGuideEntry
}{entries: map[string]taskAgentGuideEntry{}}

// taskAgentGuide 返回指定专项 agent 的指引段落(带短 TTL 缓存)。
// agent 不存在 / 已停用 / 没有提示词 => 空串 —— 调用方按「无专项指引」处理,
// 任务行为与未绑定专项 agent 时完全一致。
func (s *Server) taskAgentGuide(agentKey string) string {
	if s == nil || s.m == nil || s.m.pg == nil || agentKey == "" {
		return ""
	}
	taskAgentGuideCache.mu.Lock()
	entry, ok := taskAgentGuideCache.entries[agentKey]
	taskAgentGuideCache.mu.Unlock()
	if ok && time.Since(entry.fetchedAt) < taskAgentGuideCacheTTL {
		return entry.guide
	}
	guide := ""
	if ag, prompt, err := s.m.pg.ResolveTaskAgent(agentKey); err == nil && ag != nil {
		// 用自定义 assistant agent 的变量集渲染一遍({{.Now}} / {{.DataDir}}),
		// 渲染失败时 RenderStoredPrompt 回退到原文。
		rendered := agent.RenderStoredPrompt(prompt, s.m.dir)
		guide = taskAgentGuideBlock(ag.Key, ag.Name, rendered)
	}
	taskAgentGuideCache.mu.Lock()
	taskAgentGuideCache.entries[agentKey] = taskAgentGuideEntry{guide: guide, fetchedAt: time.Now()}
	taskAgentGuideCache.mu.Unlock()
	return guide
}

// taskAgentGuideFn 返回该任务的「专项指引」解析器,交给 agent 的 SetPromptAppendix。
// 每次组提示词时读一次任务【当前】的 agent_key —— 任务中途改绑专项 agent 立即生效。
// agent_key 为空 => 返回空串,系统提示词与从前逐字一致(不追加任何内容)。
func (s *Server) taskAgentGuideFn(t *Task) agent.PromptAppendixFn {
	if t == nil {
		return nil
	}
	return func() string {
		key := strings.TrimSpace(t.agentKeyValue())
		if key == "" {
			return ""
		}
		return s.taskAgentGuide(key)
	}
}
