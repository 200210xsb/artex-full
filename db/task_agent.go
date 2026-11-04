package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// 任务级【专项 agent】绑定。
//
// 语义:tasks.agent_key / task_templates.agent_key 均为可空列。
//   - NULL(默认):任务不绑定专项 agent,继续用系统内置 agent 集
//     (goals/planner/worker/mainagent),提示词行为与引入本特性之前完全一致。
//   - 非空:指向 agents.key 的一个已启用 agent。引擎在组装该任务的
//     planner/worker/main 系统提示词时,把该 agent 的【当前提示词】
//     (agents.current_prompt_id -> agent_prompts.template_text)作为一段
//     「本次任务专项指引」追加到提示词末尾。只追加、不替换原有提示词。
//
// 本文件提供:可选 agent 列表、agent_key 归一化/校验、当前提示词读取。

var (
	// ErrTaskAgentInvalid 表示 agent_key 非法(超长/字符集不合法)。
	ErrTaskAgentInvalid = errors.New("invalid task agent key")
	// ErrTaskAgentNotFound 表示 agents 表里不存在这个 key。
	ErrTaskAgentNotFound = errors.New("task agent not found")
	// ErrTaskAgentDisabled 表示 agent 存在但已被停用。
	ErrTaskAgentDisabled = errors.New("task agent disabled")
)

// MaxTaskAgentKeyRunes 是 agent_key 的长度上限(与 agents.key 的实际长度相当)。
const MaxTaskAgentKeyRunes = 64

// agentKeyValue 把可空的 agent_key 指针转成字符串(nil 指针 => 空串)。
func agentKeyValue(key *string) string {
	if key == nil {
		return ""
	}
	return *key
}

// AgentKeyString 返回任务的专项 agent key(未绑定 => 空串)。
func AgentKeyString(key *string) string { return agentKeyValue(key) }

// nullString 把可空字符串指针转成可直接传给 SQL 的参数(nil / 空串 => SQL NULL)。
func nullString(value *string) any {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}

// TaskAgent 是一个可绑定到任务的专用 agent(自定义 assistant agent)。
type TaskAgent struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ListTaskAgents 返回可绑定到任务的【已启用】agent。
// 只返回 role='assistant' 的 agent:内置角色(goals/planner/worker/mainagent/
// auto/pentest)是系统执行角色,不是「专项指引」的来源。
func (d *DB) ListTaskAgents() ([]TaskAgent, error) {
	rows, err := d.Query(`
SELECT key, name, COALESCE(description,'')
FROM agents
WHERE enabled AND role='assistant'
ORDER BY name, key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskAgent{}
	for rows.Next() {
		var a TaskAgent
		if err := rows.Scan(&a.Key, &a.Name, &a.Description); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// NormalizeTaskAgentKey 归一化并校验 agent_key。
//   - 空串/纯空白 => ("", nil):表示「不绑定专项 agent」,调用方按默认行为处理。
//   - 超过 MaxTaskAgentKeyRunes 或字符集不合法 => ErrTaskAgentInvalid。
// 字符集与 agents.key 的数据库约束保持一致:小写字母开头,后接小写字母/数字/下划线。
func NormalizeTaskAgentKey(key string) (string, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "", nil
	}
	if len([]rune(trimmed)) > MaxTaskAgentKeyRunes {
		return "", fmt.Errorf("%w: agent key exceeds %d characters", ErrTaskAgentInvalid, MaxTaskAgentKeyRunes)
	}
	for i, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		case r == '_' && i > 0:
		default:
			return "", fmt.Errorf("%w: agent key must match ^[a-z][a-z0-9_]*$", ErrTaskAgentInvalid)
		}
	}
	return trimmed, nil
}

// ValidateTaskAgentKey 校验 agent_key 指向的 agent 存在且已启用。
// 空串表示不绑定,直接放行(保持默认行为)。
func (d *DB) ValidateTaskAgentKey(key string) error {
	normalized, err := NormalizeTaskAgentKey(key)
	if err != nil {
		return err
	}
	if normalized == "" {
		return nil
	}
	var enabled bool
	err = d.QueryRow(`SELECT enabled FROM agents WHERE key=$1`, normalized).Scan(&enabled)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: %s", ErrTaskAgentNotFound, normalized)
	}
	if err != nil {
		return err
	}
	if !enabled {
		return fmt.Errorf("%w: %s", ErrTaskAgentDisabled, normalized)
	}
	return nil
}

// TaskAgentPrompt 返回指定 agent 的【当前提示词】正文
// (agents.current_prompt_id -> agent_prompts.template_text)。
// agent 不存在 => ErrTaskAgentNotFound;agent 没有可用提示词 => 返回空串、nil。
func (d *DB) TaskAgentPrompt(key string) (string, error) {
	var tmpl string
	err := d.QueryRow(`
SELECT COALESCE(p.template_text,'')
FROM agents a
LEFT JOIN agent_prompts p ON p.id = a.current_prompt_id
WHERE a.key = $1`, key).Scan(&tmpl)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("%w: %s", ErrTaskAgentNotFound, key)
	}
	if err != nil {
		return "", err
	}
	return tmpl, nil
}

// ResolveTaskAgent 一次性取回 agent 的元信息与当前提示词正文,
// 并校验 agent 存在且已启用。校验失败时返回对应错误
// (ErrTaskAgentNotFound / ErrTaskAgentDisabled)。
func (d *DB) ResolveTaskAgent(key string) (*TaskAgent, string, error) {
	normalized, err := NormalizeTaskAgentKey(key)
	if err != nil {
		return nil, "", err
	}
	if normalized == "" {
		return nil, "", nil
	}
	var a TaskAgent
	var enabled bool
	err = d.QueryRow(`
SELECT key, name, COALESCE(description,''), enabled
FROM agents WHERE key=$1`, normalized).Scan(&a.Key, &a.Name, &a.Description, &enabled)
	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("%w: %s", ErrTaskAgentNotFound, normalized)
	}
	if err != nil {
		return nil, "", err
	}
	if !enabled {
		return nil, "", fmt.Errorf("%w: %s", ErrTaskAgentDisabled, normalized)
	}
	prompt, err := d.TaskAgentPrompt(normalized)
	if err != nil {
		return nil, "", err
	}
	return &a, prompt, nil
}

// TaskAgentKeyForTask 返回任务绑定的专项 agent key（未绑定 => 空串）。
//
// 装配工具时要用它：任务的专项 agent 只负责「提示词附加」，真正执行的角色固定是
// worker/planner/main，而 MCP 可见性是按角色 key 查的。不把这层转接补上，攻防
// agent 手里的 Webshell/Nuclei 就永远到不了干活的那一端——目标要求「拿 shell」
// 的任务只能在报告里写「工具不可用」，页面上一条会话都没有。
func (d *DB) TaskAgentKeyForTask(taskID int64) (string, error) {
	if taskID == 0 {
		return "", nil
	}
	var key sql.NullString
	err := d.QueryRow(`SELECT agent_key FROM tasks WHERE id=$1`, taskID).Scan(&key)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(key.String), nil
}
