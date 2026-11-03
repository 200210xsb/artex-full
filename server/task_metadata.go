package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

const (
	maxTaskNameRunes           = 200
	maxTaskMetadataRequestSize = 16 << 10
)

// taskMetadataRequest 是任务元数据 PATCH 的请求体。
// AgentKey 用 *string:显式传 null / "" 表示「解绑专项 agent」,与「未提供」不同,
// 故另用顶层 key 集合判定存在性(见 decodeTaskMetadataRequest)。
type taskMetadataRequest struct {
	Name    *string `json:"name"`
	Pinned  *bool   `json:"pinned"`
	AgentKey *string `json:"agent_key"`
}

// decodeTaskMetadataRequest 读取并解析请求体,返回「agent_key 是否出现」。
// 第二个返回值 false 表示解析失败(已写过错误响应)。
func decodeTaskMetadataRequest(w http.ResponseWriter, r *http.Request, req *taskMetadataRequest) (bool, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskMetadataRequestSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return false, false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return false, false
	}
	if err := json.Unmarshal(body, req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return false, false
	}
	_, present := raw["agent_key"]
	return present, true
}

// updateTaskMetadata changes list-only task metadata. It intentionally does not
// touch lifecycle state, scheduling, or the task's immutable description/goal.
// agent_key IS supported here: rebinding the task's 专项 agent takes effect on the
// next agent turn (the guidance block is resolved per prompt assembly).
func (s *Server) updateTaskMetadata(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	if _, ok := s.m.Task(taskID); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	var request taskMetadataRequest
	agentKeyPresent, ok := decodeTaskMetadataRequest(w, r, &request)
	if !ok {
		return
	}
	if request.Name == nil && request.Pinned == nil && !agentKeyPresent {
		writeErr(w, http.StatusBadRequest, "至少需要提供 name、pinned 或 agent_key")
		return
	}
	if request.Name != nil {
		name := strings.TrimSpace(*request.Name)
		if name == "" {
			writeErr(w, http.StatusBadRequest, "任务名称不能为空")
			return
		}
		if utf8.RuneCountInString(name) > maxTaskNameRunes {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("任务名称最多 %d 个字符", maxTaskNameRunes))
			return
		}
		request.Name = &name
	}
	patch := db.TaskPatch{Name: request.Name, Pinned: request.Pinned}
	if agentKeyPresent {
		key, err := s.validateTaskAgentKey(request.AgentKey)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		patch.SetAgentKey = true
		if key == "" {
			patch.AgentKey = nil // 解绑
		} else {
			patch.AgentKey = &key
		}
	}
	task, err := s.m.UpdateTaskMetadata(taskID, patch)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if task == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, taskDTO(task, s.resolvedTaskStatus(task)))
}
