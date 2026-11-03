// ARTEX —— 任务「专项 agent」相关接口。
//
// 独立成文件的原因:api.ts / types.ts 由其它并行改动占用,本特性不碰它们。
// 这里只声明本特性需要的类型与调用方法,复用 api.ts 导出的 http()。
//
// 后端契约:
//   GET  /api/task-agents           -> { agents: [{ key, name, description }] }
//   POST /api/tasks                 -> 请求体多一个 agent_key(缺省=不绑定)
//   PATCH /api/tasks/{id}           -> 请求体可带 agent_key(null/""=解绑)
//   GET/POST/PATCH /api/task-templates -> 模板可带 agent_key(建任务时自动带上)

import { http } from "@/lib/api";
import type { AssetInterceptRuleInput, Task, TaskTemplate } from "@/lib/types";

// TaskAgent 是一个可绑定到任务的专用 agent(后端只返回已启用的自定义 assistant agent)。
export interface TaskAgent {
  key: string;
  name: string;
  description: string;
}

// TaskWithAgent 在 Task 基础上补上 agent_key。
// 后端在任务 JSON 里返回 agent_key(未绑定时缺省);types.ts 不可改,故在此扩展。
export interface TaskWithAgent extends Task {
  agent_key?: string;
}

// TaskTemplateWithAgent 在 TaskTemplate 基础上补上 agent_key(模板级绑定)。
export interface TaskTemplateWithAgent extends TaskTemplate {
  agent_key?: string | null;
}

// listTaskAgents 列出可绑定到任务的专项 agent。
export async function listTaskAgents(): Promise<TaskAgent[]> {
  const res = await http<{ agents?: TaskAgent[] | null }>("/task-agents");
  return res.agents ?? [];
}

// CreateTaskWithAgentInput 是创建任务的请求体。
// 字段与后端 createTaskReq 一一对应;agentKey 缺省=不绑定专项 agent。
export interface CreateTaskWithAgentInput {
  name?: string;
  categoryId?: number;
  description: string;
  goal: string;
  llmProfileIds?: number[];
  sourceTaskIds?: string[];
  companyIds?: number[];
  timeoutSeconds?: number;
  seedFirstIntent?: boolean;
  planHeartbeatSeconds?: number;
  coverageEnabled?: boolean;
  interceptRules?: AssetInterceptRuleInput[];
  // agentKey:专项 agent 的 key;空/省略=不绑定(默认,行为与从前一致)。
  agentKey?: string;
}

// createTaskWithAgent 创建任务并可携带专项 agent。
export async function createTaskWithAgent(input: CreateTaskWithAgentInput): Promise<TaskWithAgent> {
  return http<TaskWithAgent>("/tasks", {
    method: "POST",
    body: JSON.stringify({
      name: input.name ?? "",
      category_id: input.categoryId ?? null,
      description: input.description,
      goal: input.goal,
      llm_profile_ids: input.llmProfileIds ?? [],
      source_task_ids: input.sourceTaskIds ?? [],
      company_ids: input.companyIds ?? [],
      timeout_seconds: input.timeoutSeconds ?? 0,
      seed_first_intent: input.seedFirstIntent ?? false,
      plan_heartbeat_seconds: input.planHeartbeatSeconds ?? 0, // 0 = 后端归一到默认 600(10min)
      coverage_enabled: input.coverageEnabled ?? true, // 默认开;false=关闭资产覆盖度功能
      intercept_rules: input.interceptRules ?? [], // 任务级资产拦截规则
      agent_key: input.agentKey || null, // null=不绑定专项 agent
    }),
  });
}

// updateTaskAgentKey 改绑/解绑任务的专项 agent。
// agentKey 传空串或 null 表示解绑(回到默认行为)。下一次组提示词时立即生效。
export async function updateTaskAgentKey(taskId: string, agentKey: string | null): Promise<TaskWithAgent> {
  return http<TaskWithAgent>(`/tasks/${encodeURIComponent(taskId)}`, {
    method: "PATCH",
    body: JSON.stringify({ agent_key: agentKey || null }),
  });
}

// TaskTemplateWithAgentInput 是任务模板的创建/更新请求体。
export interface TaskTemplateWithAgentInput {
  name: string;
  description: string;
  goal: string;
  category_id?: number | null;
  intercept_rules?: AssetInterceptRuleInput[];
  // agent_key:模板级专项 agent;null/省略=不带。
  agent_key?: string | null;
}

// createTaskTemplateWithAgent 创建带专项 agent 的任务模板。
export async function createTaskTemplateWithAgent(
  input: TaskTemplateWithAgentInput,
): Promise<TaskTemplateWithAgent> {
  return http<TaskTemplateWithAgent>("/task-templates", {
    method: "POST",
    body: JSON.stringify({ ...input, agent_key: input.agent_key || null }),
  });
}

// updateTaskTemplateWithAgent 更新任务模板(可改专项 agent 绑定)。
export async function updateTaskTemplateWithAgent(
  id: number,
  input: TaskTemplateWithAgentInput,
): Promise<TaskTemplateWithAgent> {
  return http<TaskTemplateWithAgent>(`/task-templates/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ ...input, agent_key: input.agent_key || null }),
  });
}

// taskAgentLabel 返回专项 agent 的展示名(优先名称,回退 key)。
export function taskAgentLabel(agent: TaskAgent | null | undefined): string {
  if (!agent) return "";
  return agent.name || agent.key;
}

// findTaskAgent 按 key 在列表里找 agent。
export function findTaskAgent(agents: TaskAgent[], key: string | null | undefined): TaskAgent | null {
  if (!key) return null;
  return agents.find((agent) => agent.key === key) ?? null;
}
