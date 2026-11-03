// 资产中枢的新接口客户端：血缘 / 覆盖度 / POC 联动。
//
// 与 lib/api.ts 分开放：那边正在被并行改动，这里只复用它的 http 助手
// （鉴权、错误消息、401 跳转都走同一条路径）。

import { http } from "@/lib/api";

// ---- 血缘 ----

/** 一条发现来源：哪个任务、用什么方式关联的。 */
export interface AssetLineageSource {
  task_id: number;
  task_name: string;
  task_status?: string;
  source: string;
  source_summary?: string;
  source_node_id?: number;
  linked_at?: string;
}

/** 一条资产的完整血缘。 */
export interface AssetLineage {
  id: number;
  type: string;
  label: string;
  domain?: string;
  root_domain?: string;
  ip?: string;
  port?: number;
  url?: string;
  bundle_id?: string;
  technologies?: string[];
  task_ids?: number[];
  company_id?: number;
  company_name?: string;
  company_source?: string;
  created_at?: string;
  updated_at?: string;
  last_seen?: string;
  /** 是否落在查询指定的任务范围内 */
  in_scope: boolean;
  /** 同根域名（同企业时同企业）下的兄弟资产数量 */
  sibling_count: number;
  sources: AssetLineageSource[];
}

// ---- 覆盖度 ----

export interface AssetCoverageByType {
  type: string;
  total: number;
  tested: number;
}

export interface AssetCoverage {
  enabled: boolean;
  /** global = 按 DSL 过滤的全库视图；task = 指定任务的范围内视图 */
  scope: "global" | "task";
  scope_rows?: number;
  denominator: number;
  tested: number;
  untested: number;
  pct?: number | null;
  by_type: AssetCoverageByType[];
}

// ---- POC 联动 ----

/** 参与匹配的一条资产。 */
export interface PocMatchAsset {
  asset_id: number;
  label: string;
  target: string;
  type: string;
  fingerprints: string[];
}

/** 一个候选模板（资产 × 模板）。 */
export interface PocCandidate {
  asset_id: number;
  asset_label: string;
  target: string;
  template_id: string;
  name: string;
  severity: string;
  tags: string;
  path: string;
  /** 命中的指纹关键词 */
  matched: string[];
  /** 拿 shell 概率档位 A/B/C/D */
  tier: string;
  tier_label: string;
  score: number;
  advice: string;
}

export interface PocMatchResult {
  assets: PocMatchAsset[];
  candidates: PocCandidate[];
  total: number;
  limit: number;
  templates_scanned: number;
  templates_eligible: number;
  warning?: string;
}

export interface PocMatchRequest {
  asset_ids?: number[];
  dsl?: string;
  type?: string;
  limit?: number;
}

export const assetsApi = {
  /** 资产血缘：谁发现的、什么时候发现的、归属谁。 */
  lineage: (params: { ids?: number[]; id?: number; dsl?: string; type?: string; taskId?: number }) => {
    const q = new URLSearchParams();
    if (params.ids?.length) q.set("ids", params.ids.join(","));
    if (params.id != null) q.set("id", String(params.id));
    if (params.dsl) q.set("dsl", params.dsl);
    if (params.type) q.set("type", params.type);
    if (params.taskId != null) q.set("task_id", String(params.taskId));
    return http<{ assets: AssetLineage[]; total: number }>(`/assets/lineage?${q.toString()}`).then((r) => ({
      assets: r?.assets ?? [],
      total: r?.total ?? 0,
    }));
  },

  /** 资产覆盖度：范围内总数 / 已测 / 未测 / 按类型分布。 */
  coverage: (params: { dsl?: string; type?: string; taskId?: number } = {}) => {
    const q = new URLSearchParams();
    if (params.dsl) q.set("dsl", params.dsl);
    if (params.type) q.set("type", params.type);
    if (params.taskId != null) q.set("task_id", String(params.taskId));
    return http<AssetCoverage>(`/assets/coverage?${q.toString()}`);
  },

  /** 指纹 → POC 候选：只放行 high/critical/medium 且能落地的模板。 */
  pocMatch: (body: PocMatchRequest) =>
    http<PocMatchResult>("/assets/poc-match", {
      method: "POST",
      body: JSON.stringify(body),
    }).then((r) => ({
      assets: r?.assets ?? [],
      candidates: r?.candidates ?? [],
      total: r?.total ?? 0,
      limit: r?.limit ?? 0,
      templates_scanned: r?.templates_scanned ?? 0,
      templates_eligible: r?.templates_eligible ?? 0,
      warning: r?.warning,
    })),

  /** 批量改企业归属（company_id=0 表示取消归属）。 */
  attribute: (ids: number[], companyId: number) =>
    http<{ updated: number }>("/assets/attribute", {
      method: "POST",
      body: JSON.stringify({ ids, company_id: companyId }),
    }),
};

/** 资产类型的展示名（前端表格与文案统一用这套）。 */
export const ASSET_TYPE_LABEL: Record<string, string> = {
  root_domain: "根域名",
  ip: "IP",
  subdomain: "子域名",
  app: "应用",
  service: "服务",
  endpoint: "接口",
};

/** 资产来源（task_asset_links.source）的中文说明。 */
export const ASSET_SOURCE_LABEL: Record<string, string> = {
  system: "任务自动关联",
  manual: "人工登记",
  api: "通过资产 API 登记",
  legacy: "历史迁移",
  agent: "Agent 上报",
};

/** 企业归属方式（assets.company_source）的中文说明。 */
export const COMPANY_SOURCE_LABEL: Record<string, string> = {
  explicit: "人工指定",
  scope: "范围命中",
  task: "任务关联企业",
};
