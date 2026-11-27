"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowUpRightIcon, RouteIcon, SearchIcon } from "lucide-react";

import { FindingDiscoveryPathPanel } from "@/components/finding-discovery-path";
import { StatusBadge } from "@/components/status-badge";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { cn } from "@/lib/utils";

// 发现路径：独立功能页。
//
// 左边选一条漏洞，右边把它「怎么被发现的」摊成白话时间线：
// 溯源（最早的采集/事实 → 派生的意图 → 本条漏洞）→ 目标判定（为什么打这个入口）
// → 实测请求序列（命中那条高亮）→ 决定性证据（原始请求/响应）。
//
// 数据全部来自已有记录（图谱边、意图文本、该意图的 Bash 调用、已绑定的流量快照），
// 只读，不重新探测，历史漏洞一样能看。
export default function DiscoveryPathPage() {
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [query, setQuery] = React.useState("");
  const [selected, setSelected] = React.useState<string>("");

  React.useEffect(() => {
    let alive = true;
    api
      .findings()
      .then((list) => {
        if (!alive) return;
        const sorted = [...list].sort((a, b) => (a.ts < b.ts ? 1 : -1));
        setFindings(sorted);
        const first = sorted.find((f) => f.finding_id);
        if (first?.finding_id) setSelected(first.finding_id);
      })
      .catch(() => {
        if (alive) setFindings([]);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  const filtered = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return findings;
    return findings.filter((f) =>
      [f.name, f.vulnclass, f.summary, f.task_description, f.task_id]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q)),
    );
  }, [findings, query]);

  const current = findings.find((f) => f.finding_id === selected);

  return (
    <div data-content-padding={false} className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        <RouteIcon className="size-4 text-muted-foreground" />
        <h1 className="text-sm font-semibold">发现路径</h1>
        <span className="text-muted-foreground text-xs">
          一条漏洞是从哪条线索长出来的、打的哪个入口、发了哪些请求
        </span>
      </div>

      <div className="flex min-h-0 flex-1">
        {/* 左：漏洞清单 */}
        <div className="flex w-80 shrink-0 flex-col border-r border-border">
          <div className="border-b border-border p-2">
            <InputGroup>
              <InputGroupAddon>
                <SearchIcon className="size-3.5" />
              </InputGroupAddon>
              <InputGroupInput
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="搜漏洞名 / 类别 / 任务"
                className="h-8 text-xs"
              />
            </InputGroup>
            <p className="text-muted-foreground mt-1.5 px-0.5 text-[11px]">
              共 {findings.length} 条{query ? `，命中 ${filtered.length} 条` : ""}
            </p>
          </div>
          <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto">
            {loading ? (
              <div className="flex items-center justify-center py-10">
                <Spinner className="size-4" />
              </div>
            ) : filtered.length === 0 ? (
              <p className="text-muted-foreground p-4 text-xs">没有匹配的漏洞。</p>
            ) : (
              filtered.map((f) => {
                const id = f.finding_id ?? "";
                const active = id && id === selected;
                return (
                  <button
                    key={`${f.id}-${id}`}
                    type="button"
                    disabled={!id}
                    onClick={() => id && setSelected(id)}
                    className={cn(
                      "flex w-full flex-col items-start gap-1 border-b border-border/40 px-3 py-2 text-left transition-colors",
                      active ? "bg-primary/10" : "hover:bg-muted/60",
                      !id && "opacity-50",
                    )}
                  >
                    <div className="flex w-full items-center gap-1.5">
                      <StatusBadge domain="severity" value={f.severity} dot />
                      <span className="min-w-0 flex-1 truncate text-xs font-medium">
                        {f.name || f.vulnclass || "未分类"}
                      </span>
                    </div>
                    <span className="text-muted-foreground line-clamp-2 text-[11px]">{f.summary}</span>
                    <span className="text-muted-foreground text-[10px]">
                      {f.task_description ? `任务：${f.task_description}` : `任务 #${f.task_id ?? "-"}`}
                    </span>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* 右：时间线 */}
        <div className="scrollbar-thin min-w-0 flex-1 overflow-y-auto p-4">
          {!selected ? (
            <p className="text-muted-foreground text-xs">左侧选一条漏洞查看它的发现路径。</p>
          ) : (
            <div className="mx-auto flex max-w-4xl flex-col gap-3">
              {current && (
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge domain="severity" value={current.severity} dot />
                  <span className="text-sm font-semibold">{current.name || current.vulnclass}</span>
                  <Link
                    href={`/function/findings/detail?id=${selected}`}
                    className="text-primary inline-flex items-center gap-0.5 text-[11px] hover:underline"
                  >
                    漏洞详情
                    <ArrowUpRightIcon className="size-3" />
                  </Link>
                </div>
              )}
              <FindingDiscoveryPathPanel findingId={selected} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
