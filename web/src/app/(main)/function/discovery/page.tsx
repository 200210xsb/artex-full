"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowUpRightIcon, ChevronLeftIcon, ChevronRightIcon, RouteIcon, SearchIcon } from "lucide-react";

import { FindingDiscoveryPathPanel } from "@/components/finding-discovery-path";
import { StatusBadge } from "@/components/status-badge";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingStats, FindingStatus, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

// 发现路径：独立功能页。
//
// 筛选条与「发现」页保持一致（检索 + 严重度 + 状态 + 漏洞类型 + 任务 + 排序，
// 全部走后端 findingsPage 的同一套筛选参数）；左边列出命中的漏洞，右边把选中
// 那条漏洞「怎么被发现的」摊成白话时间线：
// 溯源 → 目标判定 → 实测请求 → 决定性证据。只读派生，不重新探测。
const PAGE_SIZE = 30;

const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

const EMPTY_STATS: FindingStats = {
  total: 0,
  pending: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  vulnclasses: [],
  tasks: [],
};

export default function DiscoveryPathPage() {
  const [search, setSearch] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [severity, setSeverity] = React.useState<"all" | Severity>("all");
  const [status, setStatus] = React.useState<"all" | FindingStatus>("all");
  const [vulnclass, setVulnclass] = React.useState("all");
  const [task, setTask] = React.useState("all");
  const [sort, setSort] = React.useState<"severity" | "time">("time");
  const [page, setPage] = React.useState(1);

  const [items, setItems] = React.useState<Finding[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [stats, setStats] = React.useState<FindingStats>(EMPTY_STATS);
  const [selected, setSelected] = React.useState("");

  // 检索防抖：输入停 300ms 再打请求，避免每个按键都发一次。
  React.useEffect(() => {
    const t = setTimeout(() => setQuery(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);

  React.useEffect(() => {
    setPage(1);
  }, [query, severity, status, vulnclass, task, sort]);

  React.useEffect(() => {
    api
      .findingStats()
      .then((s) => setStats(s))
      .catch(() => {});
  }, []);

  // 拉当前页；筛选变了就整页替换。
  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .findingsPage({
        page,
        pageSize: PAGE_SIZE,
        severity,
        status,
        vulnclass,
        task,
        query,
        sort,
      })
      .then((r) => {
        if (!alive) return;
        setItems(r.items ?? []);
        setTotal(r.total ?? 0);
        // 选中项不在当前页时，自动选第一条可查的
        const pick = (r.items ?? []).find((f) => f.finding_id && f.finding_id === selected);
        if (!pick) {
          const first = (r.items ?? []).find((f) => f.finding_id);
          setSelected(first?.finding_id ?? "");
        }
      })
      .catch(() => {
        if (alive) {
          setItems([]);
          setTotal(0);
        }
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
    // selected 故意不进依赖：只在换页/换筛选时重选
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, query, severity, status, vulnclass, task, sort]);

  const current = items.find((f) => f.finding_id === selected);
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div data-content-padding={false} className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        <RouteIcon className="text-muted-foreground size-4" />
        <h1 className="text-sm font-semibold">发现路径</h1>
        <span className="text-muted-foreground text-xs">
          一条漏洞是从哪条线索长出来的、打的哪个入口、发了哪些请求
        </span>
      </div>

      {/* 筛选条：与「发现」页同一套 */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2">
        <InputGroup className="w-full sm:w-64">
          <InputGroupInput
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="检索漏洞内容"
            aria-label="检索漏洞内容"
            className="h-8 text-xs"
          />
          <InputGroupAddon>
            <SearchIcon aria-hidden="true" />
          </InputGroupAddon>
        </InputGroup>

        <ToggleGroup
          type="single"
          value={severity}
          onValueChange={(v) => v && setSeverity(v as "all" | Severity)}
          variant="outline"
          size="sm"
          spacing={0}
        >
          {(
            [
              ["all", "全部"],
              ["critical", "严重"],
              ["high", "高危"],
              ["medium", "中危"],
              ["low", "低危"],
            ] as const
          ).map(([val, label]) => (
            <ToggleGroupItem key={val} value={val} aria-label={`按${label}等级筛选`} className="h-8 text-xs">
              {label}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>

        <Select value={status} onValueChange={(v) => setStatus(v as "all" | FindingStatus)}>
          <SelectTrigger size="sm" className="w-28 text-xs">
            <SelectValue placeholder="状态" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            {FINDING_STATUSES.map((st) => (
              <SelectItem key={st} value={st}>
                {statusMeta("finding", st).label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={vulnclass} onValueChange={setVulnclass}>
          <SelectTrigger size="sm" className="w-36 text-xs">
            <SelectValue placeholder="漏洞类型" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部类型</SelectItem>
            {stats.vulnclasses.map((vc) => (
              <SelectItem key={vc} value={vc}>
                {vc}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={task} onValueChange={setTask}>
          <SelectTrigger size="sm" className="w-40 text-xs">
            <SelectValue placeholder="任务" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部任务</SelectItem>
            {(stats.tasks ?? []).map((t) => {
              const id = String(t.id);
              const label = t.name || t.description || `任务 #${id}（已删除）`;
              return (
                <SelectItem key={id} value={id}>
                  <span className="flex w-full items-center gap-2">
                    <span className="max-w-[14rem] truncate" title={label}>
                      {label}
                    </span>
                    <span className="text-muted-foreground tabular-nums">{t.count}</span>
                  </span>
                </SelectItem>
              );
            })}
          </SelectContent>
        </Select>

        <Select value={sort} onValueChange={(v) => setSort(v as "severity" | "time")}>
          <SelectTrigger size="sm" className="w-32 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="severity">按严重度</SelectItem>
            <SelectItem value="time">按时间</SelectItem>
          </SelectContent>
        </Select>

        <span className="text-muted-foreground ml-auto text-[11px] tabular-nums">
          共 {total} 条{loading ? " · 加载中…" : ""}
        </span>
      </div>

      <div className="flex min-h-0 flex-1">
        {/* 左：命中的漏洞 */}
        <div className="flex w-80 shrink-0 flex-col border-r border-border">
          <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto">
            {loading && items.length === 0 ? (
              <div className="flex flex-col gap-2 p-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : items.length === 0 ? (
              <p className="text-muted-foreground p-4 text-xs">没有匹配的漏洞。</p>
            ) : (
              items.map((f) => {
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
          <div className="flex items-center justify-between border-t border-border px-2 py-1.5">
            <span className="text-muted-foreground text-[11px] tabular-nums">
              {page} / {pageCount}
            </span>
            <div className="flex items-center gap-1">
              <button
                type="button"
                disabled={page <= 1 || loading}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="hover:bg-muted rounded p-1 disabled:opacity-40"
                aria-label="上一页"
              >
                <ChevronLeftIcon className="size-3.5" />
              </button>
              <button
                type="button"
                disabled={page >= pageCount || loading}
                onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
                className="hover:bg-muted rounded p-1 disabled:opacity-40"
                aria-label="下一页"
              >
                <ChevronRightIcon className="size-3.5" />
              </button>
            </div>
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
