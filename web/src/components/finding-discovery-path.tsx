"use client";

import * as React from "react";
import { RouteIcon, SearchIcon, ShieldCheckIcon, TargetIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { FindingDiscoveryPath, FindingDiscoveryStep } from "@/lib/api";
import { cn } from "@/lib/utils";

// FindingDiscoveryPathPanel 把一条漏洞的溯源链渲染成白话时间线：
// 这条漏洞是从哪条线索长出来的 → 为什么打这个入口 → 实际发了哪些请求 → 决定性证据。
//
// 数据来源：图谱的 yields/derived_from 边、意图文本、该意图的 Bash 调用记录、
// 以及已绑定的流量快照。全部只读，历史漏洞同样可看。
export function FindingDiscoveryPathPanel({ findingId }: { findingId: string }) {
  const [data, setData] = React.useState<FindingDiscoveryPath | null>(null);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .findingDiscoveryPath(findingId)
      .then((d) => {
        if (alive) setData(d);
      })
      .catch(() => {
        if (alive) setData(null);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [findingId]);

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">发现路径</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground text-xs">加载中…</p>
        </CardContent>
      </Card>
    );
  }

  if (!data || !data.steps?.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">发现路径</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground text-xs">
            无链路可展示（该漏洞可能不是探索流程产生的，或所属任务已删除）。
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="gap-1">
        <CardTitle className="flex items-center gap-2 text-sm">
          <RouteIcon className="size-4 text-muted-foreground" />
          发现路径
        </CardTitle>
        {data.target_url && (
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            <span className="text-muted-foreground text-[11px]">目标入口</span>
            {data.target_method && (
              <Badge variant="outline" className="font-mono text-[10px]">
                {data.target_method}
              </Badge>
            )}
            <code className="bg-muted max-w-full truncate rounded px-1.5 py-0.5 font-mono text-[11px]">
              {data.target_url}
            </code>
          </div>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {data.steps.map((step, i) => (
          <StepRow key={`${step.phase}-${i}`} step={step} index={i} />
        ))}
      </CardContent>
    </Card>
  );
}

const PHASE_ICON: Record<string, React.ReactNode> = {
  溯源: <SearchIcon className="size-3.5" />,
  目标判定: <TargetIcon className="size-3.5" />,
  实测: <RouteIcon className="size-3.5" />,
  证据: <ShieldCheckIcon className="size-3.5" />,
};

function StepRow({ step, index }: { step: FindingDiscoveryStep; index: number }) {
  const [expanded, setExpanded] = React.useState(step.phase !== "溯源");
  const items = expanded ? step.items : step.items.slice(0, 3);
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <div className="bg-muted text-muted-foreground flex size-6 shrink-0 items-center justify-center rounded-full">
          {PHASE_ICON[step.phase] ?? <span className="text-[10px]">{index + 1}</span>}
        </div>
        <div className="bg-border mt-1 w-px flex-1" />
      </div>
      <div className="min-w-0 flex-1 pb-1">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="secondary" className="text-[10px]">
            {step.phase}
          </Badge>
          <span className="text-xs font-medium">{step.title}</span>
          {step.items.length > 3 && (
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="text-muted-foreground hover:text-foreground text-[10px] underline"
            >
              {expanded ? "收起" : `展开全部 ${step.items.length} 项`}
            </button>
          )}
        </div>
        {step.note && <p className="text-muted-foreground mt-1 text-[11px]">{step.note}</p>}
        <ul className="mt-2 flex flex-col gap-1">
          {items.map((it, j) => (
            <li
              key={`${it.ref ?? it.url ?? j}-${j}`}
              className={cn(
                "flex min-w-0 items-start gap-1.5 rounded px-1.5 py-1 text-[11px]",
                it.hit ? "bg-primary/10 text-foreground" : "text-muted-foreground",
              )}
            >
              {it.ref && <code className="shrink-0 font-mono opacity-70">{it.ref}</code>}
              {it.method && (
                <Badge variant={it.hit ? "default" : "outline"} className="shrink-0 font-mono text-[10px]">
                  {it.method}
                </Badge>
              )}
              {it.url ? (
                <code className="min-w-0 break-all font-mono">{it.url}</code>
              ) : (
                <span className="min-w-0 break-words">{it.text}</span>
              )}
              {typeof it.status === "number" && it.status > 0 && (
                <span className="shrink-0 opacity-70">{it.status}</span>
              )}
              {it.hit && <Badge className="shrink-0 text-[10px]">命中</Badge>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
