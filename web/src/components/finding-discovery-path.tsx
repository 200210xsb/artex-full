"use client";

import * as React from "react";
import { DatabaseIcon, RouteIcon, SearchIcon, ShieldCheckIcon, TargetIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type {
  FindingDiscoveryPath,
  FindingDiscoveryStep,
  FindingDiscoveryTarget,
} from "@/lib/api";
import { cn } from "@/lib/utils";

// FindingDiscoveryPathPanel 把一条漏洞的溯源链渲染成白话时间线：
// 目标入口（方法/URL/参数/接口来源）→ 溯源 → 为什么打这个入口 → 实测请求（含 query 与 body）→ 决定性证据。
//
// 数据来源：资产表的 endpoint 资产（method + params，回答"接口哪来的、参数是什么"）、
// 图谱的 yields/derived_from 边、意图文本、该意图的 Bash 调用记录、已绑定的流量快照。
// 全部只读，历史漏洞同样可看。
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
    <div className="flex flex-col gap-3">
      <TargetCard target={data.target} />
      <Card>
        <CardHeader className="gap-1 pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <RouteIcon className="text-muted-foreground size-4" />
            发现路径
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {data.steps.map((step, i) => (
            <StepRow key={`${step.phase}-${i}`} step={step} index={i} />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// TargetCard 是「打的是哪个接口」：方法、URL、参数、以及这个接口是哪来的。
function TargetCard({ target }: { target: FindingDiscoveryTarget }) {
  if (!target?.url) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <TargetIcon className="text-muted-foreground size-4" />
            目标入口
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground text-xs">
            未能定位具体接口（漏洞未绑定流量证据，名称里也没有「METHOD /path」）。
          </p>
        </CardContent>
      </Card>
    );
  }
  return (
    <Card>
      <CardHeader className="gap-2 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <TargetIcon className="text-muted-foreground size-4" />
          目标入口
        </CardTitle>
        <div className="flex flex-wrap items-center gap-1.5">
          {target.method && (
            <Badge variant="outline" className="font-mono text-[10px]">
              {target.method}
            </Badge>
          )}
          <code className="bg-muted max-w-full break-all rounded px-1.5 py-0.5 font-mono text-[11px]">
            {target.url}
          </code>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {/* 参数 */}
        <div>
          <p className="text-muted-foreground mb-1 text-[11px]">参数</p>
          {target.params && target.params.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-[11px]">
                <thead className="text-muted-foreground">
                  <tr className="border-b border-border/60">
                    <th className="py-1 pr-3 text-left font-medium">参数名</th>
                    <th className="py-1 pr-3 text-left font-medium">位置</th>
                    <th className="py-1 pr-3 text-left font-medium">类型</th>
                    <th className="py-1 text-left font-medium">取值 / 说明</th>
                  </tr>
                </thead>
                <tbody>
                  {target.params.map((p, i) => (
                    <tr key={`${p.name}-${i}`} className="border-b border-border/30">
                      <td className="py-1 pr-3 font-mono">{p.name}</td>
                      <td className="py-1 pr-3">
                        <Badge variant="secondary" className="text-[10px]">
                          {p.location || "-"}
                        </Badge>
                      </td>
                      <td className="text-muted-foreground py-1 pr-3">{p.type || "-"}</td>
                      <td className="py-1 break-all">{p.value || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-muted-foreground text-[11px]">
              资产里没有登记该接口的参数（POST 的请求体请看下面「实测」里命中那条）。
            </p>
          )}
        </div>

        {/* 接口来源 */}
        <div className="flex flex-wrap items-center gap-1.5">
          <DatabaseIcon className="text-muted-foreground size-3.5" />
          <span className="text-muted-foreground text-[11px]">接口来源</span>
          <span className="text-[11px]">{target.source || "未知"}</span>
          {target.asset_domain && (
            <code className="bg-muted rounded px-1.5 py-0.5 font-mono text-[10px]">{target.asset_domain}</code>
          )}
          {(target.asset_tasks?.length ?? 0) > 0 && (
            <span className="text-muted-foreground text-[10px]">
              任务 {(target.asset_tasks ?? []).map((t) => `#${t}`).join(" / ")}
            </span>
          )}
        </div>
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
                "min-w-0 rounded px-1.5 py-1 text-[11px]",
                it.hit ? "bg-primary/10 text-foreground" : "text-muted-foreground",
              )}
            >
              <div className="flex min-w-0 flex-wrap items-center gap-1.5">
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
              </div>
              {/* query 参数 */}
              {it.query && it.query.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  <span className="opacity-70">query:</span>
                  {it.query.map((q, k) => (
                    <code key={k} className="bg-muted rounded px-1 py-0.5 font-mono text-[10px]">
                      {q}
                    </code>
                  ))}
                </div>
              )}
              {/* POST 请求体 */}
              {it.body && (
                <div className="mt-1">
                  <span className="opacity-70">body:</span>
                  <pre className="bg-muted mt-0.5 max-h-40 overflow-auto rounded px-1.5 py-1 font-mono text-[10px] whitespace-pre-wrap break-all">
                    {it.body}
                  </pre>
                </div>
              )}
              {it.text && it.url && <p className="mt-0.5 opacity-80">{it.text}</p>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
