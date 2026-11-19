"use client";

// LLM 健康探测按钮：对单个 profile 发一次最小推理请求（max_tokens=5），
// 15 秒内没有完成即判定"推理后端不可用"。这补住熔断机制的盲区——
// 挂起型故障（HTTP 200 但永远不回）不会触发 Trip，UI 上却表现为任务卡死。

import * as React from "react";
import { ActivityIcon, Loader2Icon } from "lucide-react";
import { toast } from "sonner";

type Result = { ok: boolean; status: string; elapsed: string };

export function LLMProbeButton({ profileId, onDone }: { profileId: number | string; onDone?: () => void }) {
  const [busy, setBusy] = React.useState(false);
  const [res, setRes] = React.useState<Result | null>(null);

  const probe = async () => {
    setBusy(true);
    setRes(null);
    try {
      const r = await fetch(`/api/llm/profiles/${profileId}/probe`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const d = await r.json();
      setRes({ ok: !!d.ok, status: d.status || "", elapsed: d.elapsed || "" });
      toast[d.ok ? "success" : "error"](d.ok ? `推理正常（${d.elapsed}）` : `推理不可用：${d.status}`);
      onDone?.();
    } catch (e) {
      toast.error("探测失败：" + (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <span className="inline-flex items-center gap-1.5">
      <button
        onClick={() => void probe()}
        disabled={busy}
        title="发一次最小推理请求（max_tokens=5），15 秒无响应判定后端不可用"
        className="inline-flex h-7 items-center gap-1 rounded-md border px-2 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-50"
      >
        {busy ? <Loader2Icon className="size-3.5 animate-spin" /> : <ActivityIcon className="size-3.5" />}
        探测
      </button>
      {res ? (
        <span className={res.ok ? "text-[10px] text-emerald-600" : "text-[10px] text-red-600"}>
          {res.ok ? "正常" : "不可用"} · {res.elapsed}
        </span>
      ) : null}
    </span>
  );
}
