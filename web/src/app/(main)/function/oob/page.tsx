"use client";

// 回连监听（OOB）：红队值守面板。
//
// 布局：顶部统计条 + Tab（回连台账 / 能力判定 / 投喂载荷）。台账是左右主从结构：
// 左侧会话列表（搜索/筛选/分组折叠，独立滚动），右侧命中流表格（斑马行、来源
// 标记列，独立滚动）。外部未知来访（没带我们 token 的访问）单独成组、红色标记。
// 页面不整体滚动，只有左右两块各自滚动。

import * as React from "react";
import {
  ActivityIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ClockIcon,
  CopyIcon,
  EyeIcon,
  FileTextIcon,
  GlobeIcon,
  HelpCircleIcon,
  Loader2Icon,
  RadioIcon,
  RefreshCwIcon,
  SearchIcon,
  WifiIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type {
  OOBCapability,
  OOBHit,
  OOBHitDetail,
  OOBOverview,
  OOBPayload,
  OOBSession,
} from "@/lib/types";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

const errMsg = (err: unknown, fallback: string) => (err instanceof Error ? err.message : fallback);

/** L 等级配色：L0 浅灰、L1 浅橙、L2+ 深一点，和状态语义对齐。 */
const LEVEL_STYLE: Record<number, string> = {
  0: "border-slate-400/40 bg-slate-500/10 text-slate-600 dark:text-slate-300",
  1: "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400",
  2: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  3: "border-sky-500/40 bg-sky-500/10 text-sky-600 dark:text-sky-400",
  4: "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-400",
  5: "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
};

const EVIDENCE_ROWS: Array<{ key: string; title: string; desc: string }> = [
  { key: "reach", title: "能出网回连", desc: "目标发出 HTTP 请求并到达监听端口。" },
  { key: "follow_1", title: "跟随一次 302", desc: "收到重定向后主动跳到下一个地址。" },
  { key: "follow_2", title: "链式跟随", desc: "连续跟随多次跳转，可以引到更深的内网路径。" },
  { key: "auth_retry", title: "带凭据重试", desc: "遇到 401 挑战后带 Authorization 头重新请求。" },
  { key: "big_body", title: "接收大响应", desc: "完整读完 1MB 响应体，属于渲染型客户端。" },
  { key: "xproto_issued", title: "尝试其它协议", desc: "命中过 file:// 或 gopher:// 载荷。" },
];

// ---------------------------------------------------------------------------
// 纯函数
// ---------------------------------------------------------------------------

function fmtTS(ts: number, withDate = true) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const time = d.toLocaleTimeString("zh-CN", { hour12: false });
  if (!withDate) return time;
  return `${d.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" })} ${time}`;
}

function fmtAgo(ts: number) {
  if (!ts) return "—";
  const sec = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (sec < 60) return `${sec}s 前`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m 前`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h 前`;
  return `${Math.floor(sec / 86400)}d 前`;
}

function fmtBytes(n?: number) {
  if (!n) return "—";
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1024 / 1024).toFixed(1)}M`;
}

function pickSession(list: OOBSession[], prefer: string) {
  if (prefer && list.some((s) => s.id === prefer)) return prefer;
  const withHits = list.find((s) => s.hit_count > 0);
  return withHits?.id ?? list[0]?.id ?? "";
}

// ---------------------------------------------------------------------------
// 小部件
// ---------------------------------------------------------------------------

function HelpDot({ tip }: { tip: string }) {
  return (
    <span
      className="inline-flex size-4 cursor-help items-center justify-center rounded-full text-muted-foreground/60 hover:text-muted-foreground"
      title={tip}
      aria-label="说明"
    >
      <HelpCircleIcon className="size-3.5" />
    </span>
  );
}

function LevelBadge({ level, name }: { level: number; name: string }) {
  const cls = LEVEL_STYLE[Math.min(level, 5)] ?? LEVEL_STYLE[0];
  const short = name.split(" ")[0] || `L${level}`;
  return (
    <span
      className={cn("inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-medium leading-none", cls)}
      title={name}
    >
      {short}
    </span>
  );
}

function OriginBadge({ origin }: { origin: string }) {
  const ext = origin === "external";
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 text-[10px] leading-none",
        ext
          ? "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400"
          : "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
      )}
    >
      {ext ? "外部来访" : "自发包"}
    </span>
  );
}

function StatCard({
  icon,
  label,
  value,
  hint,
  mono,
  tone,
  weight = 1,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint?: string;
  mono?: boolean;
  tone?: "warn";
  weight?: number;
}) {
  return (
    <div
      style={{ flex: `${weight} 1 150px` }}
      className={cn(
        "flex min-w-0 flex-col gap-1.5 rounded-lg border bg-card/40 px-3.5 py-3",
        tone === "warn" && "border-amber-500/40 bg-amber-500/5",
      )}
    >
      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
        {icon}
        <span className="truncate">{label}</span>
      </div>
      <div
        className={cn(
          "truncate text-xl leading-tight font-semibold tracking-tight tabular-nums",
          mono && "font-mono text-base",
          tone === "warn" && "text-amber-700 dark:text-amber-300",
        )}
        title={value}
      >
        {value}
      </div>
      {hint ? <div className="truncate text-[11px] leading-4 text-muted-foreground/70">{hint}</div> : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 页面
// ---------------------------------------------------------------------------

export default function OOBPage() {
  const [ov, setOv] = React.useState<OOBOverview | null>(null);
  const [sessions, setSessions] = React.useState<OOBSession[]>([]);
  const [sid, setSid] = React.useState("");
  const [hits, setHits] = React.useState<OOBHit[]>([]);
  const [cap, setCap] = React.useState<OOBCapability | null>(null);
  const [payloads, setPayloads] = React.useState<OOBPayload[]>([]);
  const [payloadWarn, setPayloadWarn] = React.useState("");
  const [detail, setDetail] = React.useState<OOBHitDetail | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);
  const [tab, setTab] = React.useState<"ledger" | "capability" | "payloads">("ledger");
  const [pollMs, setPollMs] = React.useState(3000);
  const [busy, setBusy] = React.useState(false);

  // 左侧列表
  const [sq, setSq] = React.useState("");
  const [originFilter, setOriginFilter] = React.useState<"all" | "mine" | "ext">("all");
  const [openMine, setOpenMine] = React.useState(true);
  const [openExt, setOpenExt] = React.useState(true);

  const current = sessions.find((s) => s.id === sid);

  // -------------------------------------------------------------------------
  // 数据
  // -------------------------------------------------------------------------

  const loadTop = React.useCallback(async () => {
    try {
      const [o, ss] = await Promise.all([api.oobOverview(), api.oobSessions()]);
      setOv(o);
      const list = ss.sessions ?? [];
      setSessions(list);
      setSid((prev) => pickSession(list, prev));
    } catch {
      // 静默：OOB 库可能还没生成
    }
  }, []);

  React.useEffect(() => {
    loadTop();
  }, [loadTop]);

  React.useEffect(() => {
    if (!pollMs) return;
    const t = setInterval(loadTop, pollMs);
    return () => clearInterval(t);
  }, [pollMs, loadTop]);

  const loadSession = React.useCallback(async (id: string) => {
    if (!id) {
      setHits([]);
      setCap(null);
      setPayloads([]);
      return;
    }
    try {
      const [h, c, p] = await Promise.all([
        api.oobHits(id, 200),
        api.oobCapability(id),
        api.oobPayloads(id),
      ]);
      setHits(h.hits ?? []);
      setCap(c);
      setPayloads(p.payloads ?? []);
      setPayloadWarn(p.warning ?? "");
    } catch (e) {
      toast.error(errMsg(e, "读取会话详情失败"));
    }
  }, []);

  React.useEffect(() => {
    loadSession(sid);
  }, [sid, loadSession]);

  React.useEffect(() => {
    if (!pollMs || !sid) return;
    const t = setInterval(() => loadSession(sid), pollMs);
    return () => clearInterval(t);
  }, [pollMs, sid, loadSession]);

  const openDetail = async (hitId: number) => {
    setDetailLoading(true);
    try {
      const d = await api.oobHit(hitId);
      setDetail(d);
    } catch (e) {
      toast.error(errMsg(e, "读取详情失败"));
    } finally {
      setDetailLoading(false);
    }
  };

  const refreshNow = async () => {
    setBusy(true);
    try {
      await Promise.all([loadTop(), sid ? loadSession(sid) : Promise.resolve()]);
    } finally {
      setBusy(false);
    }
  };

  const copyText = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`已复制${label}`);
    } catch {
      toast.error("复制失败");
    }
  };

  // -------------------------------------------------------------------------
  // 派生
  // -------------------------------------------------------------------------

  const visibleSessions = React.useMemo(() => {
    const k = sq.trim().toLowerCase();
    return sessions.filter((s) => {
      if (originFilter === "mine" && s.id === "ext") return false;
      if (originFilter === "ext" && s.id !== "ext") return false;
      if (k && !`${s.label} ${s.id}`.toLowerCase().includes(k)) return false;
      return true;
    });
  }, [sessions, originFilter, sq]);

  const extCount = sessions.filter((s) => s.id === "ext").length;
  const notReady = !ov || (ov.sessions === 0 && ov.hits === 0);

  // -------------------------------------------------------------------------
  // 渲染
  // -------------------------------------------------------------------------

  return (
    <div data-content-padding={false}
      className="flex h-[calc(100vh-3rem)] min-h-0 flex-col overflow-hidden bg-background">
      {/* ---------- 顶部导航条 ---------- */}
      <div className="flex h-11 shrink-0 items-center gap-3 border-b px-3">
        <h1 className="flex items-center gap-2 text-sm font-semibold">
          <RadioIcon className="size-4 text-muted-foreground" />
          回连监听
        </h1>
        <span className="flex items-baseline gap-1.5 text-[11px] text-muted-foreground">
          会话 <span className="font-mono font-medium text-foreground tabular-nums">{sessions.length}</span>
        </span>
        <span className="flex items-baseline gap-1.5 text-[11px] text-muted-foreground">
          回连 <span className="font-mono font-medium text-foreground tabular-nums">{ov?.hits ?? 0}</span>
        </span>
        {extCount > 0 ? (
          <span className="flex items-baseline gap-1.5 text-[11px] text-red-600 dark:text-red-400">
            外部来访 <span className="font-mono font-medium tabular-nums">{extCount}</span>
          </span>
        ) : null}
        <HelpDot
          tip={
            "来源标记：本地自发包 = 我们自己投递的载荷回连；外部未知来访 = 没带我们 token 的访问（扫描器/测绘）。\n" +
            "L 等级：L0 无回连 → L5 能力最强（能跟随跳转、带凭据、收大响应）。\n" +
            "能力判定：根据回连行为推断目标客户端能做什么。"
          }
        />
        <div className="ml-auto flex items-center gap-2">
          {ov?.public_host ? (
            <button
              onClick={() => void copyText(`${ov.public_host}${ov.ports?.length ? ":" + ov.ports[0] : ""}`, "回连地址")}
              className="inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 font-mono text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            >
              <CopyIcon className="size-3.5" />
              {ov.public_host}{ov.ports?.length ? `:${ov.ports[0]}` : ""}
            </button>
          ) : null}
          <div className="flex items-center gap-1 rounded-md border px-1.5 py-0.5">
            <RefreshCwIcon className={cn("size-3", pollMs ? "text-muted-foreground" : "text-muted-foreground/40")} />
            <select
              value={String(pollMs)}
              onChange={(e) => setPollMs(Number(e.target.value))}
              className="h-6 bg-transparent text-xs text-muted-foreground outline-none"
              aria-label="自动刷新间隔"
            >
              <option value="0">关闭</option>
              <option value="3000">3s</option>
              <option value="5000">5s</option>
              <option value="10000">10s</option>
            </select>
          </div>
          <button
            onClick={() => void refreshNow()}
            disabled={busy}
            className="inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-50"
          >
            {busy ? <Loader2Icon className="size-3.5 animate-spin" /> : <RefreshCwIcon className="size-3.5" />}
            刷新
          </button>
        </div>
      </div>

      {/* ---------- 统计条（权重不等宽） ---------- */}
      <div className="flex shrink-0 flex-wrap items-stretch gap-3 border-b px-3 py-3">
        <StatCard
          icon={<WifiIcon className="size-3.5" />}
          label="监听端口"
          weight={1.4}
          value={ov?.ports?.length ? ov.ports.join(" / ") : "—"}
          hint="常驻 oob-listen"
          mono
        />
        <StatCard
          icon={<GlobeIcon className="size-3.5" />}
          label="回连地址"
          weight={1.4}
          value={ov?.public_host || "未配置"}
          hint="目标要访问的公网 IP"
          mono
          tone={ov && !ov.public_host ? "warn" : undefined}
        />
        <StatCard
          icon={<ActivityIcon className="size-3.5" />}
          label="会话 / 活跃"
          weight={1.4}
          value={`${ov?.sessions ?? 0} / ${ov?.active ?? 0}`}
          hint="累计 / 未关闭"
        />
        <StatCard
          icon={<ClockIcon className="size-3.5" />}
          label="今日回连"
          weight={0.8}
          value={String(ov?.hits_today ?? 0)}
          hint={ov?.last_hit ? `最近 ${fmtAgo(ov.last_hit)}` : "暂无"}
        />
        <StatCard
          icon={<FileTextIcon className="size-3.5" />}
          label="库大小"
          weight={0.8}
          value={fmtBytes(ov?.db_bytes)}
          hint="7 天自动清理"
        />
      </div>

      {ov?.advice ? (
        <div className="flex shrink-0 items-start gap-2 border-b border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
          <ZapIcon className="mt-0.5 size-3.5 shrink-0" />
          <span>{ov.advice}</span>
        </div>
      ) : null}

      {/* ---------- Tab ---------- */}
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="flex shrink-0 items-center gap-1 border-b px-2">
          {([
            ["ledger", "回连台账"],
            ["capability", "能力判定"],
            ["payloads", "投喂载荷"],
          ] as const).map(([v, label]) => (
            <button
              key={v}
              onClick={() => setTab(v)}
              className={cn(
                "border-b-2 px-3 pb-2 text-xs transition-colors",
                tab === v
                  ? "border-primary font-medium text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              {label}
            </button>
          ))}
        </div>

        {notReady ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 text-center">
            <RadioIcon className="size-8 text-muted-foreground/40" />
            <p className="text-sm font-medium">还没有任何回连记录</p>
            <p className="max-w-md text-xs text-muted-foreground">
              {ov?.error || "OOB 库尚未生成。等 oob-listen 收到第一条回连后，这里会自动出现数据。"}
            </p>
          </div>
        ) : (
          <>
            {/* ---------- 台账 ---------- */}
            {tab === "ledger" ? (
              <div className="flex min-h-0 flex-1 overflow-hidden">
                {/* 左侧会话面板 */}
                <aside className="flex w-[300px] shrink-0 flex-col overflow-hidden border-r">
                  <div className="shrink-0 space-y-2 border-b p-2">
                    <div className="relative">
                      <SearchIcon className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                      <input
                        value={sq}
                        onChange={(e) => setSq(e.target.value)}
                        placeholder="搜索会话 / ID"
                        className="h-8 w-full rounded-md border bg-transparent pl-7 pr-2 text-xs outline-none placeholder:text-muted-foreground focus:border-primary"
                      />
                    </div>
                    <select
                      value={originFilter}
                      onChange={(e) => setOriginFilter(e.target.value as "all" | "mine" | "ext")}
                      className="h-8 w-full rounded-md border bg-transparent px-2 text-xs text-muted-foreground outline-none"
                      aria-label="按来源筛选"
                    >
                      <option value="all">全部</option>
                      <option value="mine">我的载荷</option>
                      <option value="ext">外部来访</option>
                    </select>
                  </div>

                  <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto overscroll-contain">
                    {visibleSessions.length === 0 ? (
                      <div className="px-4 py-8 text-center">
                        <p className="text-xs font-medium">还没有会话</p>
                        <p className="mt-1 text-[11px] text-muted-foreground">
                          用「投喂载荷」生成一条 URL 投出去，命中后这里会出现会话
                        </p>
                      </div>
                    ) : (
                      (["mine", "ext"] as const).map((group) => {
                        const items = visibleSessions.filter((x) =>
                          group === "ext" ? x.id === "ext" : x.id !== "ext",
                        );
                        if (group === "mine" && originFilter === "ext") return null;
                        if (group === "ext" && originFilter === "mine") return null;
                        if (group === "ext" && items.length === 0) return null;
                        const open = group === "mine" ? openMine : openExt;
                        return (
                          <div key={group}>
                            <button
                              type="button"
                              onClick={() => (group === "mine" ? setOpenMine((v) => !v) : setOpenExt((v) => !v))}
                              className="sticky top-0 z-10 flex w-full items-center gap-2 border-y bg-background/95 px-3 py-1.5 text-[11px] font-medium text-muted-foreground backdrop-blur hover:text-foreground"
                            >
                              <ChevronRightIcon className={cn("size-3 transition-transform", open && "rotate-90")} />
                              {group === "mine" ? "我的载荷会话" : "外部未知来访会话"}
                              <span className="tabular-nums text-muted-foreground/60">{items.length}</span>
                            </button>
                            {open
                              ? items.map((s) => (
                                  <button
                                    key={s.id}
                                    type="button"
                                    onClick={() => setSid(s.id)}
                                    title={`${s.label || s.id}\n${s.id}${s.remote_ips?.length ? `\n来源 IP: ${s.remote_ips.join(", ")}` : ""}`}
                                    className={cn(
                                      "flex h-9 w-full items-center gap-2 border-b border-border/40 px-3 text-left transition-colors hover:bg-muted/60",
                                      s.id === sid && "bg-primary/10",
                                    )}
                                  >
                                    <LevelBadge level={s.level} name={s.level_name} />
                                    <span className="min-w-0 flex-1 truncate text-xs font-medium">
                                      {s.label || s.id}
                                    </span>
                                    <OriginBadge origin={s.id === "ext" ? "external" : "payload"} />
                                    <span className="shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground">
                                      {s.hit_count}
                                    </span>
                                  </button>
                                ))
                              : null}
                          </div>
                        );
                      })
                    )}
                  </div>
                </aside>

                {/* 右侧命中流 */}
                <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
                  {/* 标题行 */}
                  <div className="flex h-9 shrink-0 items-center gap-2 border-b px-3">
                    <EyeIcon className="size-3.5 text-muted-foreground" />
                    <span className="text-xs font-medium">回连流</span>
                    {current ? (
                      <>
                        <span className="max-w-64 truncate font-mono text-[11px] text-muted-foreground" title={current.label || current.id}>
                          · {current.label || current.id}
                        </span>
                        <LevelBadge level={current.level} name={current.level_name} />
                      </>
                    ) : null}
                    {detailLoading ? <Loader2Icon className="ml-auto size-3.5 animate-spin text-muted-foreground" /> : null}
                  </div>

                  {/* 表格（独立滚动） */}
                  <div className="scrollbar-thin min-h-0 flex-1 overflow-auto overscroll-contain">
                    {hits.length === 0 ? (
                      <div className="px-4 py-10 text-center">
                        {current?.id === "ext" ? (
                          <>
                            <p className="text-xs font-medium">检测到非本平台发起的外部访问</p>
                            <p className="mt-1 text-[11px] text-muted-foreground">
                              监听端口被扫描或被测绘时会出现在这里；注意确认是否已暴露。
                            </p>
                          </>
                        ) : (
                          <>
                            <p className="text-xs font-medium">还没有回连记录</p>
                            <p className="mt-1 text-[11px] text-muted-foreground">
                              等待回连命中——把载荷投到目标后，命中会实时出现在这里。
                            </p>
                          </>
                        )}
                      </div>
                    ) : (
                      <table className="w-full text-[11px]">
                        <thead className="sticky top-0 bg-background">
                          <tr className="border-b text-left text-muted-foreground [&>th]:h-8 [&>th]:font-semibold [&>th]:text-foreground/80">
                            <th className="w-[92px] shrink-0 px-3">时间</th>
                            <th className="w-[96px] shrink-0 px-2">来源</th>
                            <th className="w-[128px] shrink-0 px-2">来源 IP</th>
                            <th className="w-[96px] shrink-0 px-2">变体</th>
                            <th className="min-w-0 px-2">请求路径</th>
                            <th className="w-[132px] shrink-0 px-2">客户端</th>
                          </tr>
                        </thead>
                        <tbody>
                          {hits.map((h) => (
                            <tr
                              key={h.id}
                              onClick={() => void openDetail(h.id)}
                              className={cn(
                                "cursor-pointer border-b border-border/40 transition-colors hover:bg-muted/50 [&>td]:py-2",
                                detail?.hit.id === h.id && "bg-primary/10",
                              )}
                            >
                              <td className="px-3 font-mono text-muted-foreground">{fmtTS(h.ts, false)}</td>
                              <td className="px-2">
                                <OriginBadge origin={h.origin} />
                              </td>
                              <td className="px-2 font-mono">{h.remote_ip}</td>
                              <td className="px-2">
                                <span className="rounded bg-muted/60 px-1 font-mono text-[10px] text-muted-foreground">
                                  {h.variant || "—"}
                                </span>
                              </td>
                              <td className="max-w-0 px-2">
                                <div
                                  className="flex items-center gap-1.5 truncate font-mono"
                                  title={`${h.method} ${h.path}${h.query ? `?${h.query}` : ""}`}
                                >
                                  <span className="shrink-0 text-muted-foreground">{h.method}</span>
                                  <span className="truncate">{h.path}{h.query ? `?${h.query}` : ""}</span>
                                </div>
                              </td>
                              <td className="max-w-0 px-2">
                                <span className="block truncate text-muted-foreground" title={h.ua}>
                                  {h.ua || "—"}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>

                  {/* 命中详情 */}
                  {detail ? (
                    <div className="flex h-[220px] shrink-0 flex-col border-t">
                      <div className="flex h-8 shrink-0 items-center gap-2 border-b px-3">
                        <span className="text-xs font-medium">请求详情</span>
                        <span className="font-mono text-[10px] text-muted-foreground">#{detail.hit.id}</span>
                        <button
                          onClick={() => setDetail(null)}
                          className="ml-auto rounded p-1 text-muted-foreground hover:text-foreground"
                        >
                          ×
                        </button>
                      </div>
                      <div className="scrollbar-thin grid min-h-0 flex-1 grid-cols-2 gap-0 overflow-hidden">
                        <div className="min-h-0 overflow-y-auto border-r p-3">
                          <p className="mb-1 text-[10px] font-medium text-muted-foreground">Headers</p>
                          <pre className="whitespace-pre-wrap font-mono text-[10px] leading-relaxed">
                            {JSON.stringify(detail.headers, null, 2)}
                          </pre>
                        </div>
                        <div className="min-h-0 overflow-y-auto p-3">
                          <p className="mb-1 text-[10px] font-medium text-muted-foreground">Body</p>
                          <pre className="whitespace-pre-wrap font-mono text-[10px] leading-relaxed">
                            {detail.body || "（空）"}
                          </pre>
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}

            {/* ---------- 能力判定 ---------- */}
            {tab === "capability" ? (
              <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto overscroll-contain p-4">
                {!cap ? (
                  <p className="py-10 text-center text-xs text-muted-foreground">先选一个会话</p>
                ) : (
                  <div className="mx-auto max-w-2xl space-y-4">
                    <div className="flex items-center gap-3">
                      <LevelBadge level={cap.level} name={cap.level_name} />
                      <div>
                        <p className="text-sm font-semibold">{cap.level_name}</p>
                        <p className="text-xs text-muted-foreground">{cap.verdict}</p>
                      </div>
                      <span className="ml-auto font-mono text-xs text-muted-foreground">{cap.hits} 次回连</span>
                    </div>
                    <div className="space-y-2">
                      {EVIDENCE_ROWS.map((row) => {
                        const ok = !!cap.evidence?.[row.key];
                        return (
                          <div
                            key={row.key}
                            className={cn(
                              "flex items-start gap-2.5 rounded-md border px-3 py-2.5",
                              ok ? "border-emerald-500/30 bg-emerald-500/5" : "border-border/60",
                            )}
                          >
                            <span
                              className={cn(
                                "mt-0.5 inline-flex size-4 items-center justify-center rounded-full text-[10px]",
                                ok ? "bg-emerald-500 text-white" : "bg-muted text-muted-foreground",
                              )}
                            >
                              {ok ? <CheckIcon className="size-2.5" /> : "—"}
                            </span>
                            <div className="min-w-0">
                              <p className={cn("text-xs font-medium", !ok && "text-muted-foreground")}>{row.title}</p>
                              <p className="mt-0.5 text-[11px] text-muted-foreground/80">{row.desc}</p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    {cap.limits?.length ? (
                      <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
                        {cap.limits.join("；")}
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            ) : null}

            {/* ---------- 投喂载荷 ---------- */}
            {tab === "payloads" ? (
              <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto overscroll-contain p-4">
                {payloadWarn ? (
                  <div className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
                    {payloadWarn}
                  </div>
                ) : null}
                {payloads.length === 0 ? (
                  <p className="py-10 text-center text-xs text-muted-foreground">
                    {current ? "该会话还没有可用载荷" : "先选一个会话"}
                  </p>
                ) : (
                  <div className="mx-auto max-w-3xl space-y-2">
                    {payloads.map((p) => (
                      <div key={p.url} className="flex items-center gap-2 rounded-md border px-3 py-2">
                        <span className="w-28 shrink-0 text-xs font-medium">{p.name}</span>
                        <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground" title={p.url}>
                          {p.url}
                        </code>
                        <button
                          onClick={() => void copyText(p.url, "载荷")}
                          className="inline-flex h-6 shrink-0 items-center gap-1 rounded-md border px-2 text-[10px] transition-colors hover:bg-accent"
                        >
                          <CopyIcon className="size-3" />
                          复制
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : null}
          </>
        )}
      </div>
    </div>
  );
}
