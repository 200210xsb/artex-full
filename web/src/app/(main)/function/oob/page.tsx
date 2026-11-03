"use client";

// 回连监听（OOB）页面：谁回连了我们、它到底能做什么。
//
// 后端 server/oob.go 只读 /opt/artex/data/oob/oob.db，那份库由常驻监听器
// （oob-listen.service，端口 8889/8900/8901）写入，和 agent 侧的 MCP 工具
// （oob_mcp.py）看到的是同一份数据——页面反映的是真实回连，不是模拟。
//
// 判定思路：光有回连只能说明「目标能出网」。要区分「只能盲打」和「能带回来东西」，
// 靠的是 302 重定向链实测——cap_a1 跳 a2 → a3（401 挑战）→ a4（1MB 响应体），
// 回连方走到第几跳，就把它的能力定到哪一级。详见 server/oob.go 的 oobAssess。
//
// 页面不碰 MCP 子进程，所以 agent 没在跑的时候照样能看历史回连。

import * as React from "react";
import {
  ActivityIcon,
  CheckCircle2Icon,
  ChevronRightIcon,
  CircleIcon,
  ClockIcon,
  CopyIcon,
  CheckIcon,
  EyeIcon,
  FileTextIcon,
  GlobeIcon,
  Loader2Icon,
  RadioIcon,
  RefreshCwIcon,
  ShieldAlertIcon,
  TriangleAlertIcon,
  WifiIcon,
  XCircleIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import type {
  OOBCapability,
  OOBHit,
  OOBHitDetail,
  OOBOverview,
  OOBPayload,
  OOBSession,
} from "@/lib/types";

const POLL_MS = 3000;

/** unix 秒（后端 REAL）→ 本地时间。页面上的时间必须能对上监听器日志。 */
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
  if (sec < 60) return `${sec} 秒前`;
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟前`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} 小时前`;
  return `${Math.floor(sec / 86400)} 天前`;
}

function fmtBytes(n?: number) {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** 等级徽章。L5 是最强结论，用红底明确提示「这已经能带回内容」。 */
function LevelBadge({ level, name, className }: { level: number; name: string; className?: string }) {
  const tone =
    level >= 5
      ? "border-red-500/50 bg-red-500/10 text-red-600 dark:text-red-400"
      : level === 4
        ? "border-violet-500/50 bg-violet-500/10 text-violet-600 dark:text-violet-400"
        : level === 3
          ? "border-sky-500/50 bg-sky-500/10 text-sky-600 dark:text-sky-400"
          : level === 1
            ? "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400"
            : "border-border bg-muted text-muted-foreground";
  const short = name.split(" ")[0] || `L${level}`;
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold tabular-nums",
        tone,
        className,
      )}
      title={name}
    >
      {short}
    </span>
  );
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = React.useState(false);
  const timer = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  React.useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  const copy = async () => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // 非安全上下文（http 局域网）拿不到 clipboard API，退回 execCommand。
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch { /* 静默：浏览器彻底禁用就算了 */ }
      document.body.removeChild(ta);
    }
    setCopied(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), 1500);
  };

  return (
    <Button
      variant="ghost"
      size={label ? "sm" : "icon"}
      className={cn("shrink-0", label ? "h-7 text-xs" : "size-7")}
      disabled={!text}
      title={copied ? "已复制" : "复制"}
      onClick={copy}
    >
      {copied ? <CheckIcon className="size-3.5 text-emerald-600" /> : <CopyIcon className="size-3.5" />}
      {label ? <span className="ml-1">{copied ? "已复制" : label}</span> : null}
    </Button>
  );
}

/** 能力证据项。顺序就是能力递增的顺序，读下来等于一条推理链。 */
const EVIDENCE_ROWS: Array<{ key: string; title: string; desc: string }> = [
  { key: "reach", title: "能出网回连", desc: "目标发出 HTTP 请求并到达监听端口。这是盲 SSRF 的最低证据。" },
  { key: "follow_1", title: "跟随一次 302", desc: "收到重定向后主动跳到下一个地址，说明按 URL 语义解析。" },
  { key: "follow_2", title: "链式跟随", desc: "连续跟随多次跳转，可以把它引到更深的内网路径。" },
  { key: "auth_retry", title: "带凭据重试", desc: "遇到 401 挑战后带 Authorization 头重新请求。" },
  { key: "big_body", title: "接收大响应", desc: "完整读完 1MB 响应体，属于渲染型客户端，能把内容带回来。" },
  { key: "xproto_issued", title: "尝试其它协议", desc: "命中过 file:// 或 gopher:// 载荷。" },
];

/** 会话里挑一条作为当前观测对象：优先第一个有命中的，避免落到空会话。 */
function pickSession(list: OOBSession[], prefer: string) {
  if (prefer && list.some((s) => s.id === prefer)) return prefer;
  const withHits = list.find((s) => s.hit_count > 0);
  return withHits?.id ?? list[0]?.id ?? "";
}

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
  const [auto, setAuto] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [tab, setTab] = React.useState("ledger");

  const current = React.useMemo(
    () => sessions.find((s) => s.id === sid) ?? null,
    [sessions, sid],
  );

  // 概览 + 会话列表：3 秒一轮。轮询比 SSE 简单，且这页数据量很小。
  const loadTop = React.useCallback(async () => {
    try {
      const [o, s] = await Promise.all([api.oobOverview(), api.oobSessions()]);
      setOv(o);
      setSessions(s.sessions ?? []);
      setSid((prev) => pickSession(s.sessions ?? [], prev));
    } catch (e) {
      // 库还没生成时这里会 200 带 available:false，真正的异常才提示。
      toast.error(e instanceof Error ? e.message : "读取回连概览失败");
    }
  }, []);

  React.useEffect(() => {
    loadTop();
  }, [loadTop]);

  React.useEffect(() => {
    if (!auto) return;
    const t = setInterval(loadTop, POLL_MS);
    return () => clearInterval(t);
  }, [auto, loadTop]);

  // 选中会话后拉命中流 + 能力判定 + 载荷。
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
      toast.error(e instanceof Error ? e.message : "读取会话详情失败");
    }
  }, []);

  React.useEffect(() => {
    loadSession(sid);
  }, [sid, loadSession]);

  // 自动刷新时命中流也要跟着动，否则左边涨了右边不动。
  React.useEffect(() => {
    if (!auto || !sid) return;
    const t = setInterval(() => loadSession(sid), POLL_MS);
    return () => clearInterval(t);
  }, [auto, sid, loadSession]);

  const openDetail = async (hitId: number) => {
    setDetailLoading(true);
    try {
      setDetail(await api.oobHit(hitId));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "读取回连详情失败");
    } finally {
      setDetailLoading(false);
    }
  };

  const refreshNow = async () => {
    setBusy(true);
    try {
      await loadTop();
      await loadSession(sid);
    } finally {
      setBusy(false);
    }
  };

  const notReady = ov && !ov.available;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <RadioIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-xl font-semibold tracking-tight">回连监听</h1>
          <Badge variant="secondary">{sessions.length} 会话</Badge>
          {ov && ov.hits > 0 ? (
            <Badge variant="outline" className="font-mono tabular-nums">
              {ov.hits} 次回连
            </Badge>
          ) : null}
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 rounded-md border px-2.5 py-1">
            <Switch
              id="oob-auto"
              size="sm"
              checked={auto}
              onCheckedChange={setAuto}
            />
            <label
              htmlFor="oob-auto"
              className={cn(
                "cursor-pointer text-xs font-medium select-none",
                auto ? "text-foreground" : "text-muted-foreground",
              )}
            >
              {auto ? `每 ${POLL_MS / 1000}s 刷新` : "已暂停"}
            </label>
          </div>
          <Button variant="outline" size="sm" className="h-8" onClick={refreshNow} disabled={busy}>
            {busy ? <Loader2Icon className="size-3.5 animate-spin" /> : <RefreshCwIcon className="size-3.5" />}
            刷新
          </Button>
        </div>
      </div>

      {/* 概览条：监听端口与公网地址必须显式展示——载荷生成错了整个功能就废了 */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <StatCard icon={<WifiIcon className="size-3.5" />} label="监听端口"
          value={ov?.ports?.length ? ov.ports.join(" / ") : "—"}
          hint="常驻监听器 oob-listen" mono />
        <StatCard icon={<GlobeIcon className="size-3.5" />} label="回连地址"
          value={ov?.public_host || "未配置"} hint="目标要访问的公网 IP" mono
          tone={ov && !ov.public_host ? "warn" : undefined} />
        <StatCard icon={<ActivityIcon className="size-3.5" />} label="会话 / 活跃"
          value={`${ov?.sessions ?? 0} / ${ov?.active ?? 0}`} hint="累计 / 未关闭" />
        <StatCard icon={<ZapIcon className="size-3.5" />} label="回连总数"
          value={String(ov?.hits ?? 0)} hint="所有会话累计" />
        <StatCard icon={<ClockIcon className="size-3.5" />} label="今日回连"
          value={String(ov?.hits_today ?? 0)} hint={ov?.last_hit ? `最近 ${fmtAgo(ov.last_hit)}` : "暂无"} />
        <StatCard icon={<FileTextIcon className="size-3.5" />} label="库大小"
          value={fmtBytes(ov?.db_bytes)} hint="7 天自动清理" />
      </div>

      {ov?.advice ? (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
          <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
          <span>{ov.advice}</span>
        </div>
      ) : null}

      {notReady ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center gap-2 py-10 text-center">
            <ShieldAlertIcon className="size-8 text-muted-foreground" />
            <p className="text-sm font-medium">还没有任何回连记录</p>
            <p className="max-w-md text-xs text-muted-foreground">
              {ov?.error || "OOB 库尚未生成。等 oob-listen 常驻监听器收到第一条回连后，这里会自动出现数据。"}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col gap-3">
          <TabsList className="w-fit">
            <TabsTrigger value="ledger">回连台账</TabsTrigger>
            <TabsTrigger value="capability">能力判定</TabsTrigger>
            <TabsTrigger value="payloads">投喂载荷</TabsTrigger>
          </TabsList>

          {/* ---------- 台账：左会话 右命中流 ---------- */}
          <TabsContent value="ledger" className="mt-0 min-h-0 flex-1">
            <div className="grid min-h-0 h-full grid-cols-1 gap-4 lg:grid-cols-[minmax(260px,320px)_1fr]">
              <Card className="flex min-h-0 flex-col overflow-hidden">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">会话</CardTitle>
                  <CardDescription className="text-xs">
                    agent 发起或手工登记，一条会话对应一批载荷
                  </CardDescription>
                </CardHeader>
                <CardContent className="min-h-0 flex-1 p-0">
                  <ScrollArea className="h-full">
                    {sessions.length === 0 ? (
                      <p className="px-4 py-6 text-center text-xs text-muted-foreground">暂无会话</p>
                    ) : (
                      <div className="divide-y">
                        {sessions.map((s) => (
                          <button
                            key={s.id}
                            type="button"
                            onClick={() => setSid(s.id)}
                            className={cn(
                              "flex w-full flex-col gap-1 px-3 py-2.5 text-left transition-colors hover:bg-muted/60",
                              s.id === sid && "bg-muted",
                            )}
                          >
                            <div className="flex items-center gap-1.5">
                              <LevelBadge level={s.level} name={s.level_name} />
                              <span className="truncate text-xs font-medium">
                                {s.label || s.id}
                              </span>
                              <span className="ml-auto shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground">
                                {s.hit_count}
                              </span>
                            </div>
                            <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                              <span className="truncate font-mono">{s.id}</span>
                              <span className="ml-auto shrink-0">
                                {s.active ? (
                                  <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                                    <CircleIcon className="size-1.5 fill-current" />
                                    活跃
                                  </span>
                                ) : (
                                  "已关闭"
                                )}
                              </span>
                            </div>
                            {s.remote_ips.length > 0 ? (
                              <div className="truncate font-mono text-[10px] text-muted-foreground/80">
                                {s.remote_ips.join(", ")}
                              </div>
                            ) : null}
                          </button>
                        ))}
                      </div>
                    )}
                  </ScrollArea>
                </CardContent>
              </Card>

              <div className="flex min-h-0 flex-col gap-4">
                <Card className="flex min-h-0 flex-1 flex-col overflow-hidden">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <CardTitle className="truncate text-sm">
                          回连流
                          {current ? (
                            <span className="ml-2 font-mono text-xs font-normal text-muted-foreground">
                              {current.label || current.id}
                            </span>
                          ) : null}
                        </CardTitle>
                        <CardDescription className="text-xs">
                          谁在什么时候、用什么客户端、请求了哪条路径
                        </CardDescription>
                      </div>
                      {current ? <LevelBadge level={current.level} name={current.level_name} /> : null}
                    </div>
                  </CardHeader>
                  <CardContent className="min-h-0 flex-1 p-0">
                    <ScrollArea className="h-full">
                      {hits.length === 0 ? (
                        <p className="px-4 py-8 text-center text-xs text-muted-foreground">
                          该会话还没有回连。把载荷投到目标后，命中会实时出现在这里。
                        </p>
                      ) : (
                        <Table>
                          <TableHeader className="sticky top-0 z-10 bg-card">
                            <TableRow>
                              <TableHead className="w-20 text-xs">时间</TableHead>
                              <TableHead className="w-24 text-xs">变体</TableHead>
                              <TableHead className="w-32 text-xs">来源 IP</TableHead>
                              <TableHead className="text-xs">请求</TableHead>
                              <TableHead className="w-40 text-xs">客户端</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {hits.map((h) => (
                              <TableRow
                                key={h.id}
                                className={cn(
                                  "cursor-pointer",
                                  detail?.hit.id === h.id && "bg-muted",
                                )}
                                onClick={() => openDetail(h.id)}
                              >
                                <TableCell className="font-mono text-[11px] tabular-nums text-muted-foreground">
                                  {fmtTS(h.ts, false)}
                                </TableCell>
                                <TableCell>
                                  <span className={cn(
                                    "font-mono text-[11px]",
                                    h.variant.startsWith("cap_")
                                      ? "text-sky-600 dark:text-sky-400"
                                      : "text-muted-foreground",
                                  )}>
                                    {h.variant || "—"}
                                  </span>
                                </TableCell>
                                <TableCell className="font-mono text-[11px]">
                                  {h.remote_ip}
                                </TableCell>
                                <TableCell className="max-w-0">
                                  <div className="flex items-center gap-1 truncate font-mono text-[11px]">
                                    <span className="shrink-0 text-muted-foreground">{h.method}</span>
                                    <span className="truncate">{h.path}{h.query ? `?${h.query}` : ""}</span>
                                  </div>
                                </TableCell>
                                <TableCell className="max-w-0">
                                  <span className="block truncate text-[11px] text-muted-foreground" title={h.ua}>
                                    {h.ua || "—"}
                                  </span>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      )}
                    </ScrollArea>
                  </CardContent>
                </Card>

                {/* 命中详情：点一行就在这里展开完整请求，不用跳页 */}
                <Card className="flex max-h-[40%] min-h-0 flex-col overflow-hidden">
                  <CardHeader className="pb-2">
                    <div className="flex items-center gap-2">
                      <EyeIcon className="size-3.5 text-muted-foreground" />
                      <CardTitle className="text-sm">请求详情</CardTitle>
                      {detailLoading ? <Loader2Icon className="size-3.5 animate-spin" /> : null}
                      {detail ? (
                        <Badge variant="outline" className="ml-auto font-mono text-[10px]">
                          #{detail.hit.id}
                        </Badge>
                      ) : null}
                    </div>
                  </CardHeader>
                  <CardContent className="min-h-0 flex-1 overflow-auto p-0">
                    {!detail ? (
                      <p className="px-4 py-6 text-center text-xs text-muted-foreground">
                        点上方任意一条回连查看完整请求头与请求体
                      </p>
                    ) : (
                      <div className="flex flex-col gap-2 p-3">
                        <div className="rounded border bg-muted/40 p-2 font-mono text-[11px] break-all">
                          <span className="text-sky-600 dark:text-sky-400">{detail.hit.method}</span>{" "}
                          {detail.hit.scheme}://{detail.hit.host}
                          {detail.hit.path}
                          {detail.hit.query ? `?${detail.hit.query}` : ""}
                        </div>
                        <div>
                          <div className="mb-1 flex items-center gap-1 text-[11px] font-medium text-muted-foreground">
                            请求头
                            <CopyButton text={JSON.stringify(detail.headers, null, 2)} />
                          </div>
                          <pre className="max-h-48 overflow-auto rounded border bg-muted/40 p-2 font-mono text-[11px] whitespace-pre-wrap break-all">
                            {Object.entries(detail.headers)
                              .map(([k, v]) => `${k}: ${String(v)}`)
                              .join("\n") || "（无）"}
                          </pre>
                        </div>
                        <div>
                          <div className="mb-1 flex items-center gap-1 text-[11px] font-medium text-muted-foreground">
                            请求体
                            {detail.hit.truncated ? (
                              <Badge variant="outline" className="text-[10px]">已截断</Badge>
                            ) : null}
                            <CopyButton text={detail.body || ""} />
                          </div>
                          <pre className="max-h-40 overflow-auto rounded border bg-muted/40 p-2 font-mono text-[11px] whitespace-pre-wrap break-all">
                            {detail.body || "（空）"}
                          </pre>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          {/* ---------- 能力判定 ---------- */}
          <TabsContent value="capability" className="mt-0 min-h-0 flex-1 overflow-auto">
            {!current ? (
              <p className="py-10 text-center text-xs text-muted-foreground">先选一个会话</p>
            ) : (
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
                <Card>
                  <CardHeader>
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <CardTitle className="text-sm">
                          等级判定
                          <span className="ml-2 font-mono text-xs font-normal text-muted-foreground">
                            {current.label || current.id}
                          </span>
                        </CardTitle>
                        <CardDescription className="text-xs">
                          由 302 重定向链实测得出，不是靠猜 User-Agent
                        </CardDescription>
                      </div>
                      <LevelBadge level={current.level} name={current.level_name} className="text-xs" />
                    </div>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-3">
                    <p className="text-sm leading-relaxed">{cap?.verdict || current.verdict}</p>

                    <div className="grid gap-1.5">
                      {EVIDENCE_ROWS.map((row) => {
                        const on = Boolean(cap?.evidence?.[row.key]);
                        return (
                          <div
                            key={row.key}
                            className={cn(
                              "flex items-start gap-2 rounded-md border px-2.5 py-2",
                              on
                                ? "border-emerald-500/40 bg-emerald-500/5"
                                : "border-border bg-muted/30",
                            )}
                          >
                            {on ? (
                              <CheckCircle2Icon className="mt-0.5 size-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
                            ) : (
                              <XCircleIcon className="mt-0.5 size-3.5 shrink-0 text-muted-foreground/50" />
                            )}
                            <div className="min-w-0">
                              <div className={cn(
                                "text-xs font-medium",
                                !on && "text-muted-foreground",
                              )}>
                                {row.title}
                              </div>
                              <div className="text-[11px] text-muted-foreground">{row.desc}</div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>

                <div className="flex flex-col gap-4">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">观测到的客户端</CardTitle>
                      <CardDescription className="text-xs">
                        UA 只能说明它自称是什么，能力等级以上面实测为准
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="flex flex-col gap-2 text-xs">
                      <Field label="来源 IP" mono value={current.remote_ips.join(", ") || "—"} />
                      <Field label="命中的 Host" mono value={current.hosts.join(", ") || "—"} />
                      <Field label="变体序列" mono value={current.variants.join(" → ") || "—"} />
                      <div className="flex flex-col gap-1">
                        <span className="text-[11px] text-muted-foreground">User-Agent</span>
                        {current.uas.length === 0 ? (
                          <span className="text-muted-foreground">—</span>
                        ) : (
                          current.uas.map((ua) => (
                            <span key={ua} className="font-mono text-[11px] break-all">{ua}</span>
                          ))
                        )}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="border-amber-500/40">
                    <CardHeader className="pb-2">
                      <div className="flex items-center gap-2">
                        <TriangleAlertIcon className="size-3.5 text-amber-600 dark:text-amber-400" />
                        <CardTitle className="text-sm">这些结论测不出来</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <ul className="flex list-disc flex-col gap-1.5 pl-4 text-[11px] leading-relaxed text-muted-foreground">
                        {(cap?.limits ?? []).map((l) => (
                          <li key={l}>{l}</li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                </div>
              </div>
            )}
          </TabsContent>

          {/* ---------- 载荷 ---------- */}
          <TabsContent value="payloads" className="mt-0 min-h-0 flex-1 overflow-auto">
            {!current ? (
              <p className="py-10 text-center text-xs text-muted-foreground">先选一个会话</p>
            ) : (
              <Card>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <CardTitle className="text-sm">可投喂载荷</CardTitle>
                      <CardDescription className="text-xs">
                        同一个地址给多种 IP 写法，用来绕只做字符串匹配的弱校验
                      </CardDescription>
                    </div>
                    <CopyButton
                      label="全部复制"
                      text={payloads.map((p) => p.url).join("\n")}
                    />
                  </div>
                </CardHeader>
                <CardContent className="flex flex-col gap-2">
                  {payloadWarn ? (
                    <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
                      {payloadWarn}
                    </div>
                  ) : null}
                  {payloads.length === 0 ? (
                    <p className="py-6 text-center text-xs text-muted-foreground">
                      暂无载荷。会话令牌存在但地址未配置时不会生成。
                    </p>
                  ) : (
                    payloads.map((p) => (
                      <div
                        key={`${p.kind}-${p.name}`}
                        className="flex flex-col gap-1 rounded-md border px-3 py-2"
                      >
                        <div className="flex items-center gap-2">
                          <Badge
                            variant="outline"
                            className={cn(
                              "text-[10px]",
                              p.kind === "cap" && "border-sky-500/50 text-sky-600 dark:text-sky-400",
                              p.kind === "proto" && "border-violet-500/50 text-violet-600 dark:text-violet-400",
                            )}
                          >
                            {p.kind === "baseline" ? "基础"
                              : p.kind === "cap" ? "能力探测"
                                : p.kind === "bypass" ? "绕过"
                                  : "协议"}
                          </Badge>
                          <span className="text-xs font-medium">{p.name}</span>
                          <span className="ml-auto"><CopyButton text={p.url} /></span>
                        </div>
                        <code className="block break-all rounded bg-muted/50 px-2 py-1 font-mono text-[11px]">
                          {p.url}
                        </code>
                        <span className="text-[11px] text-muted-foreground">{p.note}</span>
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}

function StatCard({
  icon, label, value, hint, mono, tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint?: string;
  mono?: boolean;
  tone?: "warn";
}) {
  return (
    <div className={cn(
      "flex flex-col gap-0.5 rounded-md border px-3 py-2",
      tone === "warn" && "border-amber-500/40 bg-amber-500/5",
    )}>
      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
        {icon}
        <span>{label}</span>
      </div>
      <div className={cn(
        "truncate text-sm font-semibold tabular-nums",
        mono && "font-mono text-xs",
        tone === "warn" && "text-amber-700 dark:text-amber-300",
      )} title={value}>
        {value}
      </div>
      {hint ? <div className="truncate text-[10px] text-muted-foreground/70">{hint}</div> : null}
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] text-muted-foreground">{label}</span>
      <span className={cn("break-all text-xs", mono && "font-mono text-[11px]")}>{value}</span>
    </div>
  );
}
