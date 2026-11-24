"use client";

// 大模型测绘 / 密钥狩猎。
//
// 三条取 key 的路，按产出排序：① 找"响应体里已含 key"的 URL（Hunter/Quake）
// ② 目标自身的 JS bundle 与未授权配置接口 ③ 公开仓库（产出低，会被厂商吊销）。
// 所有探测只读；自动验证默认关闭，开启后仅对每条新 key 发一次免费只读请求。

import * as React from "react";
import {
  BrainIcon, CopyIcon, Loader2Icon, PlayIcon, RefreshCwIcon, SearchIcon,
  ShieldCheckIcon, SquareIcon, Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

type Asset = {
  id: number; url: string; vendor: string; version: string;
  unauth: boolean; models: string[] | null; source: string; evidence: string;
};
type LeakKey = {
  id: number; key_type: string; masked: string; url: string; found_at: string;
  source_kind?: string; repo?: string; verify_state?: string; verify_note?: string;
};
type ScanDiag = {
  running: boolean;
  rounds: number;
  last_candidates: number;
  last_fetched: number;
  last_found: number;
  last_error?: string;
  stop_reason?: string;
  rounds_no_gain?: number;
};
type ScanStatus = {
  running: boolean;
  last: { id: number; status: string; total: number; done: number; keys: number; note?: string } | null;
  diag?: ScanDiag;
};
type KeyStats = { by_provider: Record<string, number>; by_source: Record<string, number>; total: number; verified: number };
type GHStatus = {
  ready: boolean; running: boolean; found: number;
  dorks_done?: number; files_fetched?: number; last_error?: string;
  seen_files?: number; dork_hits?: Record<string, number>;
};

const VERIFY_LABEL: Record<string, { text: string; cls: string }> = {
  valid: { text: "有效", cls: "bg-destructive/15 text-destructive border-destructive/30" },
  invalid: { text: "无效", cls: "text-muted-foreground" },
  unsupported: { text: "不验证", cls: "text-muted-foreground" },
  error: { text: "不确定", cls: "text-amber-600 dark:text-amber-400" },
  "": { text: "未验证", cls: "text-muted-foreground" },
};

const SOURCE_LABEL: Record<string, string> = {
  "leak-url": "泄漏页面",
  "leak-js": "泄漏页面 JS",
  github: "公开仓库",
  target: "目标接口",
  "target-js": "目标 JS",
};

// usePersisted 把开关状态存进 localStorage：刷新页面后不用重新勾一遍。
function usePersisted(key: string, def: boolean): [boolean, (v: boolean) => void] {
  const [v, setV] = React.useState<boolean>(def);
  React.useEffect(() => {
    try {
      const raw = localStorage.getItem("llmhunt:" + key);
      if (raw === "1") setV(true);
      else if (raw === "0") setV(false);
    } catch {}
  }, [key]);
  const set = React.useCallback((next: boolean) => {
    setV(next);
    try { localStorage.setItem("llmhunt:" + key, next ? "1" : "0"); } catch {}
  }, [key]);
  return [v, set];
}

export default function LLMHuntPage() {
  const [status, setStatus] = React.useState<ScanStatus>({ running: false, last: null });
  const [stats, setStats] = React.useState<KeyStats | null>(null);
  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [keys, setKeys] = React.useState<LeakKey[]>([]);
  const [gh, setGh] = React.useState<GHStatus | null>(null);

  const [repeat, setRepeat] = usePersisted("repeat", true);
  const [autoVerify, setAutoVerify] = usePersisted("autoVerify", false);
  const [huntLeaks, setHuntLeaks] = usePersisted("huntLeaks", true);
  const [useSearch, setUseSearch] = usePersisted("useSearch", false);
  const [fromAssets, setFromAssets] = usePersisted("fromAssets", false);
  const [allowAuth, setAllowAuth] = usePersisted("allowAuth", true);
  const [seeds, setSeeds] = React.useState("");
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const [provider, setProvider] = React.useState<string>("");
  const [onlyVerified, setOnlyVerified] = React.useState(false);
  // 参考 trufflehog-explorer 的做法：按验证状态 / 来源 / 关键词筛选，点行看详情。
  const [statusFilter, setStatusFilter] = React.useState<"all" | "valid" | "invalid" | "pending">("all");
  const [srcFilter, setSrcFilter] = React.useState("");
  const [q, setQ] = React.useState("");
  const [detail, setDetail] = React.useState<LeakKey | null>(null);
  const diag = status.diag;
  const [revealed, setRevealed] = React.useState<Record<number, string>>({});
  const [copied, setCopied] = React.useState<number | null>(null);

  // load 里的错误原来全被 .catch(() => {}) 吞掉：会话失效或后端报错时，页面
  // 显示一张全 0 的空表，**没有任何提示**——用户会以为"本来就没东西"。
  // 这里把第一个错误记下来，在页面顶部显式显示。
  const [loadError, setLoadError] = React.useState<string | null>(null);

  const load = React.useCallback(() => {
    const fail = (e: unknown) => {
      const msg = e instanceof Error ? e.message : String(e);
      setLoadError((prev) => prev ?? msg);
    };
    api<ScanStatus>("/api/llmhunt/status").then((r) => { setStatus(r); setLoadError(null); }).catch(fail);
    api<KeyStats>("/api/llmhunt/key-stats").then(setStats).catch(fail);
    api<{ assets: Asset[] }>("/api/llmhunt/assets").then((r) => setAssets(r.assets ?? [])).catch(fail);
    api<{ keys: LeakKey[] }>("/api/llmhunt/keys").then((r) => setKeys(r.keys ?? [])).catch(fail);
    api<GHStatus>("/api/llmhunt/keyhunt/status").then(setGh).catch(fail);
  }, []);

  React.useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  const startHunt = async () => {
    // 自动验证 = 用别人泄漏的凭据向厂商发只读请求，和「验证待验密钥」是同一性质
    // 的动作，服务端要求显式 confirm=true，这里先问一句。
    if (autoVerify && !window.confirm("自动验证会用每条密钥向厂商发一次免费只读请求（仅列模型，不推理、不重试）。只应在你有权验证的密钥上使用。继续？")) return;
    setBusy(true);
    try {
      await api("/api/llmhunt/scan", {
        method: "POST",
        body: JSON.stringify({
          seeds, from_assets: fromAssets, use_search: useSearch, hunt_leaks: huntLeaks,
          allow_auth: allowAuth, repeat, repeat_minutes: 5,
          auto_verify: autoVerify, confirm: true,
        }),
      });
      toast.success(repeat ? "已开始持续狩猎（每 6 小时一轮）" : "已开始狩猎");
      load();
    } catch (e) {
      toast.error("启动失败：" + (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    try {
      await api("/api/llmhunt/stop", { method: "POST", body: "{}" });
      toast.success("已停止");
      load();
    } catch (e) {
      toast.error("停止失败：" + (e as Error).message);
    }
  };

  const startGH = async () => {
    try {
      await api("/api/llmhunt/keyhunt/start", { method: "POST", body: "{}" });
      toast.success("已开始 GitHub 公开仓库狩猎");
    } catch (e) {
      toast.error("启动失败：" + (e as Error).message);
    }
  };

  const verifyPending = async () => {
    if (!confirm("自动验证会用每条密钥向厂商发一次免费只读请求（仅列模型，不推理、不重试）。只应在你有权验证的密钥上使用。继续？")) return;
    try {
      const r = await api<{ tried: number; valid: number }>("/api/llmhunt/keys/verify", {
        method: "POST", body: JSON.stringify({ confirm: true, limit: 10 }),
      });
      toast.success(`验证 ${r.tried} 条，有效 ${r.valid} 条`);
      load();
    } catch (e) {
      toast.error("验证失败：" + (e as Error).message);
    }
  };

  const reveal = async (k: LeakKey) => {
    if (!confirm("这会向服务端取一次明文，15 秒后自动隐藏。确认你已获授权？")) return;
    try {
      const r = await api<{ raw: string }>(`/api/llmhunt/keys/${k.id}/reveal`);
      setRevealed((p) => ({ ...p, [k.id]: r.raw }));
      setTimeout(() => setRevealed((p) => { const n = { ...p }; delete n[k.id]; return n; }), 15000);
    } catch (e) {
      toast.error("取原文失败：" + (e as Error).message);
    }
  };

  const copyMasked = async (k: LeakKey) => {
    try {
      await navigator.clipboard.writeText(k.masked);
      setCopied(k.id);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      toast.error("复制失败");
    }
  };

  // exportCsv 导出的只有掩码与元信息，**不含明文**（避免凭据被随手落盘传播）。
  const exportCsv = () => {
    const head = ["type", "masked", "verify", "source", "url", "found_at"];
    const rows = shown.map((k) => [
      k.key_type, k.masked, k.verify_state || "unverified",
      SOURCE_LABEL[k.source_kind ?? "target"] ?? k.source_kind ?? "", k.repo || k.url, k.found_at,
    ]);
    const csv = [head, ...rows]
      .map((r) => r.map((c) => `"${String(c ?? "").replace(/"/g, '""')}"`).join(","))
      .join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `llm-keys-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const exportJson = () => {
    const data = shown.map((k) => ({
      type: k.key_type, masked: k.masked, verify: k.verify_state || "unverified",
      source: k.source_kind ?? "target", url: k.repo || k.url, found_at: k.found_at,
    }));
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `llm-keys-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const del = async (kind: "assets" | "keys", id: number) => {
    if (!confirm("确认删除这条记录？")) return;
    try {
      await api(`/api/llmhunt/${kind}/${id}`, { method: "DELETE" });
      load();
    } catch (e) {
      toast.error("删除失败：" + (e as Error).message);
    }
  };

  const last = status.last;
  const providers = Object.entries(stats?.by_provider ?? {}).sort((a, b) => b[1] - a[1]);
  const shown = React.useMemo(() => {
    const kw = q.trim().toLowerCase();
    return keys.filter((k) => {
      if (provider && k.key_type !== provider) return false;
      if (onlyVerified && k.verify_state !== "valid") return false;
      if (srcFilter && (k.source_kind ?? "target") !== srcFilter) return false;
      if (statusFilter === "valid" && k.verify_state !== "valid") return false;
      if (statusFilter === "invalid" && k.verify_state !== "invalid") return false;
      if (statusFilter === "pending" && k.verify_state) return false;
      if (kw && !JSON.stringify(k).toLowerCase().includes(kw)) return false;
      return true;
    });
  }, [keys, provider, onlyVerified, srcFilter, statusFilter, q]);

  return (
    <div className="mx-auto flex min-h-0 w-full max-w-[1440px] flex-1 flex-col gap-4">
      {/* 头部 */}
      <div className="flex flex-wrap items-center gap-2">
        <BrainIcon className="size-5 text-muted-foreground" />
        <h1 className="text-xl font-semibold tracking-tight">大模型测绘 · 密钥狩猎</h1>
        {status.running ? (
          <Badge variant="secondary" className="gap-1">
            <Loader2Icon className="size-3 animate-spin" /> 狩猎中
          </Badge>
        ) : (
          <Badge variant="outline">空闲</Badge>
        )}
        <Button variant="ghost" size="sm" className="ml-auto" onClick={load}>
          <RefreshCwIcon className="size-3.5" /> 刷新
        </Button>
      </div>

      {loadError ? (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          数据加载失败：{loadError}
          <span className="ml-2 text-muted-foreground">（会话可能已失效，刷新页面重新登录）</span>
        </div>
      ) : null}

      {/* 统计带：宽屏上四张大卡会被拉成空盒子，改成一行紧凑指标 */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border bg-card/50 px-4 py-2.5">
        <Stat label="泄漏密钥" value={stats?.total ?? 0} />
        <Divider />
        <Stat label="已确认有效" value={stats?.verified ?? 0} tone={stats?.verified ? "bad" : "muted"} />
        <Divider />
        <Stat label="暴露实例" value={assets.length} />
        <Divider />
        <Stat
          label="状态"
          text={
            status.running
              ? "狩猎中"
              : last
                ? last.status === "running"
                  ? "已中断（服务重启）"
                  : "已停止"
                : "未开始"
          }
          hint={last?.note || (last ? `#${last.id} · ${status.running ? "进行中" : last.status}` : "")}
        />
        {diag && (diag.rounds > 0 || diag.last_error) ? (
          <>
            <Divider />
            <Stat
              label="本轮"
              text={diag.rounds ? `第 ${diag.rounds} 轮` : "—"}
              hint={
                [
                  diag.last_fetched ? `抓取 ${diag.last_fetched} 个 URL` : "",
                  diag.last_found ? `新增 ${diag.last_found} 条 key` : "",
                  diag.last_error ? `异常：${diag.last_error.replace(/^，/, "")}` : "",
                ].filter(Boolean).join(" · ") || "尚无产出"
              }
            />
          </>
        ) : null}
        {diag?.stop_reason ? (
          <>
            <Divider />
            <Stat label="停止原因" text="自动停止" hint={diag.stop_reason} />
          </>
        ) : null}
      </div>

      {/* 控制台 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">狩猎控制</CardTitle>
          <CardDescription>
            默认走最短路径：让空间测绘告诉我们哪些 URL 的响应体里已经含 key，再取回来。
            全部只读；同一主机串行，命中 403/418/429 立即放弃该主机。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-lg border p-3">
              <p className="mb-2 text-xs font-medium text-muted-foreground">狩猎来源</p>
              <div className="flex flex-wrap gap-x-4 gap-y-2">
                <Toggle checked={huntLeaks} onChange={setHuntLeaks} label="泄漏的密钥文件" title="Hunter/Quake 查响应体已含 key 的 URL（产出最高）" />
                <Toggle checked={useSearch} onChange={setUseSearch} label="搜索引擎发现" />
                <Toggle checked={fromAssets} onChange={setFromAssets} label="扫资产库" />
                <Toggle checked={allowAuth} onChange={setAllowAuth} label="默认口令探测" title="每平台最多试 8 组默认口令，遇锁定即停" />
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <p className="mb-2 text-xs font-medium text-muted-foreground">运行方式</p>
              <div className="flex flex-wrap gap-x-4 gap-y-2">
                <Toggle
                  checked={repeat}
                  onChange={setRepeat}
                  label="持续狩猎（5 分钟一轮）"
                  title="连续 3 轮没有新增产出、或达到轮数上限时自动停止——测绘数据集是静态的，一直跑只会空烧配额"
                />
                <Toggle checked={autoVerify} onChange={setAutoVerify} label="自动验证可用性" title="每轮对新增 key 各发一次免费只读请求（仅列模型），上限 10 条" />
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={startHunt} disabled={busy || status.running}>
              {busy ? <Loader2Icon className="size-3.5 animate-spin" /> : <PlayIcon className="size-3.5" />}
              开始狩猎
            </Button>
            <Button variant="outline" onClick={stop} disabled={!status.running}>
              <SquareIcon className="size-3.5" /> 停止
            </Button>
            <Button variant="outline" onClick={startGH} disabled={!gh?.ready || gh?.running} title="公开仓库产出低：GitHub 会与厂商联动吊销泄漏的 key">
              公开仓库狩猎
            </Button>
            <Button variant="ghost" onClick={() => setShowAdvanced((v) => !v)}>
              {showAdvanced ? "收起目标" : "指定目标…"}
            </Button>
            <span className="text-xs text-muted-foreground">
              {gh
                ? `GitHub：${gh.ready ? (gh.running ? "运行中" : "就绪") : "未配置"}` +
                  `${gh.dorks_done ? ` · 搜索词 ${gh.dorks_done}/8` : ""}` +
                  `${gh.files_fetched ? ` · 抓取 ${gh.files_fetched} 文件` : ""}` +
                  // 跨轮记忆：已处理过的文件不再重抓，所以"抓取数"远小于
                  // "搜索结果数"是正常的，界面要说清楚，否则看着像没干活。
                  `${gh.seen_files ? ` · 累计已处理 ${gh.seen_files} 文件` : ""}` +
                  `${gh.found ? ` · 命中 ${gh.found} 条` : ""}` +
                  `${gh.last_error ? ` · ${gh.last_error.slice(0, 40)}` : ""}`
                : ""}
            </span>
          </div>

          {showAdvanced ? (
            <div className="space-y-1.5">
              <Label htmlFor="seeds" className="text-xs">目标清单（可选：host / host:端口 / URL，每行一个）</Label>
              <Textarea id="seeds" value={seeds} onChange={(e) => setSeeds(e.target.value)}
                placeholder={"10.0.0.5:11434\nllm.example.com"} className="min-h-16 font-mono text-xs" />
            </div>
          ) : null}

          {autoVerify ? (
            <p className="text-xs text-amber-600 dark:text-amber-400">
              ⚠️ 自动验证会对每条新 key 向 OpenAI/Anthropic 发一次只读请求（列模型，不推理、不重试，每轮最多 10 条）。
              请在你有权验证的范围内使用。
            </p>
          ) : null}
        </CardContent>
      </Card>

      {/* 结果 */}
      <Tabs defaultValue="keys" className="flex min-h-0 flex-1 flex-col">
        <TabsList>
          <TabsTrigger value="keys">密钥 <span className="ml-1 text-muted-foreground">{shown.length}</span></TabsTrigger>
          <TabsTrigger value="assets">实例 <span className="ml-1 text-muted-foreground">{assets.length}</span></TabsTrigger>
        </TabsList>

        <TabsContent value="keys" className="min-h-0 flex-1 overflow-auto">
          <Card>
            <CardContent className="space-y-3 pt-4">
              {/* 筛选条：厂商 / 来源 / 状态 / 关键词 */}
              <div className="flex flex-wrap items-center gap-1.5">
                <FilterChip active={provider === ""} onClick={() => setProvider("")}>
                  全部 {stats?.total ?? 0}
                </FilterChip>
                {providers.map(([p, n]) => (
                  <FilterChip key={p} active={provider === p} onClick={() => setProvider(p === provider ? "" : p)}>
                    {p} {n}
                  </FilterChip>
                ))}
                <span className="mx-1 h-4 w-px bg-border" />
                <FilterChip active={srcFilter === ""} onClick={() => setSrcFilter("")}>全部来源</FilterChip>
                {Object.entries(stats?.by_source ?? {}).map(([src, n]) => (
                  <FilterChip key={src} active={srcFilter === src} onClick={() => setSrcFilter(srcFilter === src ? "" : src)}>
                    {SOURCE_LABEL[src] ?? src} {n}
                  </FilterChip>
                ))}
                <span className="mx-1 h-4 w-px bg-border" />
                <FilterChip active={statusFilter === "all"} onClick={() => setStatusFilter("all")}>全部状态</FilterChip>
                <FilterChip active={statusFilter === "valid"} onClick={() => setStatusFilter("valid")}>有效 {stats?.verified ?? 0}</FilterChip>
                <FilterChip active={statusFilter === "pending"} onClick={() => setStatusFilter("pending")}>未验证</FilterChip>
                <FilterChip active={statusFilter === "invalid"} onClick={() => setStatusFilter("invalid")}>无效</FilterChip>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-56 flex-1">
                  <SearchIcon className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                  <Input value={q} onChange={(e) => setQ(e.target.value)}
                    placeholder="搜索：掩码 / 来源地址 / 仓库" className="h-8 pl-7 text-xs" />
                </div>
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Switch checked={onlyVerified} onCheckedChange={setOnlyVerified} size="sm" />
                  只看有效
                </label>
                <Button size="sm" variant="outline" onClick={exportCsv} disabled={shown.length === 0}>
                  <CopyIcon className="size-3.5" /> CSV
                </Button>
                <Button size="sm" variant="outline" onClick={exportJson} disabled={shown.length === 0}>
                  JSON
                </Button>
                <Button size="sm" variant="outline" onClick={verifyPending} disabled={status.running}>
                  <ShieldCheckIcon className="size-3.5" /> 验证未验证的
                </Button>
              </div>

              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-28">类型</TableHead>
                    <TableHead className="w-44">掩码</TableHead>
                    <TableHead className="w-24">可用性</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead className="w-40">发现时间</TableHead>
                    <TableHead className="w-36" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {shown.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-muted-foreground">
                        还没有密钥。点「开始狩猎」，默认会用空间测绘找暴露了密钥文件的页面。
                      </TableCell>
                    </TableRow>
                  ) : (
                    shown.map((k) => {
                      const v = VERIFY_LABEL[k.verify_state ?? ""] ?? VERIFY_LABEL[""];
                      return (
                        <TableRow key={k.id} className="cursor-pointer" onClick={() => setDetail(k)}>
                          <TableCell className="text-xs">{k.key_type}</TableCell>
                          <TableCell className="font-mono text-xs">
                            {revealed[k.id] ? <span className="text-destructive break-all">{revealed[k.id]}</span> : k.masked}
                          </TableCell>
                          <TableCell>
                            <span className={cn("rounded px-1.5 py-0.5 text-[11px]", v.cls)} title={k.verify_note}>{v.text}</span>
                          </TableCell>
                          <TableCell className="max-w-96 truncate font-mono text-xs" title={k.url}>
                            <span className="text-muted-foreground">{SOURCE_LABEL[k.source_kind ?? "target"] ?? k.source_kind} · </span>
                            {k.repo || k.url}
                          </TableCell>
                          <TableCell className="text-muted-foreground text-xs">
                            {(k.found_at ?? "").replace("T", " ").slice(0, 19)}
                          </TableCell>
                          <TableCell>
                            <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                              <Button variant="ghost" size="icon" title="复制掩码" onClick={() => copyMasked(k)}>
                                <CopyIcon className={cn("size-3.5", copied === k.id && "text-emerald-500")} />
                              </Button>
                              <Button variant="ghost" size="icon" title="查看原文" onClick={() => reveal(k)}>
                                <SearchIcon className="size-3.5" />
                              </Button>
                              <Button variant="ghost" size="icon" title="删除" onClick={() => del("keys", k.id)}>
                                <Trash2Icon className="size-3.5" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="assets" className="min-h-0 flex-1 overflow-auto">
          <Card>
            <CardContent className="pt-4">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>URL</TableHead>
                    <TableHead className="w-36">组件</TableHead>
                    <TableHead className="w-24">版本</TableHead>
                    <TableHead className="w-28">未授权</TableHead>
                    <TableHead>模型</TableHead>
                    <TableHead className="w-28">来源</TableHead>
                    <TableHead className="w-10" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground">还没有发现实例。</TableCell>
                    </TableRow>
                  ) : assets.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell className="font-mono text-xs">{a.url}</TableCell>
                      <TableCell className="text-xs">{a.vendor || "-"}</TableCell>
                      <TableCell className="font-mono text-xs">{a.version || "-"}</TableCell>
                      <TableCell>
                        {a.unauth ? <Badge variant="destructive">可未授权</Badge> : <Badge variant="outline">否</Badge>}
                      </TableCell>
                      <TableCell className="max-w-72 truncate font-mono text-xs" title={(a.models ?? []).join(", ")}>
                        {(a.models ?? []).slice(0, 4).join(", ") || "-"}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">{a.source}</TableCell>
                      <TableCell>
                        <Button variant="ghost" size="icon" onClick={() => del("assets", a.id)}>
                          <Trash2Icon className="size-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* 详情抽屉：点任意一行看完整上下文（参考 interactsh / trufflehog-explorer 的主从布局） */}
      <Sheet open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <SheetContent className="flex w-full flex-col gap-4 overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2 text-sm">
              {detail?.key_type}
              <span className={cn("rounded px-1.5 py-0.5 text-[11px]", VERIFY_LABEL[detail?.verify_state ?? ""]?.cls)}>
                {VERIFY_LABEL[detail?.verify_state ?? ""]?.text}
              </span>
            </SheetTitle>
            <SheetDescription className="font-mono text-xs">{detail?.masked}</SheetDescription>
          </SheetHeader>

          <dl className="space-y-3 text-xs">
            <Row label="来源类型" value={SOURCE_LABEL[detail?.source_kind ?? "target"] ?? detail?.source_kind ?? "-"} />
            <Row label="来源地址" value={detail?.repo || detail?.url || "-"} mono />
            <Row label="发现时间" value={(detail?.found_at ?? "").replace("T", " ").slice(0, 19) || "-"} />
            {detail?.verify_note ? <Row label="验证说明" value={detail.verify_note} /> : null}
          </dl>

          <div className="mt-auto flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => detail && reveal(detail)}>
              <SearchIcon className="size-3.5" /> 查看原文
            </Button>
            <Button size="sm" variant="outline" onClick={() => detail && copyMasked(detail)}>
              <CopyIcon className="size-3.5" /> 复制掩码
            </Button>
            <Button size="sm" variant="ghost" className="text-destructive"
              onClick={async () => { if (detail) { await del("keys", detail.id); setDetail(null); } }}>
              <Trash2Icon className="size-3.5" /> 删除
            </Button>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[80px_1fr] gap-2">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={cn("break-all", mono && "font-mono")}>{value}</dd>
    </div>
  );
}

function FilterChip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-full border px-2.5 py-0.5 text-[11px] transition-colors",
        active ? "border-primary bg-primary/10 text-foreground" : "border-border text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

function Stat({ label, value, text, hint, tone }: {
  label: string; value?: React.ReactNode; text?: string; hint?: string; tone?: "bad" | "muted";
}) {
  return (
    <div className="flex min-w-0 items-baseline gap-2">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={cn("text-base font-semibold tabular-nums",
        tone === "bad" ? "text-destructive" : tone === "muted" ? "text-muted-foreground" : "")}>
        {text ?? value}
      </span>
      {hint ? <span className="max-w-72 truncate text-[11px] text-muted-foreground" title={hint}>{hint}</span> : null}
    </div>
  );
}

function Divider() {
  return <span className="hidden h-4 w-px bg-border sm:block" />;
}

function Toggle({ checked, onChange, label, title }: { checked: boolean; onChange: (v: boolean) => void; label: string; title?: string }) {
  return (
    <label className="flex items-center gap-2 text-sm" title={title}>
      <Switch checked={checked} onCheckedChange={onChange} size="sm" />
      {label}
    </label>
  );
}

async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(path, {
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    ...opts,
  });
  if (!r.ok) throw new Error((await r.text()).slice(0, 200) || `HTTP ${r.status}`);
  return r.json() as Promise<T>;
}
