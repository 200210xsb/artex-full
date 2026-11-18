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
type ScanStatus = {
  running: boolean;
  last: { id: number; status: string; total: number; done: number; keys: number; note?: string } | null;
};
type KeyStats = { by_provider: Record<string, number>; by_source: Record<string, number>; total: number; verified: number };
type GHStatus = { ready: boolean; running: boolean; found: number; dorks_done?: number; files_fetched?: number; last_error?: string };

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
  const [allowAuth, setAllowAuth] = usePersisted("allowAuth", false);
  const [seeds, setSeeds] = React.useState("");
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const [provider, setProvider] = React.useState<string>("");
  const [onlyVerified, setOnlyVerified] = React.useState(false);
  const [revealed, setRevealed] = React.useState<Record<number, string>>({});
  const [copied, setCopied] = React.useState<number | null>(null);

  const load = React.useCallback(() => {
    api<ScanStatus>("/api/llmhunt/status").then(setStatus).catch(() => {});
    api<KeyStats>("/api/llmhunt/key-stats").then(setStats).catch(() => {});
    api<{ assets: Asset[] }>("/api/llmhunt/assets").then((r) => setAssets(r.assets ?? [])).catch(() => {});
    api<{ keys: LeakKey[] }>("/api/llmhunt/keys").then((r) => setKeys(r.keys ?? [])).catch(() => {});
    api<GHStatus>("/api/llmhunt/keyhunt/status").then(setGh).catch(() => {});
  }, []);

  React.useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  const startHunt = async () => {
    setBusy(true);
    try {
      await api("/api/llmhunt/scan", {
        method: "POST",
        body: JSON.stringify({
          seeds, from_assets: fromAssets, use_search: useSearch, hunt_leaks: huntLeaks,
          allow_auth: allowAuth, repeat, repeat_minutes: 5, auto_verify: autoVerify,
        }),
      });
      toast.success(repeat ? "已开始持续狩猎（每 5 分钟一轮）" : "已开始狩猎");
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
  const shown = keys.filter((k) => (!provider || k.key_type === provider) && (!onlyVerified || k.verify_state === "valid"));

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 p-1">
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

      {/* KPI */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi label="泄漏密钥" value={stats?.total ?? 0} hint="按指纹去重" />
        <Kpi label="已确认有效" value={stats?.verified ?? 0} tone={stats?.verified ? "bad" : "muted"} hint="仅 OpenAI / Anthropic 可验证" />
        <Kpi label="暴露实例" value={assets.length} hint="Ollama / Dify / Flowise …" />
        <Kpi
          label="狩猎状态"
          value={status.running ? "运行中" : last ? "已停止" : "未开始"}
          hint={last?.note || (last ? `#${last.id} · ${last.status}` : "点「开始狩猎」")}
        />
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
                <Toggle checked={repeat} onChange={setRepeat} label="持续狩猎（5 分钟一轮）" title="直到手动停止" />
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
              {gh ? `GitHub：${gh.ready ? (gh.running ? "运行中" : "就绪") : "未配置"}${gh.files_fetched ? ` · 抓取 ${gh.files_fetched} 文件` : ""}${gh.last_error ? ` · ${gh.last_error.slice(0, 40)}` : ""}` : ""}
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
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => setProvider("")}
                  className={cn("rounded-full border px-2.5 py-0.5 text-[11px]",
                    provider === "" ? "border-primary text-foreground" : "text-muted-foreground")}
                >
                  全部 {stats?.total ?? 0}
                </button>
                {providers.map(([p, n]) => (
                  <button key={p} onClick={() => setProvider(p === provider ? "" : p)}
                    className={cn("rounded-full border px-2.5 py-0.5 text-[11px]",
                      provider === p ? "border-primary text-foreground" : "text-muted-foreground")}>
                    {p} {n}
                  </button>
                ))}
                <label className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
                  <Switch checked={onlyVerified} onCheckedChange={setOnlyVerified} size="sm" />
                  只看有效
                </label>
                <Button size="sm" variant="outline" onClick={exportCsv} disabled={shown.length === 0}>
                  <CopyIcon className="size-3.5" /> 导出 CSV
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
                        <TableRow key={k.id}>
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
                            <div className="flex gap-1">
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
    </div>
  );
}

function Kpi({ label, value, hint, tone }: { label: string; value: React.ReactNode; hint?: string; tone?: "bad" | "muted" }) {
  return (
    <Card>
      <CardContent className="py-3">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className={cn("mt-0.5 text-2xl font-semibold tabular-nums",
          tone === "bad" ? "text-destructive" : tone === "muted" ? "text-muted-foreground" : "")}>{value}</p>
        {hint ? <p className="mt-0.5 text-[11px] text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  );
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
