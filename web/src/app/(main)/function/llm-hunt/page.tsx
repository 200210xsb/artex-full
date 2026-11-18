"use client";

// 大模型资产与密钥测绘。
//
// 数据来源三条：粘贴清单、资产库、空间测绘/搜索引擎发现。所有探测都是只读 GET，
// 且引擎里写死了每主机上限；这里只负责展示与触发。

import * as React from "react";
import { BrainIcon, Loader2Icon, PlayIcon, RefreshCwIcon, SearchIcon, SquareIcon, Trash2Icon } from "lucide-react";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

type Asset = {
  id: number;
  url: string;
  host: string;
  port: number;
  vendor: string;
  version: string;
  unauth: boolean;
  models: string[] | null;
  evidence: string;
  source: string;
  last_seen: string;
};
type LeakKey = {
  id: number;
  key_type: string;
  masked: string;
  url: string;
  found_at: string;
  source_kind?: string;
  repo?: string;
  verify_state?: string;
  verify_note?: string;
};
type ScanStatus = {
  running: boolean;
  last: { id: number; status: string; total: number; done: number; assets: number; keys: number } | null;
};

export default function LLMHuntPage() {
  const [seeds, setSeeds] = React.useState("");
  const [fromAssets, setFromAssets] = React.useState(false);
  const [useSearch, setUseSearch] = React.useState(true);
  const [dorks, setDorks] = React.useState("");
  const [maxTargets, setMaxTargets] = React.useState("100");
  const [maxFromSearch, setMaxFromSearch] = React.useState("12");
  // 默认口令探测是唯一会发 POST 的动作，默认关闭。
  const [allowAuth, setAllowAuth] = React.useState(false);
  // 泄漏文件狩猎：直接找"响应体里已含 key"的 URL（Hunter/Quake），是拿 key 最短的路径。
  const [huntLeaks, setHuntLeaks] = React.useState(true);

  const [status, setStatus] = React.useState<ScanStatus>({ running: false, last: null });
  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [keys, setKeys] = React.useState<LeakKey[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [revealed, setRevealed] = React.useState<Record<number, string>>({});
  // 密钥狩猎（GitHub 公开仓库）与统计
  const [ghStatus, setGhStatus] = React.useState<{
    ready: boolean; running: boolean; found: number;
    dorks_done?: number; files_fetched?: number; last_error?: string;
  } | null>(null);
  const [stats, setStats] = React.useState<{ by_provider: Record<string, number>; by_source: Record<string, number>; total: number } | null>(null);

  const load = React.useCallback(() => {
    api<ScanStatus>("/api/llmhunt/status").then(setStatus).catch(() => {});
    api<{ assets: Asset[] }>("/api/llmhunt/assets").then((r) => setAssets(r.assets ?? [])).catch(() => {});
    api<{ keys: LeakKey[] }>("/api/llmhunt/keys").then((r) => setKeys(r.keys ?? [])).catch(() => {});
    api<typeof ghStatus>("/api/llmhunt/keyhunt/status").then(setGhStatus).catch(() => {});
    api<typeof stats>("/api/llmhunt/key-stats").then(setStats).catch(() => {});
  }, []);

  React.useEffect(() => {
    load();
    const t = setInterval(() => {
      api<ScanStatus>("/api/llmhunt/status")
        .then((s) => {
          setStatus(s);
          if (s.running) {
            api<{ assets: Asset[] }>("/api/llmhunt/assets").then((r) => setAssets(r.assets ?? [])).catch(() => {});
          }
        })
        .catch(() => {});
    }, 4000);
    return () => clearInterval(t);
  }, [load]);

  const verifyKeys = async () => {
    if (!confirm("验证会用这些密钥向厂商发起一次只读请求（仅列模型，不推理、不重试）。只应在你有权验证的密钥上使用。继续？")) return;
    try {
      const r = await api<{ tried: number; valid: number }>("/api/llmhunt/keys/verify", {
        method: "POST",
        body: JSON.stringify({ confirm: true, limit: 20 }),
      });
      toast.success(`已验证 ${r.tried} 条，其中有效 ${r.valid} 条`);
      load();
    } catch (e) {
      toast.error("验证失败：" + (e as Error).message);
    }
  };

  const startGH = async () => {
    try {
      await api("/api/llmhunt/keyhunt/start", { method: "POST", body: "{}" });
      toast.success("已开始 GitHub 密钥狩猎（公开仓库，只登记不验证）");
      load();
    } catch (e) {
      toast.error("启动失败：" + (e as Error).message);
    }
  };

  const start = async () => {
    if (!seeds.trim() && !fromAssets && !useSearch) {
      toast.error("请粘贴目标、勾选资产库，或勾选搜索引擎发现");
      return;
    }
    setBusy(true);
    try {
      const r = await api<{ scan_id: number }>("/api/llmhunt/scan", {
        method: "POST",
        body: JSON.stringify({
          seeds,
          from_assets: fromAssets,
          use_search: useSearch,
          dorks,
          max_from_search: Number(maxFromSearch) || 12,
          allow_auth: allowAuth,
          hunt_leaks: huntLeaks,
          max_targets: Number(maxTargets) || 100,
        }),
      });
      toast.success(`已开始（scan #${r.scan_id}）`);
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
      toast.success("已请求停止");
    } catch (e) {
      toast.error("停止失败：" + (e as Error).message);
    }
  };

  const reveal = async (id: number) => {
    if (!confirm("这会向服务端取一次密钥明文，15 秒后自动隐藏。确认已获授权？")) return;
    try {
      const r = await api<{ raw: string }>(`/api/llmhunt/keys/${id}/reveal`);
      setRevealed((p) => ({ ...p, [id]: r.raw }));
      setTimeout(() => setRevealed((p) => { const n = { ...p }; delete n[id]; return n; }), 15000);
    } catch (e) {
      toast.error("取原文失败：" + (e as Error).message);
    }
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

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center gap-2">
        <BrainIcon className="size-5 text-muted-foreground" />
        <h1 className="text-xl font-semibold tracking-tight">大模型测绘</h1>
        {status.running ? (
          <Badge variant="secondary" className="gap-1">
            <Loader2Icon className="size-3 animate-spin" /> 扫描中
          </Badge>
        ) : null}
        <Button variant="ghost" size="sm" className="ml-auto" onClick={load}>
          <RefreshCwIcon className="size-3.5" /> 刷新
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        找暴露的大模型服务（Ollama / vLLM / SGLang / Xinference / Dify / Langflow / Flowise / LibreChat / FastGPT / RAGFlow…），
        判定未授权能力，并在目标自身响应里识别泄露的密钥。全部只读 GET：同一主机串行、间隔 ≥1.2 秒、每台最多 8 个请求、
        命中 403/418/429 立即放弃。
      </p>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">扫描目标</CardTitle>
          <CardDescription>
            三个来源可任意组合。空间测绘优先使用 Subfinder 配置里的 FOFA/Quake/Shodan/Hunter key；没有则回落到搜索引擎 dork。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="hunt-seeds" className="text-xs">目标清单（每行 host / host:端口 / URL）</Label>
            <Textarea
              id="hunt-seeds"
              value={seeds}
              onChange={(e) => setSeeds(e.target.value)}
              placeholder={"10.0.0.5:11434\nllm.example.com"}
              className="min-h-20 font-mono text-xs"
            />
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={fromAssets} onCheckedChange={setFromAssets} size="sm" />
              从资产库扫描
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={useSearch} onCheckedChange={setUseSearch} size="sm" />
              用搜索引擎 / 空间测绘发现
            </label>
            <span className="text-xs text-muted-foreground">最多</span>
            <Input
              className="h-8 w-20"
              value={maxTargets}
              onChange={(e) => setMaxTargets(e.target.value)}
            />
            <span className="text-xs text-muted-foreground">目标</span>
            {useSearch ? (
              <>
                <span className="text-xs text-muted-foreground">发现上限</span>
                <Input
                  className="h-8 w-20"
                  value={maxFromSearch}
                  onChange={(e) => setMaxFromSearch(e.target.value)}
                />
              </>
            ) : null}
            <label className="flex items-center gap-2 text-sm" title="用 Hunter/Quake 找响应体里本来就含 key 的 URL，再取回来；这是拿 key 最短的路径">
              <Switch checked={huntLeaks} onCheckedChange={setHuntLeaks} size="sm" />
              先找泄漏的密钥文件
            </label>
            <label className="flex items-center gap-2 text-sm" title="只试每个平台最常见的默认口令；登录后只读配置，不创建/不修改任何东西">
              <Switch checked={allowAuth} onCheckedChange={setAllowAuth} size="sm" />
              默认口令探测（POST）
            </label>
            <Button onClick={start} disabled={busy || status.running}>
              {busy ? <Loader2Icon className="size-3.5 animate-spin" /> : <PlayIcon className="size-3.5" />}
              开始测绘
            </Button>
            <Button variant="outline" onClick={stop} disabled={!status.running}>
              <SquareIcon className="size-3.5" /> 停止
            </Button>
          </div>

          {useSearch ? (
            <div className="space-y-1.5">
              <Label htmlFor="hunt-dorks" className="text-xs">自定义搜索词（留空用内置指纹词）</Label>
              <Textarea
                id="hunt-dorks"
                value={dorks}
                onChange={(e) => setDorks(e.target.value)}
                placeholder={'app:"Ollama"\napp:"vLLM"\nweb.title="LibreChat"'}
                className="min-h-16 font-mono text-xs"
              />
            </div>
          ) : null}

          {last ? (
            <p className="text-xs text-muted-foreground">
              上次（#{last.id}）：{last.status} · {last.done}/{last.total} 目标 · 实例 {last.assets} · 密钥 {last.keys}
            </p>
          ) : null}
        </CardContent>
      </Card>

      <Tabs defaultValue="assets" className="flex min-h-0 flex-1 flex-col">
        <TabsList>
          <TabsTrigger value="assets">发现的实例 <span className="ml-1 text-muted-foreground">{assets.length}</span></TabsTrigger>
          <TabsTrigger value="keys">泄露的密钥 <span className="ml-1 text-muted-foreground">{keys.length}</span></TabsTrigger>
        </TabsList>

        <TabsContent value="assets" className="min-h-0 flex-1 overflow-auto">
          <Card>
            <CardContent className="pt-4">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>URL</TableHead>
                    <TableHead>组件</TableHead>
                    <TableHead>版本</TableHead>
                    <TableHead>未授权</TableHead>
                    <TableHead>模型</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead className="w-10" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground">
                        还没有结果。设置目标后点「开始测绘」。
                      </TableCell>
                    </TableRow>
                  ) : (
                    assets.map((a) => (
                      <TableRow key={a.id}>
                        <TableCell className="font-mono text-xs">{a.url}</TableCell>
                        <TableCell>{a.vendor || "-"}</TableCell>
                        <TableCell className="font-mono text-xs">{a.version || "-"}</TableCell>
                        <TableCell>
                          {a.unauth ? <Badge variant="destructive">可未授权访问</Badge> : <Badge variant="outline">否</Badge>}
                        </TableCell>
                        <TableCell className="max-w-64 truncate font-mono text-xs" title={(a.models ?? []).join(", ")}>
                          {(a.models ?? []).slice(0, 4).join(", ") || "-"}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">{a.source}</TableCell>
                        <TableCell>
                          <Button variant="ghost" size="icon" onClick={() => del("assets", a.id)}>
                            <Trash2Icon className="size-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="keys" className="min-h-0 flex-1 overflow-auto">
          <Card>
            <CardContent className="space-y-3 pt-4">
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" onClick={startGH} disabled={!ghStatus?.ready || ghStatus?.running}>
                  {ghStatus?.running ? <Loader2Icon className="size-3.5 animate-spin" /> : <SearchIcon className="size-3.5" />}
                  GitHub 公开仓库狩猎
                </Button>
                <Button size="sm" variant="outline" onClick={verifyKeys} disabled={ghStatus?.running}>
                  <SearchIcon className="size-3.5" /> 验证可用性
                </Button>
                {ghStatus ? (
                  <span className="text-xs text-muted-foreground">
                    {ghStatus.ready ? (ghStatus.running ? "运行中…" : "就绪") : "未配置 token"}
                    {ghStatus.dorks_done ? ` · 检索 ${ghStatus.dorks_done} 条` : ""}
                    {ghStatus.files_fetched ? ` · 抓取 ${ghStatus.files_fetched} 个文件` : ""}
                    {ghStatus.found ? ` · 命中 ${ghStatus.found}` : ""}
                    {ghStatus.last_error ? ` · 错误: ${ghStatus.last_error.slice(0, 60)}` : ""}
                  </span>
                ) : null}
                {stats ? (
                  <span className="ml-auto flex flex-wrap gap-1">
                    {Object.entries(stats.by_provider).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, n]) => (
                      <Badge key={k} variant="secondary" className="text-[11px]">{k} {n}</Badge>
                    ))}
                  </span>
                ) : null}
              </div>
              <p className="text-xs text-muted-foreground">
                默认只显示掩码；点「查看原文」才向服务端取一次明文，15 秒后自动隐藏，原文不写日志。
                GitHub 狩猎只搜公开仓库（GitHub 自己的 secret scanning 也在扫同一批东西），不接触任何被测站点，且**只登记不验证**。
              </p>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>类型</TableHead>
                    <TableHead>掩码</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead>可用性</TableHead>
                    <TableHead>发现时间</TableHead>
                    <TableHead className="w-32" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {keys.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-muted-foreground">
                        还没有发现密钥。
                      </TableCell>
                    </TableRow>
                  ) : (
                    keys.map((k) => (
                      <TableRow key={k.id}>
                        <TableCell>{k.key_type}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {revealed[k.id] ? <span className="text-destructive">{revealed[k.id]}</span> : k.masked}
                        </TableCell>
                        <TableCell className="max-w-80 truncate font-mono text-xs" title={k.url}>
                          <span className="text-muted-foreground">{(k as LeakKey & { source_kind?: string }).source_kind === "github" ? "github: " : ""}</span>
                          {(k as LeakKey & { repo?: string }).repo || k.url}
                        </TableCell>
                        <TableCell className="text-xs">
                          {k.verify_state === "valid" ? <Badge variant="destructive">有效</Badge>
                            : k.verify_state === "invalid" ? <Badge variant="outline">无效</Badge>
                            : k.verify_state === "unsupported" ? <span className="text-muted-foreground">不验证</span>
                            : k.verify_state === "error" ? <span className="text-muted-foreground">不确定</span>
                            : <span className="text-muted-foreground">未验证</span>}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">
                          {(k.found_at ?? "").replace("T", " ").slice(0, 19)}
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button variant="outline" size="sm" className="h-7" onClick={() => reveal(k.id)}>
                              <SearchIcon className="size-3" /> 原文
                            </Button>
                            <Button variant="ghost" size="icon" onClick={() => del("keys", k.id)}>
                              <Trash2Icon className="size-3.5" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// api 是极简 fetch 包装：与 SPA 一致地带同源凭据，非 2xx 抛错。
async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(path, {
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    ...opts,
  });
  if (!r.ok) throw new Error((await r.text()).slice(0, 200) || `HTTP ${r.status}`);
  return r.json() as Promise<T>;
}
