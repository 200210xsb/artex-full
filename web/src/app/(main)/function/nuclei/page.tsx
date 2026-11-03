"use client";

// Nuclei POC 页面：模板库浏览 + 对目标实打 + 高危快捷入口。
//
// 后端是 server/nuclei.go（直调 /opt/artex/bin/nuclei，不经 MCP 子进程）。
// 扫描用 SSE 流式返回：每命中一条就推一条，页面边跑边显示。
// 拿到 RCE / 上传类命中后，去 WebShell 页面取马落地（payload → 上传 → 登记），
// 形成「打点 → 拿 shell → 管 shell」的闭环——和 MCP 里的提示一致。

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowRightIcon,
  ChevronDownIcon,
  CopyIcon,
  CrosshairIcon,
  FingerprintIcon,
  Loader2Icon,
  RadarIcon,
  RefreshCwIcon,
  SearchIcon,
  ShieldAlertIcon,
  SquareTerminalIcon,
  XIcon,
} from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Slider } from "@/components/ui/slider";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type {
  NucleiAutorunSummary,
  NucleiFingerprint,
  NucleiHit,
  NucleiMatchCandidate,
  NucleiRunSummary,
  NucleiSearchResponse,
  NucleiStats,
  NucleiTemplate,
  NucleiTemplateDetail,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

/** 常用 tag，点一下即多选；够覆盖攻防演练里挑 POC 的场景。 */
const TAG_PRESETS = [
  "rce",
  "command-injection",
  "file-upload",
  "deserialization",
  "sqli",
  "lfi",
  "xss",
  "ssrf",
  "unauth",
  "default-login",
  "exposure",
  "cve",
];

/** 高危快捷入口：这几个 tag 是「可能直接拿 shell」的主力。 */
const DANGER_SHORTCUTS = [
  { tag: "rce", label: "远程命令执行", hint: "命中即等于拿到命令通道" },
  { tag: "command-injection", label: "命令注入", hint: "参数里直接回显命令结果" },
  { tag: "file-upload", label: "文件上传", hint: "能落地文件 → 传马即拿 shell" },
  { tag: "deserialization", label: "反序列化", hint: "需构造 gadget 链，命中价值高" },
];

/** 「拿 shell 概率」档位 → 徽章配色（A 最红，F 最灰）。 */
const TIER_CLASS: Record<string, string> = {
  A: "border-red-500/30 bg-red-500/15 text-red-600 dark:text-red-400",
  B: "border-orange-500/30 bg-orange-500/15 text-orange-600 dark:text-orange-400",
  C: "border-amber-500/30 bg-amber-500/15 text-amber-700 dark:text-amber-400",
  D: "border-yellow-500/30 bg-yellow-500/15 text-yellow-700 dark:text-yellow-400",
  E: "border-sky-500/30 bg-sky-500/15 text-sky-600 dark:text-sky-400",
  F: "border-border bg-muted text-muted-foreground",
};

/** 把逗号/空白分隔的输入拆成去重列表（手动指定指纹、模板时用）。 */
function splitList(raw: string): string[] {
  return raw
    .split(/[,，\s]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/** 自动匹配进行到哪一步了（按钮上的文案）。 */
function autoStageLabel(stage: "idle" | "probe" | "match" | "run" | "done"): string {
  switch (stage) {
    case "probe":
      return "识别指纹中…";
    case "match":
      return "匹配 POC 中…";
    case "run":
      return "实弹验证中…";
    default:
      return "处理中…";
  }
}

/** 命中是否「可用于落马」（命令执行 / 文件上传类）。 */
function hitLandable(h: NucleiHit): boolean {
  const tags = (h.tags ?? "").toLowerCase();
  return /(^|,)(rce|remote-code-execution|file-upload|arbitrary-file-upload|unrestricted-file-upload|file-write|arbitrary-file-write)(,|$)/.test(
    tags,
  );
}

const token = () => (typeof window === "undefined" ? null : localStorage.getItem("artex_token"));

function Chip({
  active,
  onClick,
  children,
}: {
  active?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded-md border px-2 py-0.5 text-xs transition-colors",
        active
          ? "border-primary bg-primary text-primary-foreground"
          : "border-border text-muted-foreground hover:bg-muted hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

function tagList(tags: string): string[] {
  return tags
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

/** 模板表：模板库里和高危快捷区共用一份渲染。 */
function TemplateTable({
  items,
  onOpen,
  onAdd,
}: {
  items: NucleiTemplate[];
  onOpen: (t: NucleiTemplate) => void;
  onAdd: (t: NucleiTemplate) => void;
}) {
  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="min-w-[16rem]">模板</TableHead>
            <TableHead className="w-24">严重性</TableHead>
            <TableHead className="min-w-[14rem]">标签</TableHead>
            <TableHead className="w-40">作者</TableHead>
            <TableHead className="w-28 text-right">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((t) => (
            <TableRow key={t.id} className="cursor-pointer" onClick={() => onOpen(t)}>
              <TableCell>
                <div className="font-medium">{t.name || "(无名称)"}</div>
                <div className="text-muted-foreground font-mono text-xs">{t.id}</div>
              </TableCell>
              <TableCell>
                <StatusBadge domain="severity" value={t.severity} dot />
              </TableCell>
              <TableCell>
                <div className="flex flex-wrap gap-1">
                  {tagList(t.tags)
                    .slice(0, 4)
                    .map((tg) => (
                      <Badge key={tg} variant="outline" className="font-mono text-[10px] font-normal">
                        {tg}
                      </Badge>
                    ))}
                  {tagList(t.tags).length > 4 && (
                    <span className="text-muted-foreground text-[10px]">
                      +{tagList(t.tags).length - 4}
                    </span>
                  )}
                </div>
              </TableCell>
              <TableCell className="text-muted-foreground max-w-40 truncate text-xs">
                {t.author || "—"}
              </TableCell>
              <TableCell className="text-right">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={(e) => {
                    e.stopPropagation();
                    onAdd(t);
                  }}
                >
                  加入打点
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function NucleiInner() {
  const [stats, setStats] = React.useState<NucleiStats | null>(null);
  const [statsLoading, setStatsLoading] = React.useState(false);

  // 筛选
  const [keyword, setKeyword] = React.useState("");
  const [tags, setTags] = React.useState<string[]>([]);
  const [severities, setSeverities] = React.useState<string[]>([]);
  const [result, setResult] = React.useState<NucleiSearchResponse | null>(null);
  const [searching, setSearching] = React.useState(false);

  // 详情抽屉
  const [detail, setDetail] = React.useState<NucleiTemplateDetail | null>(null);
  const [detailOpen, setDetailOpen] = React.useState(false);
  const [detailLoading, setDetailLoading] = React.useState(false);

  // 打点
  const [picked, setPicked] = React.useState<NucleiTemplate[]>([]);
  const [target, setTarget] = React.useState("");
  const [rate, setRate] = React.useState(50);
  const [timeout, setTimeoutSec] = React.useState(180);
  const [running, setRunning] = React.useState(false);
  const [hits, setHits] = React.useState<NucleiHit[]>([]);
  const [summary, setSummary] = React.useState<NucleiRunSummary | null>(null);

  // 高危快捷区
  const [dangerTag, setDangerTag] = React.useState<string>("rce");
  const [dangerResult, setDangerResult] = React.useState<NucleiSearchResponse | null>(null);
  const [dangerLoading, setDangerLoading] = React.useState(false);

  // 自动匹配（指纹 → 候选 POC → 实弹验证）
  const [autoTarget, setAutoTarget] = React.useState("");
  const [autoRunning, setAutoRunning] = React.useState(false);
  /** 阶段：探测指纹 → 匹配候选 → 实弹验证 → 结束 */
  const [autoStage, setAutoStage] = React.useState<"idle" | "probe" | "match" | "run" | "done">(
    "idle",
  );
  const [autoFingerprints, setAutoFingerprints] = React.useState<NucleiFingerprint[]>([]);
  const [autoSource, setAutoSource] = React.useState("");
  const [autoNote, setAutoNote] = React.useState("");
  const [autoCandidates, setAutoCandidates] = React.useState<NucleiMatchCandidate[]>([]);
  const [autoCandidateTotal, setAutoCandidateTotal] = React.useState(0);
  const [autoHits, setAutoHits] = React.useState<NucleiHit[]>([]);
  const [autoSummary, setAutoSummary] = React.useState<NucleiAutorunSummary | null>(null);
  const [autoMessage, setAutoMessage] = React.useState("");
  // 高级选项
  const [autoLimit, setAutoLimit] = React.useState(50);
  const [autoRate, setAutoRate] = React.useState(50);
  const [autoTimeout, setAutoTimeout] = React.useState(180);
  const [autoFpInput, setAutoFpInput] = React.useState("");
  const [autoTplInput, setAutoTplInput] = React.useState("");
  const [autoAdvanced, setAutoAdvanced] = React.useState(false);
  const [autoAssetIds, setAutoAssetIds] = React.useState("");
  const [tab, setTab] = React.useState("library");

  // 资产页跳过来时带的参数：/function/nuclei/?target=…&templates=…&asset_ids=…
  // 三个参数都容错：缺失或非法都不影响页面照常工作。
  const searchParams = useSearchParams();
  const qTarget = (searchParams.get("target") ?? "").trim();
  const qTemplates = (searchParams.get("templates") ?? "").trim();
  const qAssetIDs = (searchParams.get("asset_ids") ?? "").trim();

  React.useEffect(() => {
    if (qTarget) {
      setAutoTarget(qTarget);
      setTab("auto"); // 直接落到「自动匹配」区块，别让用户自己找
    }
    if (qTemplates) {
      setAutoTplInput(qTemplates);
      setAutoAdvanced(true);
    }
    if (qAssetIDs) {
      setAutoAssetIds(qAssetIDs);
    }
  }, [qTarget, qTemplates, qAssetIDs]);

  const loadStats = React.useCallback(async () => {
    setStatsLoading(true);
    try {
      setStats(await api.nucleiStats());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "模板库概况加载失败");
    } finally {
      setStatsLoading(false);
    }
  }, []);

  const runSearch = React.useCallback(async () => {
    setSearching(true);
    try {
      setResult(
        await api.nucleiSearch({
          keyword,
          tags: tags.join(","),
          severity: severities.join(","),
          limit: 100,
        }),
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "模板检索失败");
    } finally {
      setSearching(false);
    }
  }, [keyword, tags, severities]);

  const loadDanger = React.useCallback(async (tag: string) => {
    setDangerLoading(true);
    setDangerTag(tag);
    try {
      setDangerResult(await api.nucleiSearch({ tags: tag, limit: 60 }));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "高危模板加载失败");
    } finally {
      setDangerLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadStats();
    void runSearch();
    void loadDanger("rce");
  }, [loadStats, runSearch, loadDanger]);

  async function openDetail(t: NucleiTemplate) {
    setDetailOpen(true);
    setDetailLoading(true);
    setDetail(null);
    try {
      setDetail(await api.nucleiTemplate(t.id));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "模板详情加载失败");
      setDetailOpen(false);
    } finally {
      setDetailLoading(false);
    }
  }

  function addToScan(t: NucleiTemplate) {
    setPicked((prev) => (prev.some((x) => x.id === t.id) ? prev : [...prev, t]));
    toast.success(`已加入打点：${t.id}`);
  }

  function toggle(list: string[], value: string, setter: (v: string[]) => void) {
    setter(list.includes(value) ? list.filter((x) => x !== value) : [...list, value]);
  }

  async function copy(text: string, label = "已复制") {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(label);
    } catch {
      toast.error("复制失败（浏览器不允许写剪贴板）");
    }
  }

  /** 跑一次扫描：SSE 逐条接收命中。 */
  async function runScan() {
    const t = target.trim();
    if (!t) {
      toast.error("先填目标：URL 或 host，例如 https://10.0.0.5:8443");
      return;
    }
    if (picked.length === 0 && tags.length === 0 && severities.length === 0) {
      toast.error("至少选一个模板、标签或严重性，否则会跑全库 1 万+ 模板");
      return;
    }
    setHits([]);
    setSummary(null);
    setRunning(true);
    const tk = token();
    try {
      const res = await fetch("/api/nuclei/run", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(tk ? { Authorization: `Bearer ${tk}` } : {}),
        },
        body: JSON.stringify({
          target: t,
          templates: picked.map((x) => x.id),
          tags: tags.join(","),
          severity: severities.join(","),
          rate,
          timeout,
          stream: true,
        }),
      });
      if (!res.ok) {
        let msg = `扫描失败：HTTP ${res.status}`;
        try {
          const j = (await res.json()) as { error?: string };
          if (j?.error) msg = j.error;
        } catch {
          // 非 JSON 错误体：保留状态码兜底
        }
        throw new Error(msg);
      }
      if (!res.body) throw new Error("当前浏览器不支持流式读取");

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let received = 0;

      const handleFrame = (frame: string) => {
        let event = "message";
        let data = "";
        for (const line of frame.split("\n")) {
          if (line.startsWith("event: ")) event = line.slice(7).trim();
          else if (line.startsWith("data: ")) data += line.slice(6);
        }
        if (!data) return;
        let payload: unknown;
        try {
          payload = JSON.parse(data);
        } catch {
          return;
        }
        if (event === "hit") {
          received += 1;
          setHits((prev) => [...prev, payload as NucleiHit]);
        } else if (event === "summary") {
          const s = payload as NucleiRunSummary;
          setSummary(s);
          if (s.matched > 0) toast.success(`扫描完成：命中 ${s.matched} 条`);
          else toast.message("扫描完成：未命中");
        } else if (event === "error") {
          const e = payload as { error?: string };
          toast.error(e.error ?? "扫描出错");
        }
      };

      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let idx = buffer.indexOf("\n\n");
        while (idx >= 0) {
          handleFrame(buffer.slice(0, idx));
          buffer = buffer.slice(idx + 2);
          idx = buffer.indexOf("\n\n");
        }
      }
      if (received === 0) {
        // 没有命中也要给个结束感，避免页面看着像卡住
        toast.message("扫描结束：没有命中任何模板");
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "扫描失败");
    } finally {
      setRunning(false);
    }
  }

  const sevCount = (s: string) => stats?.severity?.[s] ?? 0;
  const totalTags = stats?.top_tags?.length ?? 0;

  /**
   * 一键「识别并验证」：探测指纹 → 匹配候选 POC → 实弹验证。
   * 后端用 SSE 依次推 fingerprint / candidates / hit / summary，页面按三段渲染。
   */
  async function runAuto() {
    const t = autoTarget.trim();
    if (!t) {
      toast.error("先填目标 URL，例如 http://127.0.0.1:18082");
      return;
    }
    setAutoRunning(true);
    setAutoStage("probe");
    setAutoFingerprints([]);
    setAutoSource("");
    setAutoNote("");
    setAutoCandidates([]);
    setAutoCandidateTotal(0);
    setAutoHits([]);
    setAutoSummary(null);
    setAutoMessage("");

    const tk = token();
    try {
      const res = await fetch("/api/nuclei/autorun", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(tk ? { Authorization: `Bearer ${tk}` } : {}),
        },
        body: JSON.stringify({
          target: t,
          fingerprints: splitList(autoFpInput),
          templates: splitList(autoTplInput),
          asset_ids: splitList(autoAssetIds),
          limit: autoLimit,
          rate_limit: autoRate,
          timeout: autoTimeout,
          stream: true,
        }),
      });
      if (!res.ok) {
        let msg = `验证失败：HTTP ${res.status}`;
        try {
          const j = (await res.json()) as { error?: string };
          if (j?.error) msg = j.error;
        } catch {
          // 非 JSON 错误体：保留状态码兜底
        }
        throw new Error(msg);
      }
      if (!res.body) throw new Error("当前浏览器不支持流式读取");

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      const handleFrame = (frame: string) => {
        let event = "message";
        let data = "";
        for (const line of frame.split("\n")) {
          if (line.startsWith("event: ")) event = line.slice(7).trim();
          else if (line.startsWith("data: ")) data += line.slice(6);
        }
        if (!data) return;
        let payload: unknown;
        try {
          payload = JSON.parse(data);
        } catch {
          return;
        }
        if (event === "fingerprint") {
          const p = payload as {
            fingerprints?: NucleiFingerprint[];
            source?: string;
            note?: string;
          };
          setAutoFingerprints(p.fingerprints ?? []);
          setAutoSource(p.source ?? "");
          setAutoNote(p.note ?? "");
          setAutoStage("match");
        } else if (event === "candidates") {
          const p = payload as {
            total?: number;
            items?: NucleiMatchCandidate[];
            message?: string;
          };
          setAutoCandidates(p.items ?? []);
          setAutoCandidateTotal(p.total ?? 0);
          setAutoMessage(p.message ?? "");
          setAutoStage("run");
        } else if (event === "hit") {
          setAutoHits((prev) => [...prev, payload as NucleiHit]);
        } else if (event === "summary") {
          const s = payload as NucleiAutorunSummary;
          setAutoSummary(s);
          setAutoStage("done");
          if (s.matched > 0) toast.success(`验证完成：命中 ${s.matched} 条`);
          else toast.message("验证完成：未命中");
        } else if (event === "error") {
          const e = payload as { error?: string };
          setAutoStage("done");
          toast.error(e.error ?? "验证出错");
        }
      };

      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let idx = buffer.indexOf("\n\n");
        while (idx >= 0) {
          handleFrame(buffer.slice(0, idx));
          buffer = buffer.slice(idx + 2);
          idx = buffer.indexOf("\n\n");
        }
      }
    } catch (err) {
      setAutoStage("done");
      toast.error(err instanceof Error ? err.message : "验证失败");
    } finally {
      setAutoRunning(false);
    }
  }

  /** 候选 POC 的「拿 shell 概率」徽章。 */
  function tierBadge(c: NucleiMatchCandidate) {
    return (
      <Badge
        variant="outline"
        className={cn("font-mono text-[10px]", TIER_CLASS[c.tier] ?? TIER_CLASS.F)}
        title={c.tier_label}
      >
        {c.tier} 级
      </Badge>
    );
  }

  return (
    <div className="flex flex-1 flex-col gap-4 pb-6">
      {/* 顶部：模板库概况 */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1.5">
              <RadarIcon className="size-3.5" /> 模板总数
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">
              {statsLoading && !stats ? <Loader2Icon className="size-5 animate-spin" /> : (stats?.total ?? 0)}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground truncate text-xs">{stats?.dir ?? "—"}</CardContent>
        </Card>

        <Card className="sm:col-span-2">
          <CardHeader className="pb-2">
            <CardDescription>按严重性分布</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap items-center gap-2">
            {SEVERITIES.map((s) => (
              <span key={s} className="inline-flex items-center gap-1.5">
                <StatusBadge domain="severity" value={s} dot />
                <span className="text-sm font-medium tabular-nums">{sevCount(s)}</span>
              </span>
            ))}
            {sevCount("info") > 0 && (
              <span className="inline-flex items-center gap-1.5">
                <StatusBadge domain="severity" value="info" />
                <span className="text-sm font-medium tabular-nums">{sevCount("info")}</span>
              </span>
            )}
            <Button
              size="sm"
              variant="ghost"
              className="ml-auto"
              onClick={() => void loadStats()}
              disabled={statsLoading}
            >
              {statsLoading ? (
                <Loader2Icon className="size-3.5 animate-spin" />
              ) : (
                <RefreshCwIcon className="size-3.5" />
              )}
              刷新
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>最后更新</CardDescription>
            <CardTitle className="text-sm font-medium">{stats?.last_commit || "未知"}</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground space-y-1 text-xs">
            <div>提交：{stats?.head || "—"}</div>
            <div>标签种类：{totalTags}+</div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={tab} onValueChange={setTab} className="gap-4">
        <TabsList>
          <TabsTrigger value="library">
            <SearchIcon className="size-3.5" /> 模板库
          </TabsTrigger>
          <TabsTrigger value="danger">
            <ShieldAlertIcon className="size-3.5" /> 高危 POC
          </TabsTrigger>
          <TabsTrigger value="scan">
            <CrosshairIcon className="size-3.5" /> 打点
            {hits.length > 0 && (
              <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px]">
                {hits.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="auto">
            <FingerprintIcon className="size-3.5" /> 自动匹配
            {autoHits.length > 0 && (
              <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px]">
                {autoHits.length}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        {/* ---------------- 模板库 ---------------- */}
        <TabsContent value="library" className="space-y-3">
          <Card>
            <CardContent className="space-y-3 pt-4">
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-64 flex-1">
                  <SearchIcon className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
                  <Input
                    value={keyword}
                    onChange={(e) => setKeyword(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void runSearch();
                    }}
                    placeholder="关键词：模板 id / 名称 / 路径 / tag，例如 log4j、thinkphp、CVE-2021"
                    className="pl-8"
                  />
                </div>
                <Button onClick={() => void runSearch()} disabled={searching}>
                  {searching ? <Loader2Icon className="size-4 animate-spin" /> : <SearchIcon className="size-4" />}
                  搜索
                </Button>
                {(keyword || tags.length > 0 || severities.length > 0) && (
                  <Button
                    variant="ghost"
                    onClick={() => {
                      setKeyword("");
                      setTags([]);
                      setSeverities([]);
                    }}
                  >
                    清空
                  </Button>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-muted-foreground mr-1 text-xs">标签</span>
                {TAG_PRESETS.map((t) => (
                  <Chip key={t} active={tags.includes(t)} onClick={() => toggle(tags, t, setTags)}>
                    {t}
                  </Chip>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-muted-foreground mr-1 text-xs">严重性</span>
                {SEVERITIES.map((s) => (
                  <Chip
                    key={s}
                    active={severities.includes(s)}
                    onClick={() => toggle(severities, s, setSeverities)}
                  >
                    {s}
                  </Chip>
                ))}
              </div>

              <div className="text-muted-foreground text-xs">
                {searching
                  ? "检索中…"
                  : result
                    ? `共匹配 ${result.total} 个，显示前 ${result.items.length} 个（点行看 YAML 全文）`
                    : "—"}
              </div>
            </CardContent>
          </Card>

          {searching && !result ? (
            <div className="text-muted-foreground flex items-center gap-2 py-10 text-sm">
              <Loader2Icon className="size-4 animate-spin" /> 正在检索模板…
            </div>
          ) : result && result.items.length > 0 ? (
            <TemplateTable items={result.items} onOpen={(t) => void openDetail(t)} onAdd={addToScan} />
          ) : (
            <Card>
              <CardContent className="text-muted-foreground py-10 text-center text-sm">
                没有匹配的模板。放宽关键词或标签再试；也可以看看「高危 POC」。
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ---------------- 高危 POC ---------------- */}
        <TabsContent value="danger" className="space-y-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">一键筛高危模板</CardTitle>
              <CardDescription>
                这几类是「可能直接拿到 shell」的主力；命中后去 WebShell 页面取马落地。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {DANGER_SHORTCUTS.map((d) => (
                  <Button
                    key={d.tag}
                    size="sm"
                    variant={dangerTag === d.tag ? "default" : "outline"}
                    onClick={() => void loadDanger(d.tag)}
                    disabled={dangerLoading}
                  >
                    <ShieldAlertIcon className="size-3.5" />
                    {d.label}
                    <span className="text-muted-foreground ml-1 font-mono text-[10px]">{d.tag}</span>
                  </Button>
                ))}
              </div>
              <div className="text-muted-foreground text-xs">
                {DANGER_SHORTCUTS.find((d) => d.tag === dangerTag)?.hint ?? ""}
              </div>
              <div className="flex items-center gap-2 rounded-lg border border-dashed px-3 py-2 text-xs">
                <SquareTerminalIcon className="text-muted-foreground size-4 shrink-0" />
                <span className="text-muted-foreground">
                  命中 RCE / 上传类后，去 WebShell 页面按 <span className="font-mono">payload → 上传 → 登记</span> 落地马子。
                </span>
                <Button asChild size="sm" variant="link" className="ml-auto shrink-0">
                  <Link href="/function/webshell">
                    去 WebShell <ArrowRightIcon className="size-3.5" />
                  </Link>
                </Button>
              </div>
            </CardContent>
          </Card>

          {dangerLoading ? (
            <div className="text-muted-foreground flex items-center gap-2 py-10 text-sm">
              <Loader2Icon className="size-4 animate-spin" /> 正在筛模板…
            </div>
          ) : dangerResult && dangerResult.items.length > 0 ? (
            <>
              <div className="text-muted-foreground text-xs">
                tag={dangerTag} 共 {dangerResult.total} 个，显示前 {dangerResult.items.length} 个
              </div>
              <TemplateTable
                items={dangerResult.items}
                onOpen={(t) => void openDetail(t)}
                onAdd={addToScan}
              />
            </>
          ) : (
            <Card>
              <CardContent className="text-muted-foreground py-10 text-center text-sm">
                没有筛到模板。换一个分类，或先确认模板库已下载完整。
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ---------------- 打点 ---------------- */}
        <TabsContent value="scan" className="space-y-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">对目标实打</CardTitle>
              <CardDescription>
                只打你被授权测试的目标。默认限速 50 请求/秒，对公网目标别调高。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="nuclei-target">目标（URL 或 host）</Label>
                <Input
                  id="nuclei-target"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://10.0.0.5:8443 或 example.com"
                />
              </div>

              <div className="flex flex-col gap-1.5">
                <Label>已选模板（{picked.length}）</Label>
                {picked.length === 0 ? (
                  <div className="text-muted-foreground rounded-md border border-dashed px-3 py-2 text-xs">
                    还没选模板：去「模板库」或「高危 POC」点「加入打点」；也可以只用下面的标签/严重性扫。
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {picked.map((t) => (
                      <Badge key={t.id} variant="secondary" className="gap-1 font-mono text-[11px]">
                        {t.id}
                        <button
                          type="button"
                          onClick={() => setPicked((prev) => prev.filter((x) => x.id !== t.id))}
                          className="hover:text-destructive"
                          aria-label={`移除 ${t.id}`}
                        >
                          <XIcon className="size-3" />
                        </button>
                      </Badge>
                    ))}
                  </div>
                )}
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div className="flex flex-col gap-1.5">
                  <Label>
                    限速 <span className="font-mono">{rate}</span> 请求/秒
                  </Label>
                  <Slider
                    value={[rate]}
                    min={1}
                    max={150}
                    step={1}
                    onValueChange={(v) => setRate(v[0] ?? 50)}
                  />
                  <span className="text-muted-foreground text-[11px]">
                    对公网目标建议 20–50；本地/内网可以高一些，上限 150。
                  </span>
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="nuclei-timeout">整体超时（秒）</Label>
                  <Input
                    id="nuclei-timeout"
                    type="number"
                    min={5}
                    max={600}
                    value={timeout}
                    onChange={(e) => setTimeoutSec(Math.max(5, Math.min(600, Number(e.target.value) || 180)))}
                  />
                  <span className="text-muted-foreground text-[11px]">
                    到点会中断并保留已经拿到的命中。
                  </span>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Button onClick={() => void runScan()} disabled={running}>
                  {running ? (
                    <Loader2Icon className="size-4 animate-spin" />
                  ) : (
                    <RadarIcon className="size-4" />
                  )}
                  {running ? "扫描中…" : "开始扫描"}
                </Button>
                {tags.length > 0 && (
                  <span className="text-muted-foreground text-xs">tags: {tags.join(",")}</span>
                )}
                {severities.length > 0 && (
                  <span className="text-muted-foreground text-xs">severity: {severities.join(",")}</span>
                )}
                {(hits.length > 0 || summary) && !running && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setHits([]);
                      setSummary(null);
                    }}
                  >
                    清空结果
                  </Button>
                )}
              </div>

              {running && (
                <div className="text-muted-foreground flex items-center gap-2 text-xs">
                  <Loader2Icon className="size-3.5 animate-spin" />
                  扫描进行中：已命中 {hits.length} 条（命中会实时出现在下面）
                </div>
              )}
            </CardContent>
          </Card>

          {/* 汇总 */}
          {summary && (
            <Card>
              <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-1 pt-4 text-sm">
                <span>
                  命中 <span className="font-semibold tabular-nums">{summary.matched}</span>
                </span>
                <span>
                  请求 <span className="font-semibold tabular-nums">{summary.requests || "—"}</span>
                </span>
                <span>
                  耗时{" "}
                  <span className="font-semibold tabular-nums">
                    {(summary.elapsed_ms / 1000).toFixed(1)}s
                  </span>
                </span>
                <span className="text-muted-foreground text-xs">{summary.strategy}</span>
                {summary.timed_out && (
                  <Badge variant="outline" className="text-amber-600">
                    到超时被中断，结果可能不完整
                  </Badge>
                )}
              </CardContent>
            </Card>
          )}

          {/* 命中 */}
          {hits.length === 0 ? (
            <Card>
              <CardContent className="text-muted-foreground py-10 text-center text-sm">
                {running ? "等待命中…" : "还没有命中。选好模板或标签后点「开始扫描」。"}
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {hits.map((h, i) => (
                <Card key={`${h.template_id}-${h.matched_at}-${i}`}>
                  <CardContent className="space-y-2 pt-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge domain="severity" value={h.severity} dot />
                      <span className="font-mono text-sm font-medium">{h.template_id}</span>
                      <span className="text-muted-foreground truncate text-xs">{h.name}</span>
                      {h.matcher_name && (
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {h.matcher_name}
                        </Badge>
                      )}
                    </div>
                    <div className="break-all font-mono text-xs">{h.matched_at}</div>
                    {h.extracted_results?.length > 0 && (
                      <div className="text-xs">
                        <span className="text-muted-foreground">提取结果：</span>
                        <span className="font-mono">{h.extracted_results.slice(0, 20).join(" | ")}</span>
                      </div>
                    )}
                    {h.curl_command && (
                      <div className="flex items-start gap-2">
                        <pre className="bg-muted/50 max-h-28 flex-1 overflow-auto rounded-md p-2 font-mono text-[11px] whitespace-pre-wrap">
                          {h.curl_command}
                        </pre>
                        <Button
                          size="sm"
                          variant="outline"
                          className="shrink-0"
                          onClick={() => void copy(h.curl_command, "curl 命令已复制")}
                        >
                          <CopyIcon className="size-3.5" /> 复制
                        </Button>
                      </div>
                    )}
                    {(h.severity === "critical" || h.severity === "high") && (
                      <div className="text-muted-foreground flex items-center gap-1.5 text-xs">
                        <SquareTerminalIcon className="size-3.5" />
                        可能是拿 shell 的点：
                        <Link href="/function/webshell" className="text-primary inline-flex items-center gap-1 hover:underline">
                          去 WebShell 落地马子 <ArrowRightIcon className="size-3" />
                        </Link>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ---------------- 自动匹配（指纹 → POC → 验证） ---------------- */}
        <TabsContent value="auto" className="space-y-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">按指纹自动匹配并验证 POC</CardTitle>
              <CardDescription>
                输一个 URL → 自动识别技术栈 → 自动挑候选 POC → 自动实弹验证。只打你被授权测试的目标。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
                <div className="flex-1 space-y-1.5">
                  <Label htmlFor="nuclei-auto-target">目标 URL</Label>
                  <Input
                    id="nuclei-auto-target"
                    value={autoTarget}
                    onChange={(e) => setAutoTarget(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void runAuto();
                    }}
                    placeholder="http://127.0.0.1:18082 或 https://10.0.0.5:8443"
                    disabled={autoRunning}
                  />
                  {autoAssetIds && (
                    <div className="text-muted-foreground flex flex-wrap items-center gap-1 text-[11px]">
                      <FingerprintIcon className="size-3" />
                      已从资产页带入 {splitList(autoAssetIds).length} 个资产
                      <span className="font-mono opacity-70">asset_ids={autoAssetIds}</span>
                    </div>
                  )}
                </div>
                <Button
                  onClick={() => void runAuto()}
                  disabled={autoRunning}
                  className="sm:w-44"
                  title="自动完成：识别指纹 → 匹配候选 POC → 实弹验证"
                >
                  {autoRunning ? (
                    <Loader2Icon className="size-4 animate-spin" />
                  ) : (
                    <FingerprintIcon className="size-4" />
                  )}
                  {autoRunning ? autoStageLabel(autoStage) : "一键识别并验证"}
                </Button>
              </div>

              {/* 高级选项：手动指定指纹 / 模板、限速与上限 */}
              <Collapsible open={autoAdvanced} onOpenChange={setAutoAdvanced}>
                <CollapsibleTrigger className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-xs">
                  <ChevronDownIcon
                    className={cn("size-3.5 transition-transform", autoAdvanced && "rotate-180")}
                  />
                  高级选项（手动指定指纹 / 模板、限速、候选上限）
                </CollapsibleTrigger>
                <CollapsibleContent className="space-y-3 pt-3">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label htmlFor="nuclei-auto-fp">手动指纹（逗号分隔，可选）</Label>
                      <Input
                        id="nuclei-auto-fp"
                        value={autoFpInput}
                        onChange={(e) => setAutoFpInput(e.target.value)}
                        placeholder="Apache Tomcat 9.0, Java, nginx"
                      />
                      <span className="text-muted-foreground text-[11px]">
                        留空则自动探测；填了就以这里为准（不再探测）。
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="nuclei-auto-tpl">手动模板 id（逗号分隔，可选）</Label>
                      <Input
                        id="nuclei-auto-tpl"
                        value={autoTplInput}
                        onChange={(e) => setAutoTplInput(e.target.value)}
                        placeholder="CVE-2021-44228, CVE-2017-12615"
                      />
                      <span className="text-muted-foreground text-[11px]">
                        填了就跳过指纹匹配，直接跑这些模板。
                      </span>
                    </div>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-3">
                    <div className="space-y-1.5">
                      <Label>
                        候选上限 <span className="font-mono">{autoLimit}</span>
                      </Label>
                      <Slider
                        value={[autoLimit]}
                        min={1}
                        max={200}
                        step={1}
                        onValueChange={(v) => setAutoLimit(v[0] ?? 50)}
                      />
                      <span className="text-muted-foreground text-[11px]">默认 50，上限 200。</span>
                    </div>
                    <div className="space-y-1.5">
                      <Label>
                        限速 <span className="font-mono">{autoRate}</span> 请求/秒
                      </Label>
                      <Slider
                        value={[autoRate]}
                        min={1}
                        max={150}
                        step={1}
                        onValueChange={(v) => setAutoRate(v[0] ?? 50)}
                      />
                      <span className="text-muted-foreground text-[11px]">
                        默认 50，上限 150；对公网目标别调高。
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="nuclei-auto-timeout">整体超时（秒）</Label>
                      <Input
                        id="nuclei-auto-timeout"
                        type="number"
                        min={5}
                        max={600}
                        value={autoTimeout}
                        onChange={(e) =>
                          setAutoTimeout(Math.max(5, Math.min(600, Number(e.target.value) || 180)))
                        }
                      />
                      <span className="text-muted-foreground text-[11px]">
                        指纹探测本身要 20 秒左右，别调太小。
                      </span>
                    </div>
                  </div>
                </CollapsibleContent>
              </Collapsible>
            </CardContent>
          </Card>

          {/* ① 识别到的指纹 */}
          {autoStage !== "idle" && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">① 识别到的指纹</CardTitle>
                {autoSource && (
                  <CardDescription>
                    来源：
                    {autoSource === "nuclei-tech"
                      ? "nuclei tech 模板"
                      : autoSource === "http-header"
                        ? "HTTP 响应头 / 标题（粗判）"
                        : autoSource}
                    {autoNote ? ` · ${autoNote}` : ""}
                  </CardDescription>
                )}
              </CardHeader>
              <CardContent className="space-y-2">
                {autoStage === "probe" && (
                  <div className="text-muted-foreground flex items-center gap-2 text-sm">
                    <Loader2Icon className="size-4 animate-spin" /> 正在用 tech 模板识别技术栈…
                  </div>
                )}
                {autoFingerprints.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {autoFingerprints.map((f, i) => (
                      <Badge key={`${f.tech}-${i}`} variant="secondary" className="gap-1">
                        {f.tech}
                        {f.version && <span className="opacity-70">{f.version}</span>}
                      </Badge>
                    ))}
                  </div>
                )}
                {autoFingerprints.length === 0 && autoStage !== "probe" && (
                  <div className="text-muted-foreground text-sm">
                    未识别到指纹：nuclei 的 tech 模板没命中，HTTP 响应头 / 标题也没有可用线索。
                    可在「高级选项」里手动指定指纹后再匹配。
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* ② 匹配到的候选 POC */}
          {(autoStage === "match" || autoStage === "run" || autoStage === "done") && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">② 匹配到的候选 POC</CardTitle>
                <CardDescription>
                  {autoStage === "match"
                    ? "正在按指纹反查候选 POC…"
                    : `共匹配 ${autoCandidateTotal} 个（按拿 shell 概率排序），下面显示前 ${autoCandidates.length} 个`}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {autoCandidates.length > 0 ? (
                  <div className="rounded-lg border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="min-w-[16rem]">模板</TableHead>
                          <TableHead className="w-24">严重性</TableHead>
                          <TableHead className="min-w-[9rem]">命中指纹词</TableHead>
                          <TableHead className="w-28">拿 shell 概率</TableHead>
                          <TableHead className="min-w-[18rem]">建议</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {autoCandidates.map((c) => (
                          <TableRow key={c.id}>
                            <TableCell>
                              <div className="font-medium">{c.name || "(无名称)"}</div>
                              <div className="text-muted-foreground font-mono text-xs">{c.id}</div>
                            </TableCell>
                            <TableCell>
                              <StatusBadge domain="severity" value={c.severity} dot />
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-wrap gap-1">
                                {c.matched.map((m) => (
                                  <Badge
                                    key={m}
                                    variant="outline"
                                    className="font-mono text-[10px] font-normal"
                                  >
                                    {m}
                                  </Badge>
                                ))}
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-col items-start gap-1">
                                {tierBadge(c)}
                                <span className="text-muted-foreground text-[10px]">
                                  {c.tier_label}
                                </span>
                                {c.landable && (
                                  <span className="text-red-600 dark:text-red-400 text-[10px] font-medium">
                                    可用于落马
                                  </span>
                                )}
                              </div>
                            </TableCell>
                            <TableCell className="text-muted-foreground text-xs">{c.advice}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : autoStage === "match" ? (
                  <div className="text-muted-foreground flex items-center justify-center gap-2 py-8 text-sm">
                    <Loader2Icon className="size-4 animate-spin" /> 匹配中…
                  </div>
                ) : (
                  <div className="py-8 text-center text-sm">
                    <div className="font-medium">未匹配到相关 POC</div>
                    <div className="text-muted-foreground mx-auto mt-1 max-w-xl text-xs">
                      {autoMessage ||
                        "模板库里没有同时满足 severity ∈ {critical, high, medium} 且带 rce / 文件上传 / 反序列化 / 命令注入 / SQLi / 弱配置标签或 CVE 号的模板。可以换更精确的指纹（产品版本号 / CVE 编号）再试。"}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* ③ 验证命中 */}
          {(autoStage === "run" || autoStage === "done") && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">③ 验证命中</CardTitle>
                <CardDescription>
                  {autoStage === "run"
                    ? "实弹验证中，命中会实时出现在下面…"
                    : `共命中 ${autoHits.length} 条`}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {autoSummary && (
                  <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
                    <span>
                      候选{" "}
                      <span className="font-semibold tabular-nums">{autoSummary.candidates}</span>
                    </span>
                    <span>
                      实跑 <span className="font-semibold tabular-nums">{autoSummary.ran}</span>
                    </span>
                    <span>
                      请求{" "}
                      <span className="font-semibold tabular-nums">{autoSummary.requests || "—"}</span>
                    </span>
                    <span>
                      命中{" "}
                      <span className="font-semibold tabular-nums">{autoSummary.matched}</span>
                    </span>
                    <span>
                      耗时{" "}
                      <span className="font-semibold tabular-nums">
                        {(autoSummary.elapsed_ms / 1000).toFixed(1)}s
                      </span>
                    </span>
                    <span className="text-muted-foreground text-xs">{autoSummary.strategy}</span>
                    {autoSummary.timed_out && (
                      <Badge variant="outline" className="text-amber-600">
                        到超时被中断，结果可能不完整
                      </Badge>
                    )}
                  </div>
                )}

                {autoHits.length === 0 ? (
                  <div className="text-muted-foreground py-8 text-center text-sm">
                    {autoStage === "run"
                      ? "等待命中…"
                      : "未命中任何候选模板：指纹匹配到的 POC 在目标上没有复现成功。可提高候选上限或补充更精确的指纹后重试。"}
                  </div>
                ) : (
                  <div className="space-y-2">
                    {autoHits.map((h, i) => (
                      <div
                        key={`${h.template_id}-${h.matched_at}-${i}`}
                        className="rounded-lg border p-3"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <StatusBadge domain="severity" value={h.severity} dot />
                          <span className="font-mono text-sm font-medium">{h.template_id}</span>
                          <span className="text-muted-foreground truncate text-xs">{h.name}</span>
                          {hitLandable(h) && (
                            <Badge
                              variant="outline"
                              className="border-red-500/30 bg-red-500/15 text-red-600 dark:text-red-400"
                            >
                              该命中可用于落马
                            </Badge>
                          )}
                          {h.matcher_name && (
                            <Badge variant="outline" className="font-mono text-[10px]">
                              {h.matcher_name}
                            </Badge>
                          )}
                        </div>
                        <div className="mt-1 break-all font-mono text-xs">{h.matched_at}</div>
                        {h.extracted_results?.length > 0 && (
                          <div className="mt-1 text-xs">
                            <span className="text-muted-foreground">提取结果：</span>
                            <span className="font-mono">
                              {h.extracted_results.slice(0, 20).join(" | ")}
                            </span>
                          </div>
                        )}
                        {h.curl_command && (
                          <div className="mt-2 flex items-start gap-2">
                            <pre className="bg-muted/50 max-h-28 flex-1 overflow-auto rounded-md p-2 font-mono text-[11px] whitespace-pre-wrap">
                              {h.curl_command}
                            </pre>
                            <Button
                              size="sm"
                              variant="outline"
                              className="shrink-0"
                              onClick={() => void copy(h.curl_command, "curl 命令已复制")}
                            >
                              <CopyIcon className="size-3.5" /> 复制
                            </Button>
                          </div>
                        )}
                        {hitLandable(h) && (
                          <div className="text-muted-foreground mt-2 flex items-center gap-1.5 text-xs">
                            <SquareTerminalIcon className="size-3.5" />
                            落地马子：
                            <Link
                              href="/function/webshell"
                              className="text-primary inline-flex items-center gap-1 hover:underline"
                            >
                              去 WebShell 取 payload 落地 <ArrowRightIcon className="size-3" />
                            </Link>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* YAML 详情抽屉 */}
      <Sheet open={detailOpen} onOpenChange={setDetailOpen}>
        <SheetContent className="flex w-full flex-col gap-3 sm:max-w-3xl">
          <SheetHeader>
            <SheetTitle className="font-mono text-sm">{detail?.id ?? "加载中…"}</SheetTitle>
            <SheetDescription>
              {detailLoading ? "正在读取模板…" : (detail?.name ?? "")}
            </SheetDescription>
          </SheetHeader>

          {detailLoading ? (
            <div className="text-muted-foreground flex items-center gap-2 text-sm">
              <Loader2Icon className="size-4 animate-spin" /> 读取中…
            </div>
          ) : detail ? (
            <>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <StatusBadge domain="severity" value={detail.severity} dot />
                <span className="text-muted-foreground">作者：{detail.author || "—"}</span>
                <span className="text-muted-foreground">大小：{detail.size} 字节</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {tagList(detail.tags).map((t) => (
                  <Badge key={t} variant="outline" className="font-mono text-[10px] font-normal">
                    {t}
                  </Badge>
                ))}
              </div>
              {detail.description && (
                <p className="text-muted-foreground max-h-24 overflow-auto text-xs">{detail.description}</p>
              )}
              {detail.reference?.length > 0 && (
                <div className="max-h-20 overflow-auto text-xs">
                  <span className="text-muted-foreground">参考：</span>
                  {detail.reference.slice(0, 8).map((r) => (
                    <div key={r} className="truncate font-mono text-[11px]">
                      {r}
                    </div>
                  ))}
                </div>
              )}
              <div className="flex items-center gap-2">
                <Button size="sm" variant="outline" onClick={() => void copy(detail.yaml, "YAML 已复制")}>
                  <CopyIcon className="size-3.5" /> 复制 YAML
                </Button>
                <Button size="sm" onClick={() => addToScan(detail)}>
                  <CrosshairIcon className="size-3.5" /> 加入打点
                </Button>
              </div>
              <ScrollArea className="min-h-0 flex-1 rounded-md border">
                <pre className="p-3 font-mono text-[11px] leading-relaxed">{detail.yaml}</pre>
              </ScrollArea>
            </>
          ) : (
            <div className="text-muted-foreground text-sm">没有取到模板内容。</div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function NucleiPage() {
  return (
    <React.Suspense fallback={null}>
      <NucleiInner />
    </React.Suspense>
  );
}
