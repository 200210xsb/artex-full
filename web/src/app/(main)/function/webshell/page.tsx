"use client";

// WebShell 页面：把 MCP 的 shell_add/list/exec/upload/download/payload_* 变成可视化操作。
// 会话库和 MCP 共用 webshells.json，但这里直接打后端的 /api/webshell/*（不走 MCP
// 子进程），所以点一下就有响应。
//
// 布局（桌面）：左 280px 会话栏 + 右侧上下 6:4（命令控制台 / 文件·Payload Tab）；
// 移动端整体堆叠。终端交互：Enter 执行、↑/↓ 翻历史、Ctrl+L 清屏，手动上滑时不抢
// 滚动位置。

import * as React from "react";

import {
  CheckCircle2Icon,
  ChevronRightIcon,
  CopyIcon,
  DownloadIcon,
  FileIcon,
  FolderIcon,
  FolderUpIcon,
  Loader2Icon,
  PlusIcon,
  RefreshCwIcon,
  SendIcon,
  TerminalIcon,
  Trash2Icon,
  UploadIcon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { WebshellDownloadResult, WebshellPayloadDetail, WebshellPayloadEntry, WebshellSession } from "@/lib/types";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// 文案 / 常量
// ---------------------------------------------------------------------------

/** 统一的错误文案提取：后端返回的中文错误直接展示。 */
const errMsg = (err: unknown, fallback: string) => (err instanceof Error ? err.message : fallback);

const TYPE_LABEL: Record<string, string> = {
  php: "PHP eval",
  php_raw: "PHP 代码",
  jsp: "JSP 命令",
  aspx: "ASPX 命令",
};

const TYPE_HINT: Record<string, string> = {
  php: "eval 一句话马：命令 base64 后由 system() 执行，输出用标记回传",
  php_raw: "PHP 代码执行马：输入的内容当 PHP 代码跑",
  jsp: "命令型马：Runtime.getRuntime().exec() 执行参数",
  aspx: "命令型马：Process.Start(cmd.exe /c …) 执行参数",
};

/** 类型徽章配色：php 绿、php_raw 青、jsp 琥珀、aspx 紫。 */
const TYPE_BADGE: Record<string, string> = {
  php: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  php_raw: "border-teal-500/30 bg-teal-500/10 text-teal-600 dark:text-teal-400",
  jsp: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  aspx: "border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400",
};

/** 终端快捷命令胶囊。 */
const QUICK = ["id", "whoami", "uname -a", "pwd", "ls -la"];

// ---------------------------------------------------------------------------
// 纯函数
// ---------------------------------------------------------------------------

/** POSIX shell 单引号转义（和后端 webshellShellQuote 一致）。 */
function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** 列出目录：PHP/JSP 走远端 shell 的 ls，aspx 走 Windows 的 dir。 */
function listCommand(type: string, path: string): string {
  if (type === "aspx") return `dir "${path.replace(/"/g, '""')}"`;
  return `ls -la ${shellQuote(path)}`;
}

/** 远端路径拼接（保留分隔符风格）。 */
function joinRemote(dir: string, name: string): string {
  if (dir.endsWith("/") || dir.endsWith("\\")) return `${dir}${name}`;
  if (dir === "/") return `/${name}`;
  const win = /^[A-Za-z]:/.test(dir);
  return `${dir}${win ? "\\" : "/"}${name}`;
}

/** 上一级目录；根目录返回自身。 */
function parentPath(p: string): string {
  const clean = p.replace(/[\\/]+$/, "");
  if (!clean || clean === "/") return "/";
  if (/^[A-Za-z]:$/.test(clean)) return clean;
  const i = Math.max(clean.lastIndexOf("/"), clean.lastIndexOf("\\"));
  if (i < 0) return "/";
  const parent = clean.slice(0, i);
  if (parent === "" || /^[A-Za-z]:$/.test(parent)) return `${parent}/`;
  return parent;
}

/** 面包屑：/var/www → [{name:"var"},{name:"www"}]，各自带绝对路径。 */
function crumbsOf(p: string): Array<{ name: string; path: string }> {
  const clean = p.replace(/\\/g, "/");
  const parts = clean.split("/").filter(Boolean);
  const out: Array<{ name: string; path: string }> = [];
  parts.forEach((name, i) => {
    out.push({ name, path: `/${parts.slice(0, i + 1).join("/")}` });
  });
  return out;
}

/** 远端文件条目（由 ls -la 解析）。 */
interface RemoteFile {
  name: string;
  size: number | null;
  perm: string;
  mtime: string;
  dir: boolean;
  link?: string;
}

/** 解析 `ls -la` 输出；解析不出来（比如 Windows 的 dir）返回空数组，调用方回退成原文。 */
function parseLs(raw: string): RemoteFile[] {
  const rows: RemoteFile[] = [];
  const re = /^([dlbcps-][rwxStTs-]{9})[+@.]?\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\w{3}\s+\d{1,2}\s+[\d:]{4,5})\s+(.+)$/;
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(re);
    if (!m) continue;
    let name = m[4].trim();
    if (name === "." || name === "..") continue;
    const dir = m[1].startsWith("d");
    let link: string | undefined;
    const arrow = name.indexOf(" -> ");
    if (arrow >= 0) {
      link = name.slice(arrow + 4);
      name = name.slice(0, arrow);
    }
    rows.push({
      name,
      size: dir ? null : Number(m[2]),
      perm: m[1],
      mtime: m[3].replace(/\s+/g, " "),
      dir,
      link,
    });
  }
  return rows.sort((a, b) => {
    if (a.dir !== b.dir) return a.dir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

/** 人类可读的大小。 */
function fmtSize(n: number | null): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/** Uint8Array → base64（分块，避免大文件把调用栈打爆）。 */
function bytesToB64(bytes: Uint8Array): string {
  const chunk = 0x8000;
  let bin = "";
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

/** base64 → 二进制 Blob（下载用）。 */
function b64ToBlob(b64: string, type = "application/octet-stream"): Blob {
  const bin = atob(b64.replace(/\s+/g, ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type });
}

/** 远端路径 → 文件名。 */
function baseName(p: string): string {
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] || "download.bin";
}

// ---------------------------------------------------------------------------
// 小部件
// ---------------------------------------------------------------------------

interface TermLine {
  id: number;
  kind: "cmd" | "out" | "err" | "note";
  text: string;
  meta?: string;
}

const TERM_CLASS: Record<TermLine["kind"], string> = {
  cmd: "text-zinc-50",
  out: "text-zinc-300",
  err: "text-red-400",
  note: "text-cyan-400",
};

/** 终端一行：命令白色带绿色 $、stdout 灰白、stderr 红、系统提示青。 */
function TermRow({ line }: { line: TermLine }) {
  if (line.kind === "cmd") {
    return (
      <div className="mb-1.5 break-all">
        <span className="select-none text-emerald-400">$ </span>
        <span className="whitespace-pre-wrap font-medium text-zinc-50">{line.text}</span>
      </div>
    );
  }
  return (
    <div className={cn("mb-1.5 whitespace-pre-wrap break-all", TERM_CLASS[line.kind])}>
      {line.text}
      {line.meta ? <div className="mt-0.5 text-[10px] text-zinc-500">{line.meta}</div> : null}
    </div>
  );
}

/** 类型徽章。 */
function TypeBadge({ type, className }: { type: string; className?: string }) {
  return (
    <Badge variant="outline" className={cn("h-5 px-1.5 font-mono text-[10px]", TYPE_BADGE[type] ?? "", className)}>
      {type}
    </Badge>
  );
}

/** 连接状态徽标。 */
function ConnBadge({ state, compact }: { state: "idle" | "unknown" | "ok" | "error"; compact?: boolean }) {
  if (state === "ok") {
    return (
      <span className="inline-flex items-center gap-1.5 text-emerald-500 text-xs">
        <CheckCircle2Icon className={compact ? "size-3.5" : "size-4"} />
        已连接
      </span>
    );
  }
  if (state === "error") {
    return (
      <span className="inline-flex items-center gap-1.5 text-red-500 text-xs">
        <XCircleIcon className={compact ? "size-3.5" : "size-4"} />
        连接失败
      </span>
    );
  }
  if (state === "unknown") {
    return <span className="text-amber-500 text-xs">待验证</span>;
  }
  return <span className="text-muted-foreground text-xs">未连接</span>;
}

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <Card size="sm" className="gap-1 py-3">
      <CardContent className="flex min-w-0 flex-col gap-1">
        <div className="text-muted-foreground text-xs">{label}</div>
        <div className="truncate font-heading font-semibold text-lg">{value}</div>
        {hint ? <div className="truncate text-muted-foreground text-xs">{hint}</div> : null}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// 页面
// ---------------------------------------------------------------------------

export default function WebshellPage() {
  const [sessions, setSessions] = React.useState<WebshellSession[]>([]);
  const [storePath, setStorePath] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [selected, setSelected] = React.useState("");

  // 每个会话各留一份终端历史（只在页面内，刷新即清空）。
  const [history, setHistory] = React.useState<Record<string, TermLine[]>>({});
  const seq = React.useRef(0);
  const [cmd, setCmd] = React.useState("");
  const [running, setRunning] = React.useState(false);
  const [conn, setConn] = React.useState<"idle" | "unknown" | "ok" | "error">("idle");
  const [connMsg, setConnMsg] = React.useState("");
  const [stick, setStick] = React.useState(true);
  const [cmdHistory, setCmdHistory] = React.useState<string[]>([]);
  const [histIdx, setHistIdx] = React.useState(-1);

  // 新增会话
  const [addOpen, setAddOpen] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [form, setForm] = React.useState({
    name: "",
    url: "",
    type: "php",
    password: "pass",
    method: "POST",
    header: "",
    note: "",
    remote_path: "",
    proxy: "",
    user_agent: "",
  });

  // 删除确认（一条或多条）
  const [pendingDelete, setPendingDelete] = React.useState<string[] | null>(null);
  // 删会话时要不要连远端一起清。默认不勾：删不删痕迹由人自己决定
  const [deleteRemote, setDeleteRemote] = React.useState(false);

  // 多选：勾选后可批量改 / 批量删
  const [checked, setChecked] = React.useState<string[]>([]);
  const [bulkOpen, setBulkOpen] = React.useState(false);
  const [bulkBusy, setBulkBusy] = React.useState(false);
  // 批量改只动这四个字段：留空 = 保持原值。参数名/头/URL 这些页面拿不到（打码），
  // 后端批量接口也不会碰它们，避免把 agent 落的马改坏。
  const [bulkForm, setBulkForm] = React.useState({ note: "", remote_path: "", proxy: "", user_agent: "" });

  // 文件 Tab
  const [remotePath, setRemotePath] = React.useState("/");
  const [pathInput, setPathInput] = React.useState("/");
  const [fileBusy, setFileBusy] = React.useState<"" | "list" | "download" | "upload">("");
  const [files, setFiles] = React.useState<RemoteFile[]>([]);
  const [rawListing, setRawListing] = React.useState("");
  const [download, setDownload] = React.useState<WebshellDownloadResult | null>(null);
  const [uploadPath, setUploadPath] = React.useState("/tmp/");
  const [uploadB64, setUploadB64] = React.useState("");
  const [uploadName, setUploadName] = React.useState("");

  // Payload Tab
  const [payloads, setPayloads] = React.useState<WebshellPayloadEntry[]>([]);
  const [payloadDir, setPayloadDir] = React.useState("");
  const [payloadBusy, setPayloadBusy] = React.useState(false);
  const [payloadType, setPayloadType] = React.useState("all");
  const [payloadOpen, setPayloadOpen] = React.useState(false);
  const [payloadDetail, setPayloadDetail] = React.useState<WebshellPayloadDetail | null>(null);
  const [payloadLoading, setPayloadLoading] = React.useState(false);

  const current = sessions.find((s) => s.name === selected) ?? null;
  const lines = selected ? (history[selected] ?? []) : [];
  const termRef = React.useRef<HTMLDivElement>(null);
  const inputRef = React.useRef<HTMLInputElement>(null);
  const switched = React.useRef("");

  // ---- 数据加载 ----
  const loadSessions = React.useCallback(async (keepSelection = true) => {
    setLoading(true);
    try {
      const r = await api.webshellSessions();
      const list = r.sessions ?? [];
      setSessions(list);
      setStorePath(r.store ?? "");
      setSelected((prev) => {
        if (keepSelection && prev && list.some((s) => s.name === prev)) return prev;
        return list[0]?.name ?? "";
      });
    } catch (err) {
      toast.error(errMsg(err, "加载会话失败"));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadPayloads = React.useCallback(async () => {
    setPayloadBusy(true);
    try {
      const r = await api.webshellPayloads();
      setPayloads(r.entries ?? []);
      setPayloadDir(r.dir ?? "");
    } catch (err) {
      toast.error(errMsg(err, "加载 payload 库失败"));
      setPayloads([]);
    } finally {
      setPayloadBusy(false);
    }
  }, []);

  React.useEffect(() => {
    void loadSessions();
    void loadPayloads();
  }, [loadSessions, loadPayloads]);

  // ---- 终端行 ----
  const push = React.useCallback((name: string, line: Omit<TermLine, "id">) => {
    seq.current += 1;
    const item = { ...line, id: seq.current };
    setHistory((h) => ({ ...h, [name]: [...(h[name] ?? []), item] }));
  }, []);

  // 切换会话：连接状态复位成「待验证」，并在终端里留一条系统提示。
  React.useEffect(() => {
    if (!selected) {
      setConn("idle");
      setConnMsg("");
      switched.current = "";
      return;
    }
    if (switched.current === selected) return;
    switched.current = selected;
    setConn("unknown");
    setConnMsg("待验证");
    const s = sessions.find((x) => x.name === selected);
    push(selected, {
      kind: "note",
      text: s
        ? `已切换到会话「${selected}」 · ${TYPE_LABEL[s.type] ?? s.type} · ${s.url}`
        : `已切换到会话「${selected}」`,
    });
  }, [selected, sessions, push]);

  // 跟随最新输出；用户手动上滑后不再抢滚动位置。
  // biome-ignore lint/correctness/useExhaustiveDependencies: 输出行数/切换会话/回到底部时才需要重算。
  React.useEffect(() => {
    const el = termRef.current;
    if (el && stick) el.scrollTop = el.scrollHeight;
  }, [selected, lines.length, stick, running]);

  function onTermScroll() {
    const el = termRef.current;
    if (!el) return;
    setStick(el.scrollHeight - el.scrollTop - el.clientHeight < 40);
  }

  // ---- 执行命令 ----
  async function run(raw?: string) {
    const text = (raw ?? cmd).trim();
    if (!selected) {
      toast.error("先添加一个会话");
      return;
    }
    if (!text || running) return;
    const target = selected;
    push(target, { kind: "cmd", text });
    setCmdHistory((h) => [...h.filter((x) => x !== text), text].slice(-100));
    setHistIdx(-1);
    setCmd("");
    setStick(true);
    setRunning(true);
    try {
      const r = await api.webshellExec(target, text);
      push(target, {
        kind: r.output ? "out" : "note",
        text: r.output || "（命令已执行，远端无输出）",
        meta: `${r.mode} · ${r.elapsed_ms}ms${r.truncated ? " · 输出已截断" : ""}`,
      });
      setConn("ok");
      setConnMsg(`${r.mode} · ${r.elapsed_ms}ms`);
    } catch (err) {
      const msg = errMsg(err, "执行失败");
      push(target, { kind: "err", text: msg });
      setConn("error");
      setConnMsg(msg);
      toast.error(msg);
    } finally {
      setRunning(false);
      inputRef.current?.focus();
    }
  }

  /** 控制台键盘：Enter 执行、↑/↓ 翻历史、Ctrl+L 清屏。 */
  function onConsoleKeyDown(e: React.KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "l") {
      e.preventDefault();
      clearScreen();
      return;
    }
    if (e.key === "ArrowUp") {
      if (cmdHistory.length === 0) return;
      e.preventDefault();
      const next = Math.min(histIdx + 1, cmdHistory.length - 1);
      setHistIdx(next);
      setCmd(cmdHistory[cmdHistory.length - 1 - next]);
      return;
    }
    if (e.key === "ArrowDown") {
      if (histIdx < 0) return;
      e.preventDefault();
      const next = histIdx - 1;
      setHistIdx(next);
      setCmd(next < 0 ? "" : cmdHistory[cmdHistory.length - 1 - next]);
    }
  }

  function clearScreen() {
    if (!selected) return;
    setHistory((h) => {
      const next = { ...h };
      delete next[selected];
      return next;
    });
    setStick(true);
  }

  // ---- 会话增删 ----
  function openAdd() {
    setForm({ name: "", url: "", type: "php", password: "pass", method: "POST", header: "", note: "", remote_path: "", proxy: "", user_agent: "" });
    setAddOpen(true);
  }

  async function save() {
    if (!form.name.trim() || !form.url.trim()) {
      toast.error("会话名与 URL 都是必填的");
      return;
    }
    setSaving(true);
    try {
      const r = await api.webshellSaveSession({
        name: form.name.trim(),
        url: form.url.trim(),
        type: form.type,
        password: form.password.trim() || "pass",
        method: form.method,
        header: form.header.trim(),
        note: form.note.trim(),
        remote_path: form.remote_path.trim(),
        proxy: form.proxy.trim(),
        user_agent: form.user_agent.trim(),
      });
      toast.success(r.overwritten ? `已覆盖会话「${r.session.name}」` : `已添加会话「${r.session.name}」`);
      setAddOpen(false);
      switched.current = "";
      await loadSessions();
      setSelected(r.session.name);
    } catch (err) {
      toast.error(errMsg(err, "保存会话失败"));
    } finally {
      setSaving(false);
    }
  }

  async function doDelete() {
    const names = pendingDelete ?? [];
    if (names.length === 0) return;
    setPendingDelete(null);
    const remote = deleteRemote;
    const failed: string[] = [];
    let purged = 0;
    for (const name of names) {
      try {
        const r = await api.webshellDeleteSession(name, { remote });
        if (remote && r.purge?.self_gone) purged += 1;
      } catch (err) {
        // 远端删不掉时后端保留登记（409），这里记下来最后一起报
        failed.push(`${name}：${errMsg(err, "删除失败")}`);
      }
    }
    setHistory((h) => {
      const next = { ...h };
      for (const name of names) delete next[name];
      return next;
    });
    setChecked((c) => c.filter((n) => !names.includes(n)));
    await loadSessions(false);
    if (failed.length > 0) {
      toast.error(`已删 ${names.length - failed.length} 条，${failed.length} 条没删掉（登记保留）：${failed.join("；")}`);
      return;
    }
    if (remote) {
      toast.success(`已删除 ${names.length} 条会话，其中 ${purged} 条远端已清理干净`);
      return;
    }
    toast.success(`已删除 ${names.length} 条会话（远端文件保留）`);
  }

  // 待删会话（用于在确认框里说清楚会删什么）
  const pendingSessions = React.useMemo(
    () => sessions.filter((x) => (pendingDelete ?? []).includes(x.name)),
    [sessions, pendingDelete],
  );

  // ---- 批量改 ----
  function openBulkEdit() {
    setBulkForm({ note: "", remote_path: "", proxy: "", user_agent: "" });
    setBulkOpen(true);
  }

  async function bulkSave() {
    const names = checked.slice();
    if (names.length === 0) return;
    setBulkBusy(true);
    try {
      const r = await api.webshellBulkUpdateSessions(names, {
        note: bulkForm.note.trim(),
        remote_path: bulkForm.remote_path.trim(),
        proxy: bulkForm.proxy.trim(),
        user_agent: bulkForm.user_agent.trim(),
      });
      const updated = r.updated?.length ?? 0;
      const missing = r.missing ?? [];
      setBulkOpen(false);
      await loadSessions(false);
      if (missing.length > 0) {
        toast.message(`已改 ${updated} 条，${missing.length} 条不在会话表里：${missing.join("、")}`);
        return;
      }
      toast.success(`已改 ${updated} 条会话`);
    } catch (err) {
      toast.error(errMsg(err, "批量修改失败"));
    } finally {
      setBulkBusy(false);
    }
  }

  // ---- 文件 ----
  async function listRemote(path = remotePath) {
    if (!current) {
      toast.error("先添加一个会话");
      return;
    }
    setFileBusy("list");
    setDownload(null);
    try {
      const r = await api.webshellExec(current.name, listCommand(current.type, path || "/"));
      const parsed = current.type === "aspx" ? [] : parseLs(r.output);
      setFiles(parsed);
      setRawListing(r.output || "");
      setRemotePath(path || "/");
      setPathInput(path || "/");
      if (parsed.length === 0) {
        toast.message("目录内容无法按列解析，已显示原文");
      } else {
        toast.success(`已列出 ${path || "/"}（${parsed.length} 项）`);
      }
    } catch (err) {
      const msg = errMsg(err, "列出目录失败");
      setFiles([]);
      setRawListing(msg);
      toast.error(msg);
    } finally {
      setFileBusy("");
    }
  }

  async function downloadFile(path: string) {
    if (!current) {
      toast.error("先添加一个会话");
      return;
    }
    setFileBusy("download");
    setDownload(null);
    try {
      const r = await api.webshellDownload({ name: current.name, remote_path: path });
      setDownload(r);
      toast.success(`已取回 ${r.returned} 字节${r.truncated ? `（远端 ${r.size} 字节，已截断）` : ""} · ${r.method}`);
    } catch (err) {
      toast.error(errMsg(err, "下载失败"));
    } finally {
      setFileBusy("");
    }
  }

  function saveDownloaded() {
    if (!download) return;
    const blob =
      download.mode === "text"
        ? new Blob([download.body], { type: "text/plain;charset=utf-8" })
        : b64ToBlob(download.body);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = baseName(download.remote_path);
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast.success(`已保存 ${a.download}`);
  }

  async function pickUploadFile(file: File | null) {
    setUploadB64("");
    setUploadName("");
    if (!file) return;
    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      setUploadB64(bytesToB64(buf));
      setUploadName(file.name);
      if (!uploadPath.trim() || uploadPath.endsWith("/")) {
        setUploadPath(`${uploadPath.trim() || "/tmp/"}${file.name}`);
      }
      toast.success(`已读取 ${file.name}（${buf.length} 字节）`);
    } catch (err) {
      toast.error(errMsg(err, "读取文件失败"));
    }
  }

  async function uploadRemote() {
    if (!current) {
      toast.error("先添加一个会话");
      return;
    }
    if (!uploadB64) {
      toast.error("先选一个本地文件");
      return;
    }
    if (!uploadPath.trim()) {
      toast.error("先填远端目标路径");
      return;
    }
    setFileBusy("upload");
    try {
      const r = await api.webshellUpload({
        name: current.name,
        remote_path: uploadPath.trim(),
        b64: uploadB64,
      });
      toast.success(`已上传 ${r.bytes} 字节到 ${r.remote_path}（${r.parts} 块 · ${r.method}）`);
    } catch (err) {
      toast.error(errMsg(err, "上传失败"));
    } finally {
      setFileBusy("");
    }
  }

  // ---- Payload ----
  async function openPayload(entry: WebshellPayloadEntry) {
    setPayloadOpen(true);
    setPayloadLoading(true);
    setPayloadDetail(null);
    try {
      const d = await api.webshellPayload(entry.type, entry.file);
      setPayloadDetail(d);
    } catch (err) {
      toast.error(errMsg(err, "读取 payload 全文失败"));
    } finally {
      setPayloadLoading(false);
    }
  }

  async function copyText(text: string, label = "内容") {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`已复制${label}`);
    } catch {
      toast.error("复制失败，请手动选中后复制");
    }
  }

  const filteredPayloads = payloadType === "all" ? payloads : payloads.filter((p) => p.type === payloadType);
  const payloadTypes = Array.from(new Set(payloads.map((p) => p.type)));
  const crumbs = crumbsOf(remotePath);

  return (
    <div className="flex flex-col gap-4 p-4">
      {/* 顶部：标题 + 状态 */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="font-heading font-semibold text-xl">WebShell</h1>
          <p className="text-muted-foreground text-sm">
            会话登记与命令控制台 · 与 MCP 共用 <span className="font-mono text-xs">webshells.json</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void loadSessions()} disabled={loading}>
            {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
            刷新
          </Button>
          <Button size="sm" onClick={openAdd}>
            <PlusIcon className="size-4" />
            添加会话
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Stat label="会话数" value={sessions.length} hint={storePath || "webshells.json"} />
        <Stat
          label="当前选中"
          value={current ? current.name : "未选择"}
          hint={current ? `${TYPE_LABEL[current.type] ?? current.type} · ${current.method}` : "左侧点一个会话"}
        />
        <Stat
          label="连接状态"
          value={<ConnBadge state={conn} />}
          hint={connMsg || (current ? "执行一条命令即可验证" : "先添加一个会话")}
        />
      </div>

      {/* 主体：左会话栏 + 右侧上下 6:4 */}
      <div className="grid items-start gap-4 lg:grid-cols-[280px_minmax(0,1fr)] lg:gap-6">
        {/* ---- 左：会话列表 ---- */}
        <Card className="flex min-w-0 flex-col gap-3 py-4 lg:sticky lg:top-4">
          <CardHeader className="px-4">
            <CardTitle className="flex items-center justify-between gap-2 text-sm">
              会话列表
              <Badge variant="secondary" className="font-mono text-[10px]">
                {sessions.length}
              </Badge>
            </CardTitle>
            <CardDescription className="text-xs">
              点一下切换会话；左侧勾选后可批量改 / 批量删（删除默认只摘登记，可勾选连远端一起删）。
            </CardDescription>
            {sessions.length > 0 ? (
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <label className="flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
                  <Checkbox
                    checked={checked.length > 0 && checked.length === sessions.length}
                    onCheckedChange={(v) => setChecked(v === true ? sessions.map((s) => s.name) : [])}
                    aria-label="全选会话"
                  />
                  全选
                </label>
                {checked.length > 0 ? (
                  <>
                    <span className="text-xs">已选 {checked.length}</span>
                    <Button size="sm" variant="outline" onClick={openBulkEdit}>
                      批量修改
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setPendingDelete(checked)}>
                      批量删除
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setChecked([])}>
                      清空
                    </Button>
                  </>
                ) : null}
              </div>
            ) : null}
          </CardHeader>
          <CardContent className="min-h-0 px-2">
            {sessions.length === 0 ? (
              <div className="px-2">
                <Empty className="border border-dashed p-4">
                  <EmptyHeader>
                    <EmptyMedia variant="icon">
                      <TerminalIcon />
                    </EmptyMedia>
                    <EmptyTitle>先添加一个会话</EmptyTitle>
                    <EmptyDescription className="text-xs">马子从 Payload 库取，落地后在这里登记。</EmptyDescription>
                  </EmptyHeader>
                  <EmptyContent>
                    <Button size="sm" onClick={openAdd}>
                      <PlusIcon className="size-4" />
                      添加第一个会话
                    </Button>
                  </EmptyContent>
                </Empty>
              </div>
            ) : (
              <ScrollArea className="max-h-[min(52vh,420px)] lg:max-h-[calc(100vh-26rem)]">
                <div className="flex flex-col gap-0.5 pr-2">
                  {sessions.map((s) => {
                    const active = s.name === selected;
                    return (
                      <div
                        key={s.name}
                        className={cn(
                          "group relative flex items-center gap-1 rounded-lg py-1.5 pr-1 pl-3 transition-colors",
                          active ? "bg-accent" : "hover:bg-accent/50",
                        )}
                      >
                        {active ? (
                          <span className="absolute inset-y-1.5 left-0 w-[3px] rounded-full bg-primary" />
                        ) : null}
                        <Checkbox
                          checked={checked.includes(s.name)}
                          onCheckedChange={(v) =>
                            setChecked((c) => (v === true ? [...c, s.name] : c.filter((x) => x !== s.name)))
                          }
                          onClick={(e) => e.stopPropagation()}
                          aria-label={`选择会话 ${s.name}`}
                          className="ml-1 shrink-0"
                        />
                        <button
                          type="button"
                          onClick={() => {
                            setSelected(s.name);
                            inputRef.current?.focus();
                          }}
                          className="flex min-w-0 flex-1 flex-col items-start gap-0.5 text-left"
                        >
                          <span className="flex w-full items-center gap-1.5">
                            <span className="min-w-0 truncate font-medium text-sm">{s.name}</span>
                            <TypeBadge type={s.type} />
                          </span>
                          <span className="w-full truncate font-mono text-[11px] text-muted-foreground" title={s.url}>
                            {s.url}
                          </span>
                          {s.note ? (
                            <span className="w-full truncate text-[11px] text-muted-foreground">{s.note}</span>
                          ) : null}
                          {s.egress ? (
                            <span
                              className={cn(
                                "w-full truncate text-[11px]",
                                s.egress === "直连" ? "text-amber-600" : "text-emerald-600",
                              )}
                              title={s.egress === "直连" ? "目标侧会看到平台 IP" : "目标侧只看到代理 IP"}
                            >
                              出口：{s.egress}
                            </span>
                          ) : null}
                        </button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7 shrink-0 text-muted-foreground opacity-60 transition-opacity hover:opacity-100 focus-visible:opacity-100"
                          title="删除会话登记（默认只删登记，可在确认框里勾选连远端一起删）"
                          onClick={() => setPendingDelete([s.name])}
                        >
                          <Trash2Icon className="size-3.5" />
                        </Button>
                      </div>
                    );
                  })}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* ---- 右：控制台 + Tab 区（桌面 6:4） ---- */}
        <div className="grid min-w-0 gap-4 lg:h-[calc(100vh-17.5rem)] lg:min-h-[520px] lg:grid-rows-[3fr_2fr] lg:gap-6">
          {/* 命令控制台 */}
          <Card className="flex min-h-[360px] min-w-0 flex-col gap-0 overflow-hidden py-0 lg:min-h-0">
            <CardHeader className="shrink-0 gap-1 border-b px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <CardTitle className="flex items-center gap-2 text-sm">
                    <TerminalIcon className="size-4 text-muted-foreground" />
                    命令控制台
                    {current ? (
                      <span className="truncate font-normal text-muted-foreground">· {current.name}</span>
                    ) : null}
                  </CardTitle>
                  <CardDescription className="truncate text-xs">
                    {current ? (TYPE_HINT[current.type] ?? "回车执行") : "先在左侧添加一个会话，才能执行命令"}
                  </CardDescription>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <Button variant="ghost" size="sm" disabled={!selected || lines.length === 0} onClick={clearScreen}>
                    清屏
                    <kbd className="ml-1 rounded border px-1 text-[10px] text-muted-foreground">⌃L</kbd>
                  </Button>
                </div>
              </div>
            </CardHeader>

            {/* 终端 */}
            <div className="relative min-h-0 flex-1">
              {current ? (
                <div className="pointer-events-none absolute top-2 right-3 z-10 flex max-w-[70%] items-center gap-1.5 rounded-full border border-zinc-700/60 bg-zinc-900/80 px-2.5 py-1 backdrop-blur">
                  <ConnBadge state={conn} compact />
                  <span className="text-zinc-600">·</span>
                  <span className="font-mono text-[10px] text-zinc-300">{current.type}</span>
                  <span className="text-zinc-600">·</span>
                  <span className="max-w-[180px] truncate font-mono text-[10px] text-zinc-400">{current.url}</span>
                </div>
              ) : null}
              <div
                ref={termRef}
                onScroll={onTermScroll}
                className="size-full overflow-auto bg-zinc-950 p-4 pr-3 font-mono text-xs leading-relaxed"
              >
                {lines.length === 0 ? (
                  <div className="text-zinc-500">
                    {current
                      ? "输入 id 或点下面的快捷命令开始；↑/↓ 翻历史，Ctrl+L 清屏。"
                      : "先添加一个会话，然后在这里执行命令。"}
                  </div>
                ) : (
                  lines.map((l) => <TermRow key={l.id} line={l} />)
                )}
                {running ? (
                  <div className="flex items-center gap-2 text-cyan-400">
                    <Loader2Icon className="size-3 animate-spin" />
                    执行中…
                  </div>
                ) : null}
              </div>
              {!stick && lines.length > 0 ? (
                <Button
                  size="sm"
                  variant="secondary"
                  className="absolute right-3 bottom-3 h-7 rounded-full px-2.5 text-xs shadow"
                  onClick={() => {
                    const el = termRef.current;
                    if (el) el.scrollTop = el.scrollHeight;
                    setStick(true);
                  }}
                >
                  ↓ 最新输出
                </Button>
              ) : null}
            </div>

            {/* 固定在底部的输入区 */}
            <div className="shrink-0 border-zinc-800 border-t bg-zinc-950 px-3 py-2.5">
              <div className="mb-2 flex flex-wrap gap-1.5">
                {QUICK.map((q) => (
                  <button
                    key={q}
                    type="button"
                    disabled={!selected || running}
                    onClick={() => void run(q)}
                    className="rounded-full border border-zinc-700 px-2 py-0.5 font-mono text-[11px] text-zinc-300 transition-colors hover:border-emerald-500/60 hover:text-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {q}
                  </button>
                ))}
              </div>
              <form
                className="flex items-center gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void run();
                }}
              >
                <span className="select-none font-mono text-emerald-400">$</span>
                <Input
                  ref={inputRef}
                  value={cmd}
                  onChange={(e) => setCmd(e.target.value)}
                  onKeyDown={onConsoleKeyDown}
                  placeholder={selected ? "输入命令后回车，例如 id" : "先添加一个会话"}
                  disabled={!selected || running}
                  autoComplete="off"
                  spellCheck={false}
                  className="h-8 border-zinc-700 bg-zinc-900 font-mono text-xs text-zinc-100 placeholder:text-zinc-600 focus-visible:border-emerald-500/60 focus-visible:ring-emerald-500/20"
                />
                <Button type="submit" size="sm" className="h-8" disabled={!selected || running || !cmd.trim()}>
                  {running ? <Loader2Icon className="size-3.5 animate-spin" /> : <SendIcon className="size-3.5" />}
                  执行
                </Button>
              </form>
            </div>
          </Card>

          {/* Tab 区：文件 / Payload 库 */}
          <Tabs defaultValue="files" className="flex min-h-0 min-w-0 flex-col gap-2">
            <div className="flex shrink-0 items-center justify-between gap-2">
              <TabsList>
                <TabsTrigger value="files">文件</TabsTrigger>
                <TabsTrigger value="payloads">Payload 库</TabsTrigger>
              </TabsList>
              {current ? (
                <span className="truncate font-mono text-xs text-muted-foreground">
                  {current.name} · {TYPE_LABEL[current.type] ?? current.type}
                </span>
              ) : null}
            </div>

            {/* ---- 文件 ---- */}
            <TabsContent value="files" className="min-h-0 flex-1 overflow-auto">
              <Card className="gap-3 py-3">
                <CardContent className="flex flex-col gap-3 px-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      title="返回上级"
                      disabled={!current || remotePath === "/"}
                      onClick={() => void listRemote(parentPath(remotePath))}
                    >
                      <FolderUpIcon className="size-4" />
                      上级
                    </Button>
                    <Input
                      value={pathInput}
                      onChange={(e) => setPathInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          void listRemote(pathInput.trim() || "/");
                        }
                      }}
                      placeholder="/var/www/html 或 C:\inetpub\wwwroot"
                      className="h-8 min-w-[180px] flex-1 font-mono text-xs"
                      disabled={!current}
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => void listRemote(pathInput.trim() || "/")}
                      disabled={!current || fileBusy === "list"}
                    >
                      {fileBusy === "list" ? (
                        <Loader2Icon className="size-4 animate-spin" />
                      ) : (
                        <RefreshCwIcon className="size-4" />
                      )}
                      列出
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => void downloadFile(pathInput.trim() || remotePath)}
                      disabled={!current || fileBusy === "download"}
                    >
                      {fileBusy === "download" ? (
                        <Loader2Icon className="size-4 animate-spin" />
                      ) : (
                        <DownloadIcon className="size-4" />
                      )}
                      下载路径
                    </Button>
                  </div>

                  {crumbs.length > 0 ? (
                    <div className="flex min-w-0 flex-wrap items-center gap-0.5 text-xs">
                      <button
                        type="button"
                        onClick={() => void listRemote("/")}
                        className="shrink-0 rounded px-1 py-0.5 font-mono text-muted-foreground hover:bg-accent hover:text-foreground"
                      >
                        /
                      </button>
                      {crumbs.map((c, i) => (
                        <React.Fragment key={c.path}>
                          <ChevronRightIcon className="size-3 shrink-0 text-muted-foreground" />
                          <button
                            type="button"
                            onClick={() => void listRemote(c.path)}
                            className={cn(
                              "max-w-[160px] shrink-0 truncate rounded px-1 py-0.5 font-mono text-muted-foreground hover:bg-accent hover:text-foreground",
                              i === crumbs.length - 1 && "font-medium text-foreground",
                            )}
                          >
                            {c.name}
                          </button>
                        </React.Fragment>
                      ))}
                    </div>
                  ) : null}

                  {files.length > 0 ? (
                    <div className="overflow-hidden rounded-md border">
                      <Table>
                        <TableHeader>
                          <TableRow className="hover:bg-transparent">
                            <TableHead>名称</TableHead>
                            <TableHead className="w-24 text-right">大小</TableHead>
                            <TableHead className="w-28 font-mono">权限</TableHead>
                            <TableHead className="w-36">修改时间</TableHead>
                            <TableHead className="w-20 text-right">操作</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {files.map((f) => (
                            <TableRow key={f.name}>
                              <TableCell className="max-w-0">
                                <span className="flex min-w-0 items-center gap-2">
                                  {f.dir ? (
                                    <FolderIcon className="size-4 shrink-0 text-amber-500" />
                                  ) : (
                                    <FileIcon className="size-4 shrink-0 text-muted-foreground" />
                                  )}
                                  {f.dir ? (
                                    <button
                                      type="button"
                                      className="truncate font-mono text-xs hover:underline"
                                      title={f.name}
                                      onClick={() => void listRemote(joinRemote(remotePath, f.name))}
                                    >
                                      {f.name}
                                    </button>
                                  ) : (
                                    <span className="truncate font-mono text-xs" title={f.link ?? f.name}>
                                      {f.name}
                                      {f.link ? <span className="text-muted-foreground"> → {f.link}</span> : null}
                                    </span>
                                  )}
                                </span>
                              </TableCell>
                              <TableCell className="text-right font-mono text-xs text-muted-foreground">
                                {fmtSize(f.size)}
                              </TableCell>
                              <TableCell className="font-mono text-xs text-muted-foreground">{f.perm}</TableCell>
                              <TableCell className="text-xs text-muted-foreground">{f.mtime}</TableCell>
                              <TableCell className="text-right">
                                {f.dir ? (
                                  <span className="text-xs text-muted-foreground">—</span>
                                ) : (
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    className="size-7"
                                    title="下载到本地"
                                    disabled={fileBusy === "download"}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      void downloadFile(joinRemote(remotePath, f.name));
                                    }}
                                  >
                                    <DownloadIcon className="size-3.5" />
                                  </Button>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  ) : null}
                  {files.length === 0 && rawListing ? (
                    <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded-md border bg-muted/40 p-2.5 font-mono text-[11px]">
                      {rawListing}
                    </pre>
                  ) : null}
                  {files.length === 0 && !rawListing ? (
                    <div className="rounded-md border border-dashed p-4 text-center text-xs text-muted-foreground">
                      填一个远端路径（如 /var/www/html），点「列出」看目录内容。
                    </div>
                  ) : null}

                  {download ? (
                    <div className="flex flex-col gap-2 rounded-md border p-2.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex min-w-0 items-center gap-2 text-xs">
                          <FileIcon className="size-3.5 shrink-0 text-muted-foreground" />
                          <span className="truncate font-mono">{download.remote_path}</span>
                          <Badge variant="outline" className="shrink-0 text-[10px]">
                            {download.mode === "text" ? "文本" : "base64"}
                          </Badge>
                          <span className="shrink-0 text-muted-foreground">
                            {fmtSize(download.returned)}
                            {download.truncated ? ` / 远端 ${fmtSize(download.size)}` : ""}
                          </span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Button variant="outline" size="sm" onClick={saveDownloaded}>
                            <DownloadIcon className="size-3.5" />
                            保存
                          </Button>
                          <Button variant="ghost" size="sm" onClick={() => void copyText(download.body, "文件内容")}>
                            <CopyIcon className="size-3.5" />
                            复制
                          </Button>
                        </div>
                      </div>
                      <pre className="max-h-40 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-[11px]">
                        {download.mode === "text" ? download.body : `${download.body.slice(0, 2000)}…`}
                      </pre>
                    </div>
                  ) : null}

                  <div className="flex flex-wrap items-end gap-2 border-t pt-3">
                    <div className="flex min-w-[160px] flex-1 flex-col gap-1">
                      <Label className="text-xs">本地文件</Label>
                      <Input
                        type="file"
                        className="h-8"
                        onChange={(e) => void pickUploadFile(e.target.files?.[0] ?? null)}
                        disabled={!current}
                      />
                    </div>
                    <div className="flex min-w-[200px] flex-1 flex-col gap-1">
                      <Label className="text-xs">上传到（远端完整路径）</Label>
                      <Input
                        value={uploadPath}
                        onChange={(e) => setUploadPath(e.target.value)}
                        placeholder="/tmp/tool"
                        className="h-8 font-mono text-xs"
                      />
                    </div>
                    <Button
                      size="sm"
                      onClick={() => void uploadRemote()}
                      disabled={!current || !uploadB64 || fileBusy === "upload"}
                    >
                      {fileBusy === "upload" ? (
                        <Loader2Icon className="size-4 animate-spin" />
                      ) : (
                        <UploadIcon className="size-4" />
                      )}
                      上传
                    </Button>
                    {uploadName ? (
                      <span className="text-xs text-muted-foreground">
                        {uploadName} · {fmtSize(Math.ceil((uploadB64.length * 3) / 4))}
                      </span>
                    ) : null}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* ---- Payload 库 ---- */}
            <TabsContent value="payloads" className="min-h-0 flex-1 overflow-auto">
              <Card className="gap-3 py-3">
                <CardContent className="flex flex-col gap-3 px-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="min-w-0 text-xs text-muted-foreground">
                      点开看全文、复制；落地后回到左栏登记会话。
                      {payloadDir ? <span className="ml-1 font-mono">· {payloadDir}</span> : null}
                    </div>
                    <div className="flex items-center gap-2">
                      <Select value={payloadType} onValueChange={setPayloadType}>
                        <SelectTrigger size="sm" className="w-28">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">全部类型</SelectItem>
                          {payloadTypes.map((t) => (
                            <SelectItem key={t} value={t}>
                              {t}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Button variant="outline" size="sm" onClick={() => void loadPayloads()} disabled={payloadBusy}>
                        {payloadBusy ? (
                          <Loader2Icon className="size-4 animate-spin" />
                        ) : (
                          <RefreshCwIcon className="size-4" />
                        )}
                        刷新
                      </Button>
                    </div>
                  </div>

                  {payloads.length === 0 ? (
                    <div className="rounded-md border border-dashed p-4 text-center text-xs text-muted-foreground">
                      payload 库为空（远端应有 php / jsp / aspx 三个子目录）
                    </div>
                  ) : (
                    <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                      {filteredPayloads.map((p) => (
                        <button
                          key={p.name}
                          type="button"
                          onClick={() => void openPayload(p)}
                          className="group flex min-w-0 flex-col gap-1.5 overflow-hidden rounded-lg border p-2.5 text-left transition-colors hover:border-primary/40 hover:bg-accent/40"
                        >
                          <span className="flex w-full items-center justify-between gap-2">
                            <span className="flex min-w-0 items-center gap-1.5">
                              <TypeBadge type={p.type} />
                              <span className="min-w-0 truncate font-mono text-xs">{p.file}</span>
                            </span>
                            <span className="shrink-0 text-[10px] text-muted-foreground">{fmtSize(p.size)}</span>
                          </span>
                          <span className="w-full min-w-0 truncate text-xs text-muted-foreground">
                            {p.meta.summary || "（无说明）"}
                          </span>
                          {p.meta.mcp ? (
                            <span className="w-full min-w-0 truncate font-mono text-[10px] text-muted-foreground/80">
                              {p.meta.mcp}
                            </span>
                          ) : null}
                        </button>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>

      {/* ---- 新增会话 ---- */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-h-[90vh] overflow-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>添加 WebShell 会话</DialogTitle>
            <DialogDescription>
              同名会覆盖已有配置（created_at 保留）。会话库权限 600，参数名与 header 的值不会下发到页面。
            </DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <div className="flex flex-col gap-1.5">
              <Label>会话名</Label>
              <Input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="target-php-1（允许中文，不能含路径分隔符）"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>WebShell URL</Label>
              <Input
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder="http://target/upload/shell.php"
                className="font-mono"
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1.5">
                <Label>类型</Label>
                <Select value={form.type} onValueChange={(v) => setForm({ ...form, type: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="php">php（eval 一句话）</SelectItem>
                    <SelectItem value="php_raw">php_raw（代码执行）</SelectItem>
                    <SelectItem value="jsp">jsp（命令型）</SelectItem>
                    <SelectItem value="aspx">aspx（命令型）</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>请求方法</Label>
                <Select value={form.method} onValueChange={(v) => setForm({ ...form, method: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="POST">POST</SelectItem>
                    <SelectItem value="GET">GET</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1.5">
                <Label>参数名</Label>
                <Input
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  placeholder="pass"
                  className="font-mono"
                />
                <span className="text-xs text-muted-foreground">马里的参数名（不是口令）</span>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>备注（可选）</Label>
                <Input
                  value={form.note}
                  onChange={(e) => setForm({ ...form, note: e.target.value })}
                  placeholder="入口点 / 权限 / 来源"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>落地路径（建议填）</Label>
                <Input
                  value={form.remote_path}
                  onChange={(e) => setForm({ ...form, remote_path: e.target.value })}
                  placeholder="/var/www/html/static_xxx.php"
                  className="font-mono"
                />
                <span className="text-xs text-muted-foreground">清痕迹时靠它删远端文件</span>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>出口代理（默认跟随平台代理）</Label>
                <Input
                  value={form.proxy}
                  onChange={(e) => setForm({ ...form, proxy: e.target.value })}
                  placeholder="留空 = 跟随代理订阅里的节点；填 direct 强制直连"
                  className="font-mono"
                />
                <span className="text-xs text-muted-foreground">
                  留空即走「代理订阅」里选中的节点，换节点出口 IP 会自动跟着变，不用回来改这里。
                  也可以填 socks5h://user:pass@host:port 单独指定，或填 direct 强制直连。
                </span>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>User-Agent（可选）</Label>
                <Input
                  value={form.user_agent}
                  onChange={(e) => setForm({ ...form, user_agent: e.target.value })}
                  placeholder="留空 = 普通 Chrome UA"
                  className="font-mono"
                />
                <span className="text-xs text-muted-foreground">默认不带任何工具名，别在这里写自己的名字</span>
              </div>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>自定义 Header（可选，JSON 对象）</Label>
              <Textarea
                value={form.header}
                onChange={(e) => setForm({ ...form, header: e.target.value })}
                placeholder={'{"X-Token":"abc"}'}
                className="font-mono text-xs"
                rows={3}
              />
              <span className="text-xs text-muted-foreground">
                需要过 WAF 或带 Authorization 时填；Host / Content-Length / Connection 不允许覆盖。
              </span>
            </div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setAddOpen(false)}>
                取消
              </Button>
              <Button type="submit" disabled={saving}>
                {saving ? <Loader2Icon className="size-4 animate-spin" /> : <PlusIcon className="size-4" />}
                保存
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* ---- 删除确认 ---- */}
      <AlertDialog open={pendingDelete !== null} onOpenChange={(v) => !v && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {pendingSessions.length > 1 ? `删除选中的 ${pendingSessions.length} 个会话？` : `删除会话「${pendingSessions[0]?.name ?? ""}」？`}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {deleteRemote
                ? "先删远端的马文件和上传残留，复查确认打不通后再摘掉本机记录。"
                : "只删本机的 webshells.json 记录，远端 webshell 文件与已上传的文件都保留（痕迹还在）。"}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-2 rounded-md border p-3 text-xs">
            <label className="flex cursor-pointer items-start gap-2">
              <Checkbox
                checked={deleteRemote}
                onCheckedChange={(v) => setDeleteRemote(v === true)}
                className="mt-0.5"
              />
              <span>
                同时删除远端文件（默认不删）
                <span className="block text-muted-foreground">
                  勾上：删掉马文件{((pendingSessions?.length ?? 0) > 0) ? "和上传残留" : ""}并复查打不通；
                  不勾：只摘本机登记，目标上的文件原样保留
                </span>
              </span>
            </label>
            {pendingSessions.length > 1 ? (
              <div className="max-h-40 space-y-1 overflow-auto font-mono text-[11px] text-muted-foreground">
                {pendingSessions.map((s) => (
                  <div key={s.name} className="truncate">
                    {s.name} · {s.remote_path || "未记录落地路径"}
                  </div>
                ))}
              </div>
            ) : (
              <div className="font-mono text-[11px] text-muted-foreground">
                落地路径：{pendingSessions[0]?.remote_path || "未记录（PHP eval 型可自报路径，命令型需手填）"}
              </div>
            )}
            {(pendingSessions[0]?.artifacts?.length ?? 0) > 0 ? (
              <div className="text-[11px] text-muted-foreground">
                上传残留 {pendingSessions[0]?.artifacts?.length} 个：{pendingSessions[0]?.artifacts?.join("、")}
              </div>
            ) : null}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction onClick={() => void doDelete()}>
              {deleteRemote ? "删除并清痕迹" : "只删登记"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ---- 批量修改 ---- */}
      <Dialog open={bulkOpen} onOpenChange={(v) => !v && setBulkOpen(false)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>批量修改 {checked.length} 个会话</DialogTitle>
            <DialogDescription className="text-xs">
              只改下面四个字段，留空表示保持原值。参数名、自定义头、URL 这些页面拿不到（打码），
              也不会被改动——马不会被改坏。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label className="text-xs">备注</Label>
              <Input
                value={bulkForm.note}
                placeholder="留空 = 不改"
                onChange={(e) => setBulkForm({ ...bulkForm, note: e.target.value })}
              />
            </div>
            <div className="grid gap-1.5">
              <Label className="text-xs">落地路径（马的远端绝对路径，清痕迹要用）</Label>
              <Input
                value={bulkForm.remote_path}
                placeholder="留空 = 不改；如 /var/www/html/frontend/web/s.php"
                onChange={(e) => setBulkForm({ ...bulkForm, remote_path: e.target.value })}
              />
            </div>
            <div className="grid gap-1.5">
              <Label className="text-xs">出口代理</Label>
              <Input
                value={bulkForm.proxy}
                placeholder="留空 = 不改（继续跟随代理订阅）；填 direct = 强制直连"
                onChange={(e) => setBulkForm({ ...bulkForm, proxy: e.target.value })}
              />
            </div>
            <div className="grid gap-1.5">
              <Label className="text-xs">User-Agent</Label>
              <Input
                value={bulkForm.user_agent}
                placeholder="留空 = 不改"
                onChange={(e) => setBulkForm({ ...bulkForm, user_agent: e.target.value })}
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setBulkOpen(false)} disabled={bulkBusy}>
              取消
            </Button>
            <Button onClick={() => void bulkSave()} disabled={bulkBusy}>
              {bulkBusy ? "保存中…" : `保存到 ${checked.length} 个会话`}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* ---- Payload 全文抽屉 ---- */}
      <Sheet open={payloadOpen} onOpenChange={setPayloadOpen}>
        <SheetContent className="flex w-full flex-col gap-3 overflow-hidden sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2 font-mono text-sm">
              {payloadDetail ? <TypeBadge type={payloadDetail.type} /> : null}
              {payloadDetail?.name ?? "读取中…"}
              {payloadDetail ? (
                <span className="font-normal text-xs text-muted-foreground">{fmtSize(payloadDetail.size)}</span>
              ) : null}
            </SheetTitle>
            <SheetDescription className="text-xs">
              {payloadDetail?.meta.summary ?? "读取 payload 全文"}
            </SheetDescription>
          </SheetHeader>

          {payloadLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2Icon className="size-4 animate-spin" />
              读取中…
            </div>
          ) : null}

          {!payloadLoading && payloadDetail ? (
            <div className="flex min-h-0 flex-1 flex-col gap-3">
              <div className="grid gap-1.5 rounded-lg border bg-muted/30 p-2.5 text-xs">
                {payloadDetail.meta.scene ? (
                  <div>
                    <span className="text-muted-foreground">适用场景：</span>
                    {payloadDetail.meta.scene}
                  </div>
                ) : null}
                {payloadDetail.meta.perm ? (
                  <div>
                    <span className="text-muted-foreground">所需权限：</span>
                    {payloadDetail.meta.perm}
                  </div>
                ) : null}
                {payloadDetail.meta.bypass ? (
                  <div>
                    <span className="text-muted-foreground">绕过点：</span>
                    {payloadDetail.meta.bypass}
                  </div>
                ) : null}
                {payloadDetail.meta.param ? (
                  <div className="font-mono">
                    <span className="text-muted-foreground">参数名：</span>
                    {payloadDetail.meta.param}
                  </div>
                ) : null}
                <div className="rounded-md bg-primary/5 p-2 font-mono text-[11px]">
                  <span className="text-muted-foreground">配套 shell_add：</span>
                  <span>{payloadDetail.meta.mcp || "type=php（eval 语义，命令回显可直接读取）"}</span>
                </div>
              </div>
              <ScrollArea className="min-h-0 flex-1 rounded-md border bg-muted/20">
                <pre className="whitespace-pre p-3 font-mono text-[11px] leading-relaxed">{payloadDetail.content}</pre>
              </ScrollArea>
              <div className="flex shrink-0 justify-end gap-2">
                <Button variant="outline" onClick={() => void copyText(payloadDetail.content, "payload 全文")}>
                  <CopyIcon className="size-4" />
                  复制全文
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    setPayloadOpen(false);
                    openAdd();
                  }}
                >
                  <PlusIcon className="size-4" />
                  用这个马登记会话
                </Button>
              </div>
            </div>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}
