"use client";

// WebShell 会话工作台。
//
// 布局是 IDE 式三栏：左侧固定宽度的会话面板（搜索/筛选/折叠组），中间黑色终端
// 占满主视觉，底部文件/Payload 面板可收起。页面整体不滚动，只有会话列表、终端
// 输出、文件列表各自独立滚动。会话库与 MCP 共用 webshells.json，命令/上传/下载
// 直接走后端 /api/webshell/*，不经 MCP 子进程。

import * as React from "react";
import {
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CircleIcon,
  CopyIcon,
  DownloadIcon,
  FileIcon,
  FolderIcon,
  FolderUpIcon,
  HelpCircleIcon,
  Loader2Icon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  SendIcon,
  TerminalIcon,
  Trash2Icon,
  UploadIcon,
  XIcon,
} from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type {
  WebshellDownloadResult,
  WebshellPayloadDetail,
  WebshellPayloadEntry,
  WebshellSession,
} from "@/lib/types";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// 文案 / 常量
// ---------------------------------------------------------------------------

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

/** W 型 = eval 一句话（php）；其余归"其他 shell"。 */
const isWType = (t: string) => t === "php";

const QUICK = ["id", "whoami", "uname -a", "pwd", "ls -la"];

/** 会话执行状态：本地记录，执行成功/失败后更新。 */
type SessionState = "pending" | "ok" | "error";
const STATE_DOT: Record<SessionState, string> = {
  pending: "bg-orange-500",
  ok: "bg-emerald-500",
  error: "bg-red-500",
};

// ---------------------------------------------------------------------------
// 纯函数
// ---------------------------------------------------------------------------

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function listCommand(type: string, path: string): string {
  if (type === "aspx") return `dir "${path.replace(/"/g, '""')}"`;
  return `ls -la ${shellQuote(path)}`;
}

function joinRemote(dir: string, name: string): string {
  if (dir.endsWith("/") || dir.endsWith("\\")) return `${dir}${name}`;
  if (dir === "/") return `/${name}`;
  const win = /^[A-Za-z]:/.test(dir);
  return `${dir}${win ? "\\" : "/"}${name}`;
}

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

interface RemoteFile {
  name: string;
  size: number | null;
  perm: string;
  mtime: string;
  dir: boolean;
}

function parseLs(raw: string): RemoteFile[] {
  const rows: RemoteFile[] = [];
  const re = /^([dlbcps-][rwxStTs-]{9})[+@.]?\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\w{3}\s+\d{1,2}\s+[\d:]{4,5})\s+(.+)$/;
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(re);
    if (!m) continue;
    let name = m[4].trim();
    if (name === "." || name === "..") continue;
    const dir = m[1].startsWith("d");
    if (dir) name = name.replace(/\/$/, "");
    rows.push({ name, size: dir ? null : Number(m[2]), perm: m[1], mtime: m[3], dir });
  }
  return rows;
}

function fmtSize(n: number | null): string {
  if (n === null) return "-";
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)}M`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)}G`;
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// ---------------------------------------------------------------------------
// 终端数据
// ---------------------------------------------------------------------------

type TermLine =
  | { id: number; kind: "cmd"; text: string }
  | { id: number; kind: "out"; text: string; meta?: string }
  | { id: number; kind: "err"; text: string };

// ---------------------------------------------------------------------------
// 小部件
// ---------------------------------------------------------------------------

function StatPill({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <span className="flex items-baseline gap-1.5 text-[11px] text-muted-foreground">
      {label}
      <span className="font-mono font-medium text-foreground tabular-nums">{value}</span>
    </span>
  );
}

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

function TermRow({ line }: { line: TermLine }) {
  if (line.kind === "cmd") {
    return (
      <div className="flex gap-2">
        <span className="select-none text-emerald-500">$</span>
        <span className="text-zinc-100">{line.text}</span>
      </div>
    );
  }
  if (line.kind === "err") {
    return <div className="text-red-400">{line.text}</div>;
  }
  return (
    <div className="flex flex-col">
      <pre className="whitespace-pre-wrap text-zinc-300">{line.text}</pre>
      {line.meta ? <span className="text-[10px] text-zinc-600">{line.meta}</span> : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 页面
// ---------------------------------------------------------------------------

export default function WebshellPage() {
  const [sessions, setSessions] = React.useState<WebshellSession[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [selected, setSelected] = React.useState("");

  // 每个会话各留一份终端历史（只在页面内，刷新即清空）。
  const [history, setHistory] = React.useState<Record<string, TermLine[]>>({});
  const seq = React.useRef(0);
  const [cmd, setCmd] = React.useState("");
  const [running, setRunning] = React.useState(false);
  const [conn, setConn] = React.useState<"idle" | "unknown" | "ok" | "error">("idle");
  const [stick, setStick] = React.useState(true);
  const [cmdHistory, setCmdHistory] = React.useState<string[]>([]);
  const [histIdx, setHistIdx] = React.useState(-1);

  // 左侧列表
  const [checked, setChecked] = React.useState<string[]>([]);
  const [q, setQ] = React.useState("");
  const [filter, setFilter] = React.useState<"all" | "w" | "other">("all");
  const [openW, setOpenW] = React.useState(true);
  const [openOther, setOpenOther] = React.useState(true);
  const [stateById, setStateById] = React.useState<Record<string, SessionState>>({});

  // 底部面板
  const [panelOpen, setPanelOpen] = React.useState(true);
  const [panelTab, setPanelTab] = React.useState<"files" | "payloads">("files");

  // 文件
  const [remotePath, setRemotePath] = React.useState("/");
  const [pathInput, setPathInput] = React.useState("/");
  const [files, setFiles] = React.useState<RemoteFile[]>([]);
  const [fileRaw, setFileRaw] = React.useState("");
  const [fileBusy, setFileBusy] = React.useState<"" | "list" | "download" | "upload">("");
  const [download, setDownload] = React.useState<WebshellDownloadResult | null>(null);
  const [uploadPath, setUploadPath] = React.useState("/tmp/");
  const [uploadB64, setUploadB64] = React.useState("");
  const [uploadName, setUploadName] = React.useState("");

  // Payload 库
  const [payloadEntries, setPayloadEntries] = React.useState<WebshellPayloadEntry[]>([]);
  const [payloadDetail, setPayloadDetail] = React.useState<WebshellPayloadDetail | null>(null);

  // 新增会话
  const [addOpen, setAddOpen] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [form, setForm] = React.useState({ name: "", url: "", type: "php", method: "GET", note: "" });

  const termRef = React.useRef<HTMLDivElement>(null);
  const inputRef = React.useRef<HTMLInputElement>(null);

  const current = sessions.find((s) => s.name === selected);
  const lines = selected ? (history[selected] ?? []) : [];

  // -------------------------------------------------------------------------
  // 数据
  // -------------------------------------------------------------------------

  const loadSessions = React.useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.webshellSessions();
      setSessions(r.sessions ?? []);
      if (!selected && r.sessions?.length) setSelected(r.sessions[0].name);
    } catch (e) {
      toast.error(errMsg(e, "读取会话失败"));
    } finally {
      setLoading(false);
    }
  }, [selected]);

  const loadPayloads = React.useCallback(async () => {
    try {
      const r = await api.webshellPayloads();
      setPayloadEntries(r.entries ?? []);
    } catch {
      // 静默：payload 库可能未初始化
    }
  }, []);

  React.useEffect(() => {
    loadSessions();
    loadPayloads();
  }, [loadSessions, loadPayloads]);

  React.useEffect(() => {
    if (stick && termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight;
    }
  }, [lines.length, stick]);

  // -------------------------------------------------------------------------
  // 操作
  // -------------------------------------------------------------------------

  const push = (name: string, item: Omit<TermLine, "id"> & { meta?: string }) => {
    const id = ++seq.current;
    setHistory((h) => ({ ...h, [name]: [...(h[name] ?? []), { ...item, id } as TermLine] }));
  };

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
    setConn("unknown");
    try {
      const r = await api.webshellExec(target, text);
      push(target, {
        kind: "out",
        text: r.output || "（命令已执行，远端无输出）",
        meta: `${r.mode} · ${r.elapsed_ms}ms${r.truncated ? " · 输出已截断" : ""}`,
      });
      setConn("ok");
      setStateById((m) => ({ ...m, [target]: "ok" }));
    } catch (err) {
      const msg = errMsg(err, "执行失败");
      push(target, { kind: "err", text: msg });
      setConn("error");
      setStateById((m) => ({ ...m, [target]: "error" }));
      toast.error(msg);
    } finally {
      setRunning(false);
      inputRef.current?.focus();
    }
  }

  function onConsoleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "l") {
      e.preventDefault();
      clearScreen();
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = histIdx < 0 ? cmdHistory.length - 1 : Math.max(0, histIdx - 1);
      if (cmdHistory[next] !== undefined) {
        setHistIdx(next);
        setCmd(cmdHistory[next]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (histIdx < 0) return;
      const next = histIdx + 1;
      if (next >= cmdHistory.length) {
        setHistIdx(-1);
        setCmd("");
      } else {
        setHistIdx(next);
        setCmd(cmdHistory[next]);
      }
    }
  }

  function clearScreen() {
    if (!selected) return;
    setHistory((h) => ({ ...h, [selected]: [] }));
  }

  function onTermScroll() {
    const el = termRef.current;
    if (!el) return;
    setStick(el.scrollHeight - el.scrollTop - el.clientHeight < 32);
  }

  async function listRemote(path: string) {
    if (!current) return;
    const p = path.trim() || "/";
    setFileBusy("list");
    try {
      const r = await api.webshellExec(current.name, listCommand(current.type, p));
      const parsed = parseLs(r.output || "");
      setFiles(parsed);
      setFileRaw(parsed.length === 0 ? (r.output || "") : "");
      setRemotePath(p);
      setPathInput(p);
    } catch (e) {
      toast.error(errMsg(e, "列目录失败"));
    } finally {
      setFileBusy("");
    }
  }

  async function downloadFile(path: string) {
    if (!current) return;
    setFileBusy("download");
    setDownload(null);
    try {
      const r = await api.webshellDownload({ name: current.name, remote_path: path });
      setDownload(r);
    } catch (e) {
      toast.error(errMsg(e, "下载失败"));
    } finally {
      setFileBusy("");
    }
  }

  async function pickUploadFile(file: File | null) {
    setUploadB64("");
    setUploadName("");
    if (!file) return;
    const buf = new Uint8Array(await file.arrayBuffer());
    setUploadB64(bytesToB64(buf));
    setUploadName(file.name);
    if (!uploadPath.endsWith(file.name)) {
      setUploadPath(`${uploadPath.trim() || "/tmp/"}${file.name}`);
    }
  }

  async function doUpload() {
    if (!current || !uploadB64) return;
    setFileBusy("upload");
    try {
      await api.webshellUpload({ name: current.name, remote_path: uploadPath.trim(), b64: uploadB64 });
      toast.success(`已上传到 ${uploadPath.trim()}`);
      setUploadB64("");
      setUploadName("");
      void listRemote(remotePath);
    } catch (e) {
      toast.error(errMsg(e, "上传失败"));
    } finally {
      setFileBusy("");
    }
  }

  async function openPayload(name: string) {
    try {
      const [type, file] = name.split("/", 2);
      const d = await api.webshellPayload(type, file || "");
      setPayloadDetail(d);
    } catch (e) {
      toast.error(errMsg(e, "读取 payload 失败"));
    }
  }

  async function saveSession() {
    if (!form.name.trim() || !form.url.trim()) {
      toast.error("名称和地址必填");
      return;
    }
    setSaving(true);
    try {
      await api.webshellSaveSession({
        name: form.name.trim(),
        url: form.url.trim(),
        type: form.type,
        note: form.note.trim(),
      });
      toast.success("已登记");
      setAddOpen(false);
      setForm({ name: "", url: "", type: "php", method: "GET", note: "" });
      void loadSessions();
    } catch (e) {
      toast.error(errMsg(e, "保存失败"));
    } finally {
      setSaving(false);
    }
  }

  async function deleteSessions(names: string[]) {
    if (!names.length) return;
    if (!confirm(`删除 ${names.length} 个会话登记？`)) return;
    try {
      await Promise.all(names.map((n) => api.webshellDeleteSession(n)));
      toast.success("已删除");
      setChecked([]);
      if (names.includes(selected)) setSelected("");
      void loadSessions();
    } catch (e) {
      toast.error(errMsg(e, "删除失败"));
    }
  }

  async function copyText(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`已复制${label}`);
    } catch {
      toast.error("复制失败");
    }
  }

  // -------------------------------------------------------------------------
  // 派生
  // -------------------------------------------------------------------------

  const activeCount = sessions.filter((x) => (stateById[x.name] ?? "pending") === "ok").length;

  const filteredSessions = React.useMemo(() => {
    const k = q.trim().toLowerCase();
    let list = sessions;
    if (k) list = list.filter((it) => JSON.stringify(it).toLowerCase().includes(k));
    if (filter === "w") list = list.filter((it) => isWType(it.type));
    if (filter === "other") list = list.filter((it) => !isWType(it.type));
    return [...list].sort((a, b) => {
      const aw = isWType(a.type) ? 0 : 1;
      const bw = isWType(b.type) ? 0 : 1;
      return aw !== bw ? aw - bw : a.name.localeCompare(b.name);
    });
  }, [sessions, q, filter]);

  const crumbs = remotePath.replace(/\\/g, "/").split("/").filter(Boolean);

  // -------------------------------------------------------------------------
  // 渲染
  // -------------------------------------------------------------------------

  return (
    <div data-content-padding={false}
      className="flex h-[calc(100vh-3rem)] min-h-0 flex-col overflow-hidden bg-background">
      {/* ---------- 顶部导航条 ---------- */}
      <div className="flex h-11 shrink-0 items-center gap-3 border-b px-3">
        <h1 className="flex items-center gap-2 text-sm font-semibold">
          <TerminalIcon className="size-4 text-muted-foreground" />
          WebShell
        </h1>
        <StatPill label="会话" value={sessions.length} />
        <StatPill label="活跃" value={activeCount} />
        <HelpDot
          tip={
            "W 一句话 = eval 型一句话木马；其他 Shell = 代码马 / 命令马。\n" +
            "状态：待验证(橙) / 已连通(绿) / 失效(红)，按执行结果标记。\n" +
            "终端：Enter 执行、↑/↓ 翻历史、Ctrl+L 清屏。"
          }
        />
        <div className="ml-auto flex items-center gap-2">
          {current ? (
            <span className="flex items-center gap-1.5 rounded-md border bg-muted/30 px-2 py-1">
              <span className={cn("size-1.5 rounded-full", STATE_DOT[stateById[current.name] ?? "pending"])} />
              <span className="max-w-36 truncate text-xs font-medium" title={current.name}>{current.name}</span>
              <span className="font-mono text-[10px] text-muted-foreground/60">{current.type}</span>
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">未选择会话</span>
          )}
          <button
            onClick={() => void loadSessions()}
            disabled={loading}
            className="inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-50"
          >
            {loading ? <Loader2Icon className="size-3.5 animate-spin" /> : <RefreshCwIcon className="size-3.5" />}
            刷新
          </button>
          <button
            onClick={() => setAddOpen(true)}
            className="inline-flex h-7 items-center gap-1.5 rounded-md bg-primary px-2.5 text-xs font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            <PlusIcon className="size-3.5" />
            添加会话
          </button>
        </div>
      </div>

      {/* ---------- 主体：左列表 + 右终端 ---------- */}
      <div className="flex min-h-0 flex-1 overflow-hidden">
        {/* 左侧会话面板 */}
        <aside className="flex w-[260px] shrink-0 flex-col overflow-hidden border-r">
          {/* 固定头：搜索 + 筛选 */}
          <div className="shrink-0 space-y-2 border-b p-2">
            <div className="relative">
              <SearchIcon className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="搜索会话"
                className="h-8 w-full rounded-md border bg-transparent pl-7 pr-2 text-xs outline-none placeholder:text-muted-foreground focus:border-primary"
              />
            </div>
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as "all" | "w" | "other")}
              className="h-8 w-full rounded-md border bg-transparent px-2 text-xs text-muted-foreground outline-none"
              aria-label="按入口形态筛选"
            >
              <option value="all">全部（{sessions.length}）</option>
              <option value="w">W 一句话（{sessions.filter((s) => isWType(s.type)).length}）</option>
              <option value="other">其他 Shell（{sessions.filter((s) => !isWType(s.type)).length}）</option>
            </select>
            {checked.length > 0 ? (
              <div className="flex items-center gap-1.5 rounded-md bg-muted/50 px-2 py-1">
                <span className="text-[10px] text-muted-foreground">已选 {checked.length}</span>
                <button
                  onClick={() => deleteSessions(checked)}
                  className="ml-auto inline-flex h-6 items-center gap-1 rounded-md border px-1.5 text-[10px] text-red-600 transition-colors hover:bg-red-500/10"
                >
                  <Trash2Icon className="size-3" />
                  删除
                </button>
                <button
                  onClick={() => setChecked([])}
                  className="inline-flex h-6 items-center rounded-md px-1.5 text-[10px] text-muted-foreground hover:text-foreground"
                >
                  清空
                </button>
              </div>
            ) : null}
          </div>

          {/* 列表（独立滚动） */}
          <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto overscroll-contain">
            {filteredSessions.length === 0 ? (
              <div className="px-3 py-10 text-center">
                <p className="text-xs text-muted-foreground">
                  {sessions.length === 0 ? "还没有会话" : `没有匹配「${q}」的会话`}
                </p>
                {sessions.length === 0 ? (
                  <button
                    onClick={() => setAddOpen(true)}
                    className="mt-3 inline-flex h-7 items-center gap-1 rounded-md bg-primary px-2.5 text-xs font-medium text-primary-foreground"
                  >
                    <PlusIcon className="size-3.5" />
                    添加第一个会话
                  </button>
                ) : null}
              </div>
            ) : (
              (["w", "other"] as const).map((gk) => {
                const items = filteredSessions.filter((x) => isWType(x.type) === (gk === "w"));
                if (filter !== "all" && filter !== gk) return null;
                if (items.length === 0) return null;
                const open = gk === "w" ? openW : openOther;
                const toggle = () => (gk === "w" ? setOpenW((v) => !v) : setOpenOther((v) => !v));
                return (
                  <div key={gk}>
                    <button
                      type="button"
                      onClick={toggle}
                      className="sticky top-0 z-10 flex w-full items-center gap-2 border-b bg-background/95 px-3 py-1.5 text-[11px] font-medium text-muted-foreground backdrop-blur hover:text-foreground"
                    >
                      <span className={cn("size-1.5 rounded-full", gk === "w" ? "bg-emerald-500" : "bg-slate-400")} />
                      {gk === "w" ? "W 一句话" : "其他 Shell"}
                      <span className="tabular-nums text-muted-foreground/60">{items.length}</span>
                      <ChevronRightIcon className={cn("ml-auto size-3 transition-transform", open && "rotate-90")} />
                    </button>
                    {open
                      ? items.map((s) => {
                          const active = s.name === selected;
                          const st = stateById[s.name] ?? "pending";
                          return (
                            <div
                              key={s.name}
                              className={cn(
                                "group relative flex items-center gap-2 px-2 py-2 transition-colors",
                                active ? "bg-primary/10" : "hover:bg-muted/60",
                              )}
                            >
                              {active ? <span className="absolute inset-y-0 left-0 w-0.5 bg-primary" /> : null}
                              <input
                                type="checkbox"
                                checked={checked.includes(s.name)}
                                onChange={(e) =>
                                  setChecked((c) => (e.target.checked ? [...c, s.name] : c.filter((x) => x !== s.name)))
                                }
                                onClick={(e) => e.stopPropagation()}
                                aria-label={`选择会话 ${s.name}`}
                                className="ml-1 shrink-0 accent-primary"
                              />
                              <button
                                type="button"
                                onClick={() => {
                                  setSelected(s.name);
                                  inputRef.current?.focus();
                                }}
                                title={`${s.name}\n${s.url}${s.note ? `\n${s.note}` : ""}`}
                                className="flex min-w-0 flex-1 flex-col items-start gap-0.5 text-left"
                              >
                                <span className="flex w-full items-center gap-1.5">
                                  <span className={cn("size-1.5 shrink-0 rounded-full", STATE_DOT[st])} />
                                  <span className="min-w-0 flex-1 truncate text-xs font-medium">{s.name}</span>
                                  <span className="shrink-0 font-mono text-[9px] text-muted-foreground/60">
                                    {s.type}
                                  </span>
                                </span>
                                <span className="w-full truncate font-mono text-[10px] text-muted-foreground/70">
                                  {s.url}
                                </span>
                              </button>
                              <button
                                type="button"
                                onClick={() => deleteSessions([s.name])}
                                title="删除会话登记"
                                className="shrink-0 rounded p-1 text-muted-foreground opacity-0 transition-opacity hover:text-red-500 group-hover:opacity-100"
                              >
                                <Trash2Icon className="size-3" />
                              </button>
                            </div>
                          );
                        })
                      : null}
                  </div>
                );
              })
            )}
          </div>
        </aside>

        {/* 右侧：终端 + 底部面板 */}
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          {/* 终端标题行 */}
          <div className="flex h-8 shrink-0 items-center gap-2 border-b px-2.5">
            <TerminalIcon className="size-3.5 text-muted-foreground" />
            <span className="text-xs font-medium">终端</span>
            {current ? (
              <>
                <span className="max-w-56 truncate text-xs text-muted-foreground" title={current.name}>
                  · {current.name}
                </span>
                <span className="font-mono text-[10px] text-muted-foreground/60">
                  {TYPE_LABEL[current.type] ?? current.type}
                </span>
              </>
            ) : null}
            <button
              onClick={clearScreen}
              disabled={!selected || lines.length === 0}
              title="清屏（Ctrl+L）"
              className="ml-auto inline-flex h-6 items-center rounded-md px-2 text-[10px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-40"
            >
              清屏
            </button>
          </div>

          {/* 终端输出（独立滚动） */}
          <div
            ref={termRef}
            onScroll={onTermScroll}
            className="scrollbar-thin min-h-0 flex-1 overflow-y-auto overscroll-contain bg-zinc-950 p-4 font-mono text-[12px] leading-relaxed"
          >
            {lines.length === 0 ? (
              <div className="text-zinc-600">
                {current
                  ? "输入 id 或点下面的快捷命令开始；↑/↓ 翻历史，Ctrl+L 清屏。"
                  : "先在左侧添加一个会话，然后在这里执行命令。"}
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

          {/* 终端输入栏（紧贴输出区） */}
          <div className="shrink-0 border-t border-zinc-800 bg-zinc-950 px-3 py-2">
            <div className="mb-2 flex flex-wrap gap-1.5">
              {QUICK.map((cmd) => (
                <button
                  key={cmd}
                  type="button"
                  disabled={!selected || running}
                  onClick={() => void run(cmd)}
                  className="rounded-md border border-zinc-700/70 px-2 py-[2px] font-mono text-[10px] text-zinc-400 transition-colors hover:border-zinc-500 hover:bg-zinc-800/60 hover:text-zinc-200 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {cmd}
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
              <span className="select-none font-mono text-emerald-500">$</span>
              <input
                ref={inputRef}
                value={cmd}
                onChange={(e) => setCmd(e.target.value)}
                onKeyDown={onConsoleKeyDown}
                placeholder={selected ? "输入命令后回车，例如 id" : "先添加一个会话"}
                disabled={!selected || running}
                autoComplete="off"
                spellCheck={false}
                className="h-8 flex-1 rounded-md border border-zinc-700 bg-zinc-900 px-2 font-mono text-xs text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-emerald-500/60"
              />
              <button
                type="submit"
                disabled={!selected || running || !cmd.trim()}
                className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-xs font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-40"
              >
                {running ? <Loader2Icon className="size-3.5 animate-spin" /> : <SendIcon className="size-3.5" />}
                执行
              </button>
            </form>
          </div>

          {/* 底部面板（可收起） */}
          <div className="shrink-0 border-t">
            <div className="flex h-8 items-center gap-1 border-b px-2">
              {(["files", "payloads"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => {
                    setPanelTab(t);
                    setPanelOpen(true);
                  }}
                  className={cn(
                    "border-b-2 px-2.5 pb-1 text-xs transition-colors",
                    panelTab === t && panelOpen
                      ? "border-primary font-medium text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground",
                  )}
                >
                  {t === "files" ? "文件管理" : "Payload 库"}
                </button>
              ))}
              <button
                onClick={() => setPanelOpen((v) => !v)}
                title={panelOpen ? "收起面板" : "展开面板"}
                className="ml-auto rounded p-1 text-muted-foreground hover:text-foreground"
                aria-label="收起或展开底部面板"
              >
                <ChevronDownIcon className={cn("size-3.5 transition-transform", !panelOpen && "rotate-180")} />
              </button>
            </div>

            {panelOpen ? (
              <div className="h-[260px] overflow-hidden">
                {panelTab === "files" ? (
                  <div className="flex h-full flex-col">
                    {/* 路径行 */}
                    <div className="flex shrink-0 items-center gap-1.5 border-b px-2 py-1.5">
                      <button
                        onClick={() => void listRemote(parentPath(remotePath))}
                        disabled={!current || remotePath === "/"}
                        title="返回上级"
                        className="inline-flex h-7 items-center gap-1 rounded-md border px-2 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-40"
                      >
                        <FolderUpIcon className="size-3.5" />
                        上级
                      </button>
                      <div className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto px-1">
                        <button
                          onClick={() => void listRemote("/")}
                          className="shrink-0 font-mono text-[11px] text-muted-foreground hover:text-foreground"
                        >
                          /
                        </button>
                        {crumbs.map((c, i) => (
                          <span key={i} className="flex shrink-0 items-center gap-1">
                            <span className="text-muted-foreground/40">/</span>
                            <button
                              onClick={() => void listRemote(`/${crumbs.slice(0, i + 1).join("/")}`)}
                              className="font-mono text-[11px] text-muted-foreground hover:text-foreground"
                            >
                              {c}
                            </button>
                          </span>
                        ))}
                      </div>
                      <input
                        value={pathInput}
                        onChange={(e) => setPathInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            void listRemote(pathInput.trim() || "/");
                          }
                        }}
                        placeholder="/var/www/html"
                        disabled={!current}
                        className="h-7 w-48 rounded-md border bg-transparent px-2 font-mono text-[11px] outline-none focus:border-primary"
                      />
                      <button
                        onClick={() => void listRemote(pathInput.trim() || "/")}
                        disabled={!current || fileBusy === "list"}
                        className="inline-flex h-7 items-center gap-1 rounded-md border px-2 text-xs transition-colors hover:bg-accent disabled:opacity-40"
                      >
                        {fileBusy === "list" ? <Loader2Icon className="size-3.5 animate-spin" /> : <RefreshCwIcon className="size-3.5" />}
                        列出
                      </button>
                    </div>

                    {/* 文件列表（独立滚动） */}
                    <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto overscroll-contain">
                      {files.length === 0 && fileRaw === "" ? (
                        <p className="px-3 py-8 text-center text-xs text-muted-foreground">
                          {current ? "输入路径后点「列出」" : "先添加一个会话"}
                        </p>
                      ) : files.length === 0 ? (
                        <pre className="p-3 font-mono text-[11px] text-muted-foreground">{fileRaw}</pre>
                      ) : (
                        <table className="w-full text-[11px]">
                          <thead className="sticky top-0 bg-background">
                            <tr className="border-b text-left text-muted-foreground">
                              <th className="px-3 py-1.5 font-medium">名称</th>
                              <th className="w-20 px-2 py-1.5 font-medium">大小</th>
                              <th className="w-24 px-2 py-1.5 font-medium">权限</th>
                              <th className="w-28 px-2 py-1.5 font-medium">时间</th>
                              <th className="w-16 px-2 py-1.5" />
                            </tr>
                          </thead>
                          <tbody>
                            {files.map((f) => (
                              <tr key={f.name} className="border-b border-border/40 transition-colors hover:bg-muted/40">
                                <td className="max-w-0 px-3 py-1.5">
                                  <button
                                    onClick={() => (f.dir ? void listRemote(joinRemote(remotePath, f.name)) : void downloadFile(joinRemote(remotePath, f.name)))}
                                    className="flex w-full items-center gap-1.5 truncate text-left font-mono"
                                    title={f.name}
                                  >
                                    {f.dir ? <FolderIcon className="size-3.5 shrink-0 text-muted-foreground" /> : <FileIcon className="size-3.5 shrink-0 text-muted-foreground" />}
                                    <span className="truncate">{f.name}</span>
                                  </button>
                                </td>
                                <td className="px-2 py-1.5 font-mono text-muted-foreground">{fmtSize(f.size)}</td>
                                <td className="px-2 py-1.5 font-mono text-muted-foreground/70">{f.perm}</td>
                                <td className="px-2 py-1.5 font-mono text-muted-foreground/70">{f.mtime}</td>
                                <td className="px-2 py-1.5">
                                  {!f.dir ? (
                                    <button
                                      onClick={() => void downloadFile(joinRemote(remotePath, f.name))}
                                      className="rounded p-1 text-muted-foreground hover:text-foreground"
                                      title="下载"
                                    >
                                      <DownloadIcon className="size-3" />
                                    </button>
                                  ) : null}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>

                    {/* 上传行 */}
                    <div className="flex shrink-0 items-end gap-2 border-t px-2 py-2">
                      <div className="flex min-w-0 flex-1 flex-col gap-1">
                        <label className="text-[10px] text-muted-foreground">本地文件</label>
                        <input
                          type="file"
                          onChange={(e) => void pickUploadFile(e.target.files?.[0] ?? null)}
                          disabled={!current}
                          className="h-7 w-full rounded-md border bg-transparent px-1 text-[11px] file:mr-2 file:rounded file:border-0 file:bg-muted file:px-2 file:py-0.5 file:text-[10px]"
                        />
                      </div>
                      <div className="flex min-w-0 flex-1 flex-col gap-1">
                        <label className="text-[10px] text-muted-foreground">上传到</label>
                        <input
                          value={uploadPath}
                          onChange={(e) => setUploadPath(e.target.value)}
                          placeholder="/tmp/tool"
                          disabled={!current}
                          className="h-7 w-full rounded-md border bg-transparent px-2 font-mono text-[11px] outline-none focus:border-primary"
                        />
                      </div>
                      <button
                        onClick={() => void doUpload()}
                        disabled={!current || !uploadB64 || fileBusy === "upload"}
                        className="inline-flex h-7 items-center gap-1 rounded-md bg-primary px-2.5 text-xs font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-40"
                      >
                        {fileBusy === "upload" ? <Loader2Icon className="size-3.5 animate-spin" /> : <UploadIcon className="size-3.5" />}
                        上传
                      </button>
                    </div>
                  </div>
                ) : (
                  /* Payload 库 */
                  <div className="scrollbar-thin h-full overflow-y-auto overscroll-contain">
                    {payloadEntries.length === 0 ? (
                      <p className="px-3 py-8 text-center text-xs text-muted-foreground">Payload 库为空</p>
                    ) : (
                      <table className="w-full text-[11px]">
                        <thead className="sticky top-0 bg-background">
                          <tr className="border-b text-left text-muted-foreground">
                            <th className="px-3 py-1.5 font-medium">名称</th>
                            <th className="w-24 px-2 py-1.5 font-medium">类型</th>
                            <th className="w-20 px-2 py-1.5 font-medium">大小</th>
                            <th className="w-16 px-2 py-1.5" />
                          </tr>
                        </thead>
                        <tbody>
                          {payloadEntries.map((p) => (
                            <tr key={p.name} className="border-b border-border/40 transition-colors hover:bg-muted/40">
                              <td className="max-w-0 px-3 py-1.5">
                                <button
                                  onClick={() => void openPayload(p.name)}
                                  className="w-full truncate text-left font-mono hover:text-primary"
                                  title={p.name}
                                >
                                  {p.name}
                                </button>
                              </td>
                              <td className="px-2 py-1.5 text-muted-foreground">{p.type}</td>
                              <td className="px-2 py-1.5 font-mono text-muted-foreground">{fmtSize(p.size)}</td>
                              <td className="px-2 py-1.5">
                                <button
                                  onClick={() => void copyText(p.name, "路径")}
                                  className="rounded p-1 text-muted-foreground hover:text-foreground"
                                  title="复制路径"
                                >
                                  <CopyIcon className="size-3" />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </div>
      </div>

      {/* ---------- 新增会话 ---------- */}
      {addOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={() => setAddOpen(false)}>
          <div
            className="w-full max-w-md rounded-lg border bg-background p-4 shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-semibold">新增会话</h2>
              <button onClick={() => setAddOpen(false)} className="rounded p-1 text-muted-foreground hover:text-foreground">
                <XIcon className="size-4" />
              </button>
            </div>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <label className="flex flex-col gap-1">
                  <span className="text-[10px] text-muted-foreground">名称</span>
                  <input
                    value={form.name}
                    onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                    placeholder="目标主机备注"
                    className="h-8 rounded-md border bg-transparent px-2 text-xs outline-none focus:border-primary"
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-[10px] text-muted-foreground">类型</span>
                  <select
                    value={form.type}
                    onChange={(e) => setForm((f) => ({ ...f, type: e.target.value }))}
                    className="h-8 rounded-md border bg-transparent px-2 text-xs outline-none"
                  >
                    {Object.entries(TYPE_LABEL).map(([k, v]) => (
                      <option key={k} value={k}>{v}</option>
                    ))}
                  </select>
                </label>
              </div>
              <label className="flex flex-col gap-1">
                <span className="text-[10px] text-muted-foreground">地址（URL，query 里的 pass/pwd 会打码）</span>
                <input
                  value={form.url}
                  onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                  placeholder="http://target/shell.php?pass=cmd"
                  className="h-8 rounded-md border bg-transparent px-2 font-mono text-xs outline-none focus:border-primary"
                />
              </label>
              <div className="grid grid-cols-2 gap-2">
                <label className="flex flex-col gap-1">
                  <span className="text-[10px] text-muted-foreground">方法</span>
                  <select
                    value={form.method}
                    onChange={(e) => setForm((f) => ({ ...f, method: e.target.value }))}
                    className="h-8 rounded-md border bg-transparent px-2 text-xs outline-none"
                  >
                    {["GET", "POST"].map((m) => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-[10px] text-muted-foreground">备注</span>
                  <input
                    value={form.note}
                    onChange={(e) => setForm((f) => ({ ...f, note: e.target.value }))}
                    placeholder="可选"
                    className="h-8 rounded-md border bg-transparent px-2 text-xs outline-none focus:border-primary"
                  />
                </label>
              </div>
              <div className="flex justify-end gap-2 pt-1">
                <button
                  onClick={() => setAddOpen(false)}
                  className="inline-flex h-8 items-center rounded-md border px-3 text-xs transition-colors hover:bg-accent"
                >
                  取消
                </button>
                <button
                  onClick={() => void saveSession()}
                  disabled={saving || !form.name.trim() || !form.url.trim()}
                  className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-xs font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-40"
                >
                  {saving ? <Loader2Icon className="size-3.5 animate-spin" /> : <CheckIcon className="size-3.5" />}
                  登记
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
