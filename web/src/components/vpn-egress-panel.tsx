"use client";

// VPN 出口（OpenVPN）设置面板 + 任务侧出口选择器。
//
// 两条产品约束决定了这里的形状：
//  1. 平台按项目（每期）发一套账号，同一个 .ovpn 会被不同项目复用 —— 所以账号
//     密码是任务级输入，不是配置级的固定值；
//  2. "连上了"不等于"从对的地方出去" —— 所以每条隧道都显示**实测出口 IP**，
//     并且可以点一次立刻校验。

import * as React from "react";
import {
  GlobeIcon,
  Loader2Icon,
  PlugZapIcon,
  PlusIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  Trash2Icon,
  UploadIcon,
} from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { VPNListResponse, VPNProfile, VPNTunnelStatus } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const STATE_TEXT: Record<string, string> = {
  up: "已连接",
  starting: "连接中",
  stopped: "未连接",
  error: "异常",
  "": "未连接",
};

function StateBadge({ state }: { state: string }) {
  const s = state || "stopped";
  const cls =
    s === "up"
      ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
      : s === "error"
        ? "bg-destructive/15 text-destructive"
        : "bg-muted text-muted-foreground";
  return <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${cls}`}>{STATE_TEXT[s] ?? s}</span>;
}

// EgressIP 是这一屏最重要的信息：任务到底从哪个地址出去。
function EgressIP({ status }: { status?: VPNTunnelStatus }) {
  if (status?.egress_ip) {
    const mismatch = status.expect_egress && status.expect_egress !== status.egress_ip;
    return (
      <span className={`font-mono text-xs ${mismatch ? "text-destructive" : "text-foreground"}`}>
        {status.egress_ip}
        {mismatch ? `（预期 ${status.expect_egress}）` : ""}
      </span>
    );
  }
  return <span className="font-mono text-xs text-muted-foreground">—</span>;
}

export function VpnEgressPanel() {
  const [data, setData] = React.useState<VPNListResponse | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [busy, setBusy] = React.useState<number | null>(null);
  const [editing, setEditing] = React.useState<VPNProfile | null>(null);
  const [open, setOpen] = React.useState(false);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .vpnList()
      .then(setData)
      .catch((e) => toast.error("读取 VPN 出口失败：" + (e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  const connect = (p: VPNProfile) => {
    setBusy(p.id);
    api
      .startVPN(p.id)
      .then((r) => {
        toast.success(`已连接，出口 IP ${r.status.egress_ip || "未知"}`);
        load();
      })
      .catch((e) => toast.error("连接失败：" + (e as Error).message))
      .finally(() => setBusy(null));
  };

  const disconnect = (p: VPNProfile) => {
    setBusy(p.id);
    api
      .stopVPN(p.id)
      .then(() => load())
      .catch((e) => toast.error("断开失败：" + (e as Error).message))
      .finally(() => setBusy(null));
  };

  const remove = (p: VPNProfile) => {
    if (!confirm(`删除出口「${p.name}」？已连接的隧道会被断开。`)) return;
    api
      .deleteVPN(p.id)
      .then(() => {
        toast.success("已删除");
        load();
      })
      .catch((e) => toast.error("删除失败：" + (e as Error).message));
  };

  const profiles = data?.profiles ?? [];
  const tunnels = data?.tunnels ?? [];

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-4">
        <div>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheckIcon className="size-4" />
            VPN 出口（OpenVPN）
          </CardTitle>
          <CardDescription>
            给任务绑定平台发的 OpenVPN 隧道。绑定后该任务的所有出网流量走这条隧道，
            隧道断开时任务流量会被阻断而不是回落到直连。
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            {loading ? <Loader2Icon className="size-3.5 animate-spin" /> : <RefreshCwIcon className="size-3.5" />}
            刷新
          </Button>
          <Button size="sm" onClick={() => { setEditing(null); setOpen(true); }}>
            <PlusIcon className="size-3.5" />
            新增出口
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {data && !data.supported && (
          <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs">
            当前平台不支持 VPN 出口：需要 Linux 与网络命名空间。这条功能在 macOS / Windows 上不可用。
          </p>
        )}

        {profiles.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            还没有出口。点「新增出口」上传平台给的 <code>.ovpn</code> 文件。
          </p>
        ) : (
          <div className="divide-y rounded-md border">
            {profiles.map((p) => {
              const live =
                tunnels.find((t) => t.id === p.id && (!p.username || t.username === p.username)) ??
                tunnels.find((t) => t.id === p.id);
              return (
                <div key={p.id} className="flex flex-wrap items-center gap-3 px-3 py-2.5">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm font-medium">{p.name}</span>
                      <StateBadge state={live?.state ?? p.status?.state ?? "stopped"} />
                      {!p.enabled && <Badge variant="secondary">已禁用</Badge>}
                    </div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <GlobeIcon className="size-3" />
                        出口 <EgressIP status={live ?? p.status} />
                      </span>
                      {p.expect_egress && <span>预期 {p.expect_egress}</span>}
                      {live?.socks_addr && <span className="font-mono">{live.socks_addr}</span>}
                      {live?.last_error && <span className="text-destructive">{live.last_error}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy === p.id}
                      onClick={() => connect(p)}
                      title={p.username ? undefined : "先在该出口里填默认账号，或建任务时填账号"}
                    >
                      {busy === p.id ? <Loader2Icon className="size-3.5 animate-spin" /> : <PlugZapIcon className="size-3.5" />}
                      连接
                    </Button>
                    <Button size="sm" variant="ghost" disabled={busy === p.id} onClick={() => disconnect(p)}>
                      断开
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => { setEditing(p); setOpen(true); }}>
                      编辑
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => remove(p)}>
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {tunnels.length > 0 && (
          <div className="space-y-1.5">
            <p className="text-xs font-medium text-muted-foreground">正在运行的隧道（按账号区分）</p>
            <div className="divide-y rounded-md border text-xs">
              {tunnels.map((t) => (
                <div key={t.key ?? `${t.id}-${t.username}`} className="flex items-center gap-3 px-3 py-1.5">
                  <span className="min-w-0 flex-1 truncate">
                    {t.name} <span className="text-muted-foreground">/ {t.username || "默认账号"}</span>
                  </span>
                  <StateBadge state={t.state} />
                  <EgressIP status={t} />
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>

      <ProfileDialog
        open={open}
        onOpenChange={setOpen}
        profile={editing}
        onSaved={() => { setOpen(false); load(); }}
      />
    </Card>
  );
}

function ProfileDialog({
  open,
  onOpenChange,
  profile,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  profile: VPNProfile | null;
  onSaved: () => void;
}) {
  const [name, setName] = React.useState("");
  const [ovpn, setOvpn] = React.useState("");
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [expect, setExpect] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [fileName, setFileName] = React.useState("");

  React.useEffect(() => {
    if (!open) return;
    setName(profile?.name ?? "");
    setOvpn(profile?.ovpn ?? "");
    setUsername(profile?.username ?? "");
    setPassword("");
    setExpect(profile?.expect_egress ?? "");
    setFileName("");
  }, [open, profile]);

  const pickFile = (f: File | null) => {
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      setOvpn(String(reader.result ?? ""));
      setFileName(f.name);
      if (!name) setName(f.name.replace(/\.ovpn$/i, ""));
    };
    reader.readAsText(f);
  };

  const save = () => {
    if (!name.trim()) {
      toast.error("请填写名称");
      return;
    }
    if (!ovpn.trim()) {
      toast.error("请上传或粘贴 .ovpn 内容");
      return;
    }
    setSaving(true);
    api
      .saveVPN({
        id: profile?.id,
        name: name.trim(),
        ovpn,
        username: username.trim(),
        password: password || undefined,
        expect_egress: expect.trim(),
        enabled: true,
      })
      .then(() => {
        toast.success("已保存");
        onSaved();
      })
      .catch((e) => toast.error("保存失败：" + (e as Error).message))
      .finally(() => setSaving(false));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{profile ? "编辑 VPN 出口" : "新增 VPN 出口"}</DialogTitle>
          <DialogDescription>
            上传平台给的 <code>.ovpn</code>。配置里的老选项（ns-cert-type、comp-lzo、
            CBC 密码套件）会在建链时自动改写成现代 OpenVPN 可用的形式，并在下方隧道信息里列出。
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="vpn-name" className="text-xs">名称</Label>
              <Input id="vpn-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="360众测 / 漏洞盒子第4069期" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="vpn-expect" className="text-xs">预期出口 IP（可选）</Label>
              <Input id="vpn-expect" value={expect} onChange={(e) => setExpect(e.target.value)} placeholder="填了就校验，对不上直接报错" />
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="vpn-user" className="text-xs">默认账号（可选）</Label>
              <Input id="vpn-user" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="留空则在建任务时填" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="vpn-pass" className="text-xs">默认密码（可选）</Label>
              <Input
                id="vpn-pass"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={profile?.password_set ? "已保存，留空则不修改" : ""}
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <Label htmlFor="vpn-ovpn" className="text-xs">.ovpn 配置</Label>
              <label className="flex cursor-pointer items-center gap-1 text-xs text-primary">
                <UploadIcon className="size-3.5" />
                选择文件
                <input
                  type="file"
                  accept=".ovpn,.conf,text/plain"
                  className="hidden"
                  onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
                />
              </label>
            </div>
            <textarea
              id="vpn-ovpn"
              value={ovpn}
              onChange={(e) => setOvpn(e.target.value)}
              spellCheck={false}
              rows={8}
              placeholder="client&#10;dev tun&#10;remote 1.2.3.4 1194&#10;..."
              className="w-full rounded-md border bg-transparent px-2 py-1.5 font-mono text-[11px] outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
            {fileName && <p className="text-[11px] text-muted-foreground">已读取 {fileName}</p>}
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
          <Button onClick={save} disabled={saving}>
            {saving && <Loader2Icon className="size-3.5 animate-spin" />}
            保存
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// EgressPicker 是建任务弹窗里的出口选择：选平台出口或某个 VPN，并填该项目的账号。
// 选 VPN 时可以直接"测试"一次，把实测出口 IP 显示出来再决定要不要跑。
export function EgressPicker({
  profiles,
  egress,
  username,
  password,
  onChange,
}: {
  profiles: VPNProfile[];
  egress: string;
  username: string;
  password: string;
  onChange: (v: { egress: string; username: string; password: string }) => void;
}) {
  const [testing, setTesting] = React.useState(false);
  const [tested, setTested] = React.useState<VPNTunnelStatus | null>(null);
  const selectedID = egress.startsWith("vpn:") ? Number(egress.slice(4)) : 0;

  const test = () => {
    if (!selectedID) return;
    setTesting(true);
    setTested(null);
    api
      .startVPN(selectedID, username || undefined, password || undefined)
      .then((r) => {
        setTested(r.status);
        toast.success(`出口 IP ${r.status.egress_ip || "未知"}`);
      })
      .catch((e) => toast.error("连接失败：" + (e as Error).message))
      .finally(() => setTesting(false));
  };

  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="flex items-center gap-2">
        <GlobeIcon className="size-3.5 text-muted-foreground" />
        <Label className="text-xs">出口</Label>
      </div>
      <Select
        value={egress || "global"}
        onValueChange={(v) => {
          setTested(null);
          onChange({ egress: v === "global" ? "" : v, username, password });
        }}
      >
        <SelectTrigger size="sm" className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="global">平台默认出口（全局代理）</SelectItem>
          {profiles.map((p) => (
            <SelectItem key={p.id} value={`vpn:${p.id}`}>
              {p.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {selectedID > 0 && (
        <div className="space-y-2 border-t pt-2">
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor="egress-user" className="text-[11px]">该项目 VPN 账号</Label>
              <Input
                id="egress-user"
                className="h-8"
                value={username}
                onChange={(e) => onChange({ egress, username: e.target.value, password })}
                placeholder="例如 424789-4069"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="egress-pass" className="text-[11px]">密码</Label>
              <Input
                id="egress-pass"
                type="password"
                className="h-8"
                value={password}
                onChange={(e) => onChange({ egress, username, password: e.target.value })}
                placeholder="留空则用出口里保存的"
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="h-7" onClick={test} disabled={testing}>
              {testing ? <Loader2Icon className="size-3 animate-spin" /> : <PlugZapIcon className="size-3" />}
              测试并查看出口 IP
            </Button>
            <span className="text-[11px] text-muted-foreground">
              实际出口 <EgressIP status={tested ?? undefined} />
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
