"use client";

import * as React from "react";

import { Link2Icon, Loader2Icon, RefreshCwIcon, SmartphoneIcon, TerminalIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { DeviceBridgeInfo, DeviceProxyConfig, DeviceRow, DevicesResponse } from "@/lib/types";

const token = () => (typeof window === "undefined" ? null : localStorage.getItem("artex_token"));

/** 接入时设备在 hello 里报的 rooted 标记；没 root 的设备，抓包/系统代理/root shell 都用不了。 */
const isRooted = (d: DeviceRow | null | undefined): boolean => {
  const extra = d?.extra as Record<string, unknown> | null | undefined;
  return extra != null && extra.rooted === true;
};

const stateVariant = (state: string): "default" | "secondary" | "destructive" | "outline" => {
  switch (state) {
    case "online":
    case "connected":
      return "default";
    case "unauthorized":
      return "destructive";
    case "registered":
      return "secondary";
    default:
      return "outline";
  }
};

export default function DevicesPage() {
  const [data, setData] = React.useState<DevicesResponse | null>(null);
  const [loading, setLoading] = React.useState(false);

  const [platform, setPlatform] = React.useState<"android" | "ios">("android");
  const [address, setAddress] = React.useState("");
  const [name, setName] = React.useState("");
  const [connecting, setConnecting] = React.useState(false);

  const [bridge, setBridge] = React.useState<DeviceBridgeInfo | null>(null);
  const [proxy, setProxy] = React.useState<DeviceProxyConfig | null>(null);
  const [showToken, setShowToken] = React.useState(false);

  const [active, setActive] = React.useState<DeviceRow | null>(null);
  const [cmd, setCmd] = React.useState("id");
  const [output, setOutput] = React.useState("");
  const [running, setRunning] = React.useState(false);
  const [shot, setShot] = React.useState<string | null>(null);
  const [shotError, setShotError] = React.useState("");
  const [captureMsg, setCaptureMsg] = React.useState("");
  const [proxyMsg, setProxyMsg] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      setData(await api.devices());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "设备列表加载失败");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
    void api.deviceBridge().then(setBridge).catch(() => setBridge(null));
    void api.deviceProxyConfig().then(setProxy).catch(() => setProxy(null));
  }, [load]);

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    if (!address.trim()) {
      toast.error("地址必填：Android 填 IP:端口（如 192.168.1.7:5555），iOS 填 UDID");
      return;
    }
    setConnecting(true);
    try {
      await api.createDevice({ platform, address: address.trim(), name: name.trim() });
      toast.success("设备已接入");
      setAddress("");
      setName("");
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "接入失败");
    } finally {
      setConnecting(false);
    }
  }

  async function remove(d: DeviceRow) {
    if (!window.confirm(`把 ${d.name || d.id} 移出登记表？`)) return;
    try {
      await api.deleteDevice(d.id);
      toast.success("已移除");
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "移除失败");
    }
  }

  async function runShell() {
    if (!active) return;
    setRunning(true);
    setOutput("");
    try {
      const r = await api.deviceShell(active.id, cmd);
      setOutput(r.output || "(无输出)");
    } catch (err) {
      setOutput(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  }

  async function loadShot() {
    if (!active) return;
    setShotError("");
    try {
      const t = token();
      const res = await fetch(`/api/devices/${encodeURIComponent(active.id)}/screenshot`, {
        headers: t ? { Authorization: `Bearer ${t}` } : {},
      });
      if (!res.ok) {
        setShotError((await res.text()) || `HTTP ${res.status}`);
        return;
      }
      const blob = await res.blob();
      setShot(URL.createObjectURL(blob));
    } catch (err) {
      setShotError(err instanceof Error ? err.message : String(err));
    }
  }

  React.useEffect(() => {
    if (!shot) return;
    return () => URL.revokeObjectURL(shot);
  }, [shot]);

  async function proxyAction(kind: "set" | "clear") {
    if (!active) return;
    setProxyMsg("");
    try {
      if (kind === "set") {
        const r = await api.deviceSetProxy(active.id);
        setProxyMsg(r.output || `已把系统代理指向 ${r.addr}`);
      } else {
        const r = await api.deviceClearProxy(active.id);
        setProxyMsg(r.output || "已清除系统代理");
      }
    } catch (err) {
      setProxyMsg(err instanceof Error ? err.message : String(err));
    }
  }

  async function capture(kind: "start" | "status" | "pull") {
    if (!active) return;
    setCaptureMsg("");
    try {
      if (kind === "start") {
        const r = await api.deviceCaptureStart(active.id);
        setCaptureMsg(r.output || "已开始抓包");
      } else if (kind === "status") {
        const r = await api.deviceCaptureStatus(active.id);
        setCaptureMsg(r.output || "(无输出)");
      } else {
        const r = await api.deviceCapturePull(active.id);
        setCaptureMsg(`pcap 已保存：${r.path}（${r.bytes} 字节）`);
      }
    } catch (err) {
      setCaptureMsg(err instanceof Error ? err.message : String(err));
    }
  }

  const devices = data?.devices ?? [];

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl">设备</h1>
          <p className="text-muted-foreground text-sm">
            移动端设备接入：ADB（Android）、usbmux（iOS）、接入代理（设备反连）。
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
          刷新
        </Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="设备总数"
          value={devices.length}
          hint={`ADB ${data?.adb_available ? "可用" : "未接入"} · iOS ${data?.ios_available ? "可用" : "未安装"}`}
        />
        <StatCard
          label="在线"
          value={devices.filter((d) => d.state === "online" || d.state === "connected").length}
          hint="state = online / connected"
        />
        <StatCard label="已 root" value={devices.filter((d) => isRooted(d)).length} hint="抓包、系统代理、root shell 可用" />
        <StatCard label="未 root" value={devices.filter((d) => !isRooted(d)).length} hint="只能用截图、文件、应用管理" />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">设备列表</CardTitle>
            <CardDescription>登记过的设备离线后仍保留；实时枚举到的设备直接出现在这里。</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>设备</TableHead>
                  <TableHead>平台</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>接入方式</TableHead>
                  <TableHead>标识</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-muted-foreground text-center">
                      {loading ? "加载中…" : "还没有设备。用右侧表单接入，或在手机上跑接入代理。"}
                    </TableCell>
                  </TableRow>
                ) : (
                  devices.map((d) => (
                    <TableRow key={d.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <SmartphoneIcon className="size-4 text-muted-foreground" />
                          <span className="font-medium">{d.name || d.model || d.id}</span>
                        </div>
                        {d.note ? <div className="text-muted-foreground text-xs">{d.note}</div> : null}
                      </TableCell>
                      <TableCell className="uppercase text-xs">{d.platform}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-1">
                          <Badge variant={stateVariant(d.state)}>{d.state || "unknown"}</Badge>
                          {d.platform === "android" ? (
                            <Badge
                              variant={isRooted(d) ? "default" : "outline"}
                              title={isRooted(d) ? "已 root：抓包、系统代理、root shell 可用" : "未 root：抓包、系统代理、root shell 不可用"}>
                              {isRooted(d) ? "root" : "未 root"}
                            </Badge>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs">{d.transport || "-"}</TableCell>
                      <TableCell className="max-w-[220px] truncate font-mono text-xs" title={d.serial || d.udid || d.id}>
                        {d.serial || d.udid || d.id}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setActive(d);
                              setOutput("");
                              setShot(null);
                              setShotError("");
                            }}>
                            <TerminalIcon className="size-4" />
                          </Button>
                          <Button variant="ghost" size="sm" onClick={() => void remove(d)}>
                            <Trash2Icon className="size-4" />
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

        <Card>
          <CardHeader>
            <CardTitle className="text-base">接入设备</CardTitle>
            <CardDescription>Android 需要先有 adb server；iOS 需要 libimobiledevice。</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="flex flex-col gap-3" onSubmit={connect}>
              <div className="flex flex-col gap-1.5">
                <Label>平台</Label>
                <Select value={platform} onValueChange={(v) => setPlatform(v as "android" | "ios")}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="android">Android（ADB）</SelectItem>
                    <SelectItem value="ios">iOS（usbmux）</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>地址 / 标识</Label>
                <Input
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  placeholder={platform === "android" ? "192.168.1.7:5555" : "设备 UDID"}
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>名称（可选）</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="测试机" />
              </div>
              <Button type="submit" disabled={connecting}>
                {connecting ? <Loader2Icon className="size-4 animate-spin" /> : <Link2Icon className="size-4" />}
                接入
              </Button>
            </form>

            <div className="mt-4 flex flex-col gap-1.5 border-t pt-4 text-sm">
              <div className="font-medium">接入代理（设备反连）</div>
              <div className="text-muted-foreground text-xs">
                设备上跑 artex-device-agent 回连 ARTEX，手机不用开端口，跨网段也能接。用手机扫下面这个码，或在命令里直接用配对地址。
              </div>
              <PairQR />
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="outline" size="sm" onClick={() => window.open("/device-agent.apk", "_blank")}>
                  下载接入代理 APK
                </Button>
                <span className="text-muted-foreground text-xs">约 4 MB，装到 root 手机上扫码即接入</span>
              </div>
              <div className="text-xs">
                <span className="text-muted-foreground">配对地址：</span>
                <code className="break-all">{bridge?.pair_url ?? "-"}</code>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!bridge?.pair_url}
                  onClick={() => {
                    if (!bridge?.pair_url) return;
                    void navigator.clipboard.writeText(bridge.pair_url);
                    toast.success("配对地址已复制");
                  }}>
                  复制
                </Button>
              </div>
              <div className="text-xs">
                <span className="text-muted-foreground">端点：</span>
                <code className="break-all">{bridge?.endpoint ?? "-"}</code>
              </div>
              <div className="text-xs">
                <span className="text-muted-foreground">令牌：</span>
                <code className="break-all">
                  {bridge?.token ? (showToken ? bridge.token : `${bridge.token.slice(0, 8)}…`) : "-"}
                </code>
                <Button variant="ghost" size="sm" onClick={() => setShowToken((v) => !v)}>
                  {showToken ? "隐藏" : "显示"}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!bridge?.token}
                  onClick={() => {
                    if (!bridge?.token) return;
                    void navigator.clipboard.writeText(bridge.token);
                    toast.success("令牌已复制");
                  }}>
                  复制
                </Button>
              </div>
              <div className="text-muted-foreground text-xs">记录代理：{proxy?.proxy_addr || "未启用"}</div>
              {proxy?.ca_path ? <div className="text-muted-foreground text-xs">CA：{proxy.ca_path}</div> : null}
            </div>
          </CardContent>
        </Card>
      </div>

      <Sheet open={active !== null} onOpenChange={(open) => !open && setActive(null)}>
        <SheetContent className="flex w-full flex-col gap-4 sm:max-w-xl">
          <SheetHeader>
            <SheetTitle>{active?.name || active?.model || active?.id}</SheetTitle>
            <SheetDescription>
              {active?.platform} · {active?.transport} · {active?.serial || active?.udid}
            </SheetDescription>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge variant={isRooted(active) ? "default" : "outline"}>{isRooted(active) ? "已 root" : "未 root"}</Badge>
              <span className="text-muted-foreground">
                截图：{isRooted(active) ? "root screencap / MediaProjection" : "MediaProjection（需授权）"} · 抓包：
                {isRooted(active) ? "可用" : "需 root"} · 系统代理：{isRooted(active) ? "可用" : "需 root"}
              </span>
            </div>
          </SheetHeader>

          <div className="flex flex-col gap-2">
            <div className="flex gap-2">
              <Input value={cmd} onChange={(e) => setCmd(e.target.value)} placeholder="shell 命令，如 id / pm list packages" />
              <Button onClick={() => void runShell()} disabled={running}>
                {running ? <Loader2Icon className="size-4 animate-spin" /> : <TerminalIcon className="size-4" />}
                执行
              </Button>
            </div>
            <pre className="max-h-64 overflow-auto rounded-md border bg-muted p-2 text-xs whitespace-pre-wrap">{output}</pre>
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">截图</span>
              <Button variant="outline" size="sm" onClick={() => void loadShot()}>
                抓一张
              </Button>
            </div>
            {shotError ? <div className="text-destructive text-xs">{shotError}</div> : null}
            {shot ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={shot} alt="设备截图" className="max-h-80 w-auto rounded-md border object-contain" />
            ) : null}
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-sm font-medium">抓包（tcpdump）</span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" disabled={!isRooted(active)} title={isRooted(active) ? "" : "需要 root"} onClick={() => void capture("start")}>
                  开始
                </Button>
                <Button variant="outline" size="sm" disabled={!isRooted(active)} title={isRooted(active) ? "" : "需要 root"} onClick={() => void capture("status")}>
                  状态
                </Button>
                <Button variant="outline" size="sm" disabled={!isRooted(active)} title={isRooted(active) ? "" : "需要 root"} onClick={() => void capture("pull")}>
                  停止并拉取
                </Button>
              </div>
            </div>
            <div className="text-muted-foreground text-xs">
              仅接入代理设备可用（APK 里是 root tcpdump）。HTTPS 只能看到端点，明文请配合系统代理走记录代理。
            </div>
            {captureMsg ? (
              <pre className="max-h-40 overflow-auto rounded-md border bg-muted p-2 text-xs whitespace-pre-wrap">{captureMsg}</pre>
            ) : null}
          </div>
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-sm font-medium">流量代理</span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" disabled={!isRooted(active)} title={isRooted(active) ? "" : "需要 root"} onClick={() => void proxyAction("set")}>
                  设代理
                </Button>
                <Button variant="outline" size="sm" disabled={!isRooted(active)} title={isRooted(active) ? "" : "需要 root"} onClick={() => void proxyAction("clear")}>
                  清代理
                </Button>
                <Button variant="outline" size="sm" onClick={() => window.open("/device-ca.pem", "_blank")}>
                  下载 CA
                </Button>
              </div>
            </div>
            <div className="text-muted-foreground text-xs">
              手机流量走 {proxy?.proxy_addr_lan || "（先去系统里打开流量录制）"}；装 CA 后 HTTPS 才能解出明文。
            </div>
            {proxyMsg ? (
              <pre className="max-h-40 overflow-auto rounded-md border bg-muted p-2 text-xs whitespace-pre-wrap">{proxyMsg}</pre>
            ) : null}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

/** 顶部统计卡：设备总数 / 在线 / root 分布。 */
function StatCard({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col gap-1 py-4">
        <div className="text-muted-foreground text-xs">{label}</div>
        <div className="font-semibold text-2xl">{value}</div>
        {hint ? <div className="text-muted-foreground text-xs">{hint}</div> : null}
      </CardContent>
    </Card>
  );
}

/** 配对二维码：服务端把 pair_url 渲染成 PNG，这里按鉴权拉成 blob 再展示。 */
function PairQR() {
  const [src, setSrc] = React.useState<string | null>(null);

  React.useEffect(() => {
    let objectURL: string | null = null;
    let cancelled = false;
    void (async () => {
      try {
        const t = token();
        const res = await fetch("/api/devices/pair.png", {
          headers: t ? { Authorization: `Bearer ${t}` } : {},
        });
        if (!res.ok) return;
        const blob = await res.blob();
        if (cancelled) return;
        objectURL = URL.createObjectURL(blob);
        setSrc(objectURL);
      } catch {
        /* 二维码只是便利入口，失败就不显示 */
      }
    })();
    return () => {
      cancelled = true;
      if (objectURL) URL.revokeObjectURL(objectURL);
    };
  }, []);

  if (!src) return null;
  return (
    <div className="flex items-center gap-3">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={src} alt="配对二维码" className="size-36 rounded-md border bg-white p-1" />
      <div className="text-muted-foreground text-xs">
        手机扫码得到反连地址 + token，
        <br />
        在 Termux 里把它当 <code>--server</code> 传进去即可。
      </div>
    </div>
  );
}
