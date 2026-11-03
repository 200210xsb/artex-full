"use client";

import * as React from "react";

import {
  Loader2Icon,
  PlusIcon,
  PowerIcon,
  PowerOffIcon,
  RefreshCwIcon,
  Trash2Icon,
  WaypointsIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { ProxyNode, ProxyStatus, ProxySubscription } from "@/lib/types";

/** 统一的错误文案提取：后端返回的中文错误直接展示。 */
const errMsg = (err: unknown, fallback: string) => (err instanceof Error ? err.message : fallback);

/** unix 秒 → 本地时间；0/空表示还没刷新过。 */
const fmtTime = (sec?: number) => (sec ? new Date(sec * 1000).toLocaleString() : "-");

export default function ProxyPage() {
  const [status, setStatus] = React.useState<ProxyStatus | null>(null);
  const [subs, setSubs] = React.useState<ProxySubscription[]>([]);
  const [nodes, setNodes] = React.useState<ProxyNode[]>([]);
  const [loading, setLoading] = React.useState(false);

  const [name, setName] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [creating, setCreating] = React.useState(false);
  const [busy, setBusy] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [st, list, ns] = await Promise.all([api.proxyStatus(), api.proxySubscriptions(), api.proxyNodes()]);
      setStatus(st);
      setSubs(list);
      setNodes(ns);
    } catch (err) {
      toast.error(errMsg(err, "代理状态加载失败"));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) {
      toast.error("订阅链接必填");
      return;
    }
    setCreating(true);
    try {
      const sub = await api.createProxySubscription({ name: name.trim(), url: url.trim() });
      toast.success(`订阅已添加：解析到 ${sub.nodes?.length ?? 0} 个节点`);
      setName("");
      setUrl("");
      await load();
    } catch (err) {
      toast.error(errMsg(err, "添加订阅失败"));
    } finally {
      setCreating(false);
    }
  }

  async function refresh(sub: ProxySubscription) {
    setBusy(`refresh-${sub.id}`);
    try {
      const updated = await api.refreshProxySubscription(sub.id);
      toast.success(`已刷新「${updated.name}」：${updated.nodes?.length ?? 0} 个节点`);
      await load();
    } catch (err) {
      toast.error(errMsg(err, "刷新订阅失败"));
    } finally {
      setBusy("");
    }
  }

  async function remove(sub: ProxySubscription) {
    if (!window.confirm(`删除订阅「${sub.name}」？已选的出口不会被自动取消。`)) return;
    setBusy(`del-${sub.id}`);
    try {
      await api.deleteProxySubscription(sub.id);
      toast.success("订阅已删除");
      await load();
    } catch (err) {
      toast.error(errMsg(err, "删除订阅失败"));
    } finally {
      setBusy("");
    }
  }

  async function selectNode(node: ProxyNode) {
    setBusy(`select-${node.name}`);
    try {
      const st = await api.proxySelect(node.name);
      setStatus(st);
      toast.success(`出口已切到「${node.name}」，边车 ${st.listen}`);
      await load();
    } catch (err) {
      toast.error(errMsg(err, "切换出口失败"));
      await load();
    } finally {
      setBusy("");
    }
  }

  async function deselect() {
    setBusy("deselect");
    try {
      const st = await api.proxyDeselect();
      setStatus(st);
      toast.success("已取消出口，恢复直连");
      await load();
    } catch (err) {
      toast.error(errMsg(err, "取消出口失败"));
      await load();
    } finally {
      setBusy("");
    }
  }

  const running = status?.running === true;

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl">代理订阅</h1>
          <p className="text-muted-foreground text-sm">
            粘贴 Clash 订阅链接，选一个节点作为 ARTEX 出口：本地 sing-box 边车监听 {status?.listen ?? "127.0.0.1:7890"}
            （http + socks），并自动设为全局代理。
          </p>
        </div>
        <div className="flex items-center gap-2">
          {status?.selected ? (
            <Button variant="outline" size="sm" onClick={() => void deselect()} disabled={busy === "deselect"}>
              {busy === "deselect" ? <Loader2Icon className="size-4 animate-spin" /> : <PowerOffIcon className="size-4" />}
              取消出口
            </Button>
          ) : null}
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
            刷新
          </Button>
        </div>
      </div>

      {/* 状态条：当前出口 + 边车运行状态 + 上次错误 */}
      <Card>
        <CardContent className="flex flex-col gap-2 py-4">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <div className="flex items-center gap-2">
              <WaypointsIcon className="size-4 text-muted-foreground" />
              <Badge variant={running ? "default" : "outline"}>{running ? "边车运行中" : "边车未运行"}</Badge>
              {status?.node ? <Badge variant="secondary">{status.node}</Badge> : null}
            </div>
            <div className="text-sm">
              <span className="text-muted-foreground">当前出口：</span>
              <code className="break-all">{status?.egress || "直连（未设全局代理）"}</code>
            </div>
            <div className="text-muted-foreground text-sm">
              监听 <code>{status?.listen ?? "-"}</code>
              {status?.pid ? ` · pid ${status.pid}` : ""}
              {status?.started_at ? ` · 启动于 ${fmtTime(status.started_at)}` : ""}
            </div>
            <div className="text-muted-foreground text-sm">
              订阅 {status?.subscriptions ?? 0} 条 · 节点 {status?.nodes ?? 0} 个
              {status?.selected ? ` · 已选 ${status.selected}` : ""}
            </div>
          </div>
          {status && !status.binary_ready ? (
            <div className="text-destructive text-xs">
              sing-box 未找到：{status.binary}（放到该路径，或设环境变量 ARTEX_SINGBOX_BIN 指向可执行文件）
            </div>
          ) : null}
          {status?.last_error ? <div className="text-destructive text-xs">上次错误：{status.last_error}</div> : null}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">订阅列表</CardTitle>
            <CardDescription>刷新会重新拉取并解析节点；删除只影响这条订阅，不会自动取消已选出口。</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>订阅</TableHead>
                  <TableHead>节点</TableHead>
                  <TableHead>更新时间</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {subs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="text-muted-foreground text-center">
                      {loading ? "加载中…" : "还没有订阅。用右侧表单粘贴 Clash 订阅链接。"}
                    </TableCell>
                  </TableRow>
                ) : (
                  subs.map((sub) => (
                    <TableRow key={sub.id}>
                      <TableCell>
                        <div className="font-medium">{sub.name}</div>
                        <div className="text-muted-foreground max-w-[320px] truncate font-mono text-xs" title={sub.url}>
                          {sub.url}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">{sub.nodes?.length ?? 0}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{fmtTime(sub.updated_at)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            title="重新拉取并解析"
                            disabled={busy === `refresh-${sub.id}`}
                            onClick={() => void refresh(sub)}>
                            {busy === `refresh-${sub.id}` ? (
                              <Loader2Icon className="size-4 animate-spin" />
                            ) : (
                              <RefreshCwIcon className="size-4" />
                            )}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            title="删除订阅"
                            disabled={busy === `del-${sub.id}`}
                            onClick={() => void remove(sub)}>
                            {busy === `del-${sub.id}` ? (
                              <Loader2Icon className="size-4 animate-spin" />
                            ) : (
                              <Trash2Icon className="size-4" />
                            )}
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
            <CardTitle className="text-base">添加订阅</CardTitle>
            <CardDescription>支持 Clash / Clash.Meta（proxies 列表）和 base64 分享链接。</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="flex flex-col gap-3" onSubmit={create}>
              <div className="flex flex-col gap-1.5">
                <Label>名称（可选）</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="留空则用域名" />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>订阅链接</Label>
                <Input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com/api/v1/client/subscribe?token=…"
                />
              </div>
              <Button type="submit" disabled={creating}>
                {creating ? <Loader2Icon className="size-4 animate-spin" /> : <PlusIcon className="size-4" />}
                拉取并解析
              </Button>
              <p className="text-muted-foreground text-xs">
                拉取失败会直接显示后端返回的原因（订阅 404、内容不是 Clash YAML 或 base64 分享链接等）。
              </p>
            </form>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">节点</CardTitle>
          <CardDescription>
            选中一个节点后，ARTEX 会生成 sing-box 配置、拉起边车并把全局出口指向它；切换失败会回滚到原来的出口。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>名称</TableHead>
                <TableHead>类型</TableHead>
                <TableHead>服务器</TableHead>
                <TableHead>地区</TableHead>
                <TableHead className="text-right">出口</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {nodes.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground text-center">
                    {loading ? "加载中…" : "还没有节点：先添加订阅。"}
                  </TableCell>
                </TableRow>
              ) : (
                nodes.map((node) => {
                  const isCurrent = running && status?.node === node.name;
                  return (
                    <TableRow key={`${node.server}:${node.port}-${node.name}`}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{node.name}</span>
                          {isCurrent ? <Badge variant="default">当前出口</Badge> : null}
                        </div>
                      </TableCell>
                      <TableCell className="uppercase text-xs">{node.type || "-"}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {node.server}:{node.port}
                      </TableCell>
                      <TableCell className="text-sm">{node.region || "-"}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant={isCurrent ? "secondary" : "outline"}
                          size="sm"
                          disabled={busy === `select-${node.name}` || isCurrent}
                          onClick={() => void selectNode(node)}>
                          {busy === `select-${node.name}` ? (
                            <Loader2Icon className="size-4 animate-spin" />
                          ) : (
                            <PowerIcon className="size-4" />
                          )}
                          设为出口
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
