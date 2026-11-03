"use client";

import * as React from "react";

import Link from "next/link";

import {
  BanIcon,
  BuildingIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  DownloadIcon,
  GitBranchIcon,
  GlobeIcon,
  KeyRoundIcon,
  LayoutTemplateIcon,
  LinkIcon,
  type LucideIcon,
  NetworkIcon,
  PlusIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  ShieldAlertIcon,
  SmartphoneIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { AssetDslSearch } from "@/components/asset-dsl-search";
import { ScopeTextEditor } from "@/components/scope-text-editor";
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
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import {
  ASSET_SOURCE_LABEL,
  ASSET_TYPE_LABEL,
  type AssetCoverage,
  type AssetLineage,
  assetsApi,
  COMPANY_SOURCE_LABEL,
  type PocCandidate,
  type PocMatchResult,
} from "@/lib/assets-api";
import { parseCompanyScopeText } from "@/lib/company-scope";
import type { Asset, Company, CompanyScopeRule } from "@/lib/types";
import { cn } from "@/lib/utils";

const METHOD_COLOR: Record<string, string> = {
  GET: "bg-emerald-100 text-emerald-700",
  POST: "bg-blue-100 text-blue-700",
  PUT: "bg-amber-100 text-amber-700",
  PATCH: "bg-orange-100 text-orange-700",
  DELETE: "bg-red-100 text-red-700",
  HEAD: "bg-purple-100 text-purple-700",
  OPTIONS: "bg-slate-100 text-slate-600",
};

function MethodBadge({ method }: { method: string }) {
  const m = method.toUpperCase();
  return (
    <span
      className={cn(
        "inline-block rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold leading-none",
        METHOD_COLOR[m] ?? "bg-muted text-muted-foreground",
      )}
    >
      {m || "—"}
    </span>
  );
}

function statusTone(code: number) {
  if (code >= 500) return "text-red-500";
  if (code >= 400) return "text-amber-500";
  if (code >= 300) return "text-blue-500";
  if (code >= 200) return "text-emerald-500";
  return "text-muted-foreground";
}

const PAGE_SIZES = [25, 50, 100, 200];

const TABS: { key: string; label: string; icon: LucideIcon }[] = [
  { key: "company", label: "企业", icon: BuildingIcon },
  { key: "root_domain", label: "根域名", icon: GlobeIcon },
  { key: "ip", label: "IP", icon: NetworkIcon },
  { key: "subdomain", label: "子域名", icon: GlobeIcon },
  { key: "app", label: "应用", icon: SmartphoneIcon },
  { key: "service", label: "服务", icon: LayoutTemplateIcon },
  { key: "endpoint", label: "接口", icon: LinkIcon },
];

export default function AssetsPage() {
  const [rows, setRows] = React.useState<Asset[]>([]);
  const [total, setTotal] = React.useState(0);
  const [companies, setCompanies] = React.useState<Company[]>([]);
  const [counts, setCounts] = React.useState<Record<string, number>>({});
  const [tab, setTab] = React.useState("company");
  const [query, setQuery] = React.useState("");
  const [loaded, setLoaded] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  const [dslError, setDslError] = React.useState("");
  const [refreshKey, setRefreshKey] = React.useState(0);
  const assetsRequestRef = React.useRef(0);
  const [rowsTab, setRowsTab] = React.useState("");

  // 覆盖度（资产中枢）：顶部卡片 + 「只看未测」筛选
  const [untestedOnly, setUntestedOnly] = React.useState(false);
  const [coverage, setCoverage] = React.useState<AssetCoverage | null>(null);
  const [coverageLoading, setCoverageLoading] = React.useState(false);

  // 血缘（发现来源）
  const [lineageMap, setLineageMap] = React.useState<Record<number, AssetLineage>>({});
  const [lineageTarget, setLineageTarget] = React.useState<AssetLineage | null>(null);

  // POC 联动
  const [pocOpen, setPocOpen] = React.useState(false);
  const [pocLoading, setPocLoading] = React.useState(false);
  const [pocResult, setPocResult] = React.useState<PocMatchResult | null>(null);

  // 批量改归属
  const [attributeOpen, setAttributeOpen] = React.useState(false);
  const [attributeCompany, setAttributeCompany] = React.useState("0");
  const [attributing, setAttributing] = React.useState(false);

  // 重新认领（按当前企业范围重算全部归属）
  const [reattributing, setReattributing] = React.useState(false);

  // asset selection & delete
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [deleteIds, setDeleteIds] = React.useState<number[]>([]);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);

  // company delete
  const [companyDeleteTarget, setCompanyDeleteTarget] = React.useState<Company | null>(null);
  const [companyDeleteAssets, setCompanyDeleteAssets] = React.useState(false);
  const [companyDeleting, setCompanyDeleting] = React.useState(false);

  // Companies + per-type counts (tab badges) — loaded on demand, no background polling.
  const loadMeta = React.useCallback(() => {
    api
      .companies()
      .then(setCompanies)
      .catch(() => {
        /* Keep the last successful company snapshot on a transient failure. */
      });
    api
      .assetCounts()
      .then(setCounts)
      .catch(() => {
        /* Keep the last successful counters on a transient failure. */
      });
  }, []);

  // Manual refresh: reload counts/companies and re-fetch the current page.
  const refresh = React.useCallback(() => {
    loadMeta();
    setRefreshKey((k) => k + 1);
    setSelected(new Set());
  }, [loadMeta]);

  const toggleSelect = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = (ids: number[]) => {
    setSelected((prev) => {
      const allSelected = ids.every((id) => prev.has(id));
      const next = new Set(prev);
      if (allSelected) {
        ids.forEach((id) => {
          next.delete(id);
        });
      } else {
        ids.forEach((id) => {
          next.add(id);
        });
      }
      return next;
    });
  };

  const openDelete = (ids: number[]) => {
    setDeleteIds(ids);
    setDeleteOpen(true);
  };

  const confirmDelete = async () => {
    setDeleting(true);
    try {
      const res = await api.deleteAssets(deleteIds);
      toast.success(`已删除 ${res.deleted} 条资产`);
      setSelected(new Set());
      refresh();
    } catch (e) {
      toast.error("删除失败：" + String((e as Error)?.message ?? e));
    } finally {
      setDeleting(false);
      setDeleteOpen(false);
    }
  };

  const confirmDeleteCompany = async () => {
    if (!companyDeleteTarget) return;
    setCompanyDeleting(true);
    try {
      const res = await api.deleteCompany(companyDeleteTarget.id, companyDeleteAssets);
      const msg =
        companyDeleteAssets && res.assets_deleted > 0
          ? `已删除企业，同时删除 ${res.assets_deleted} 条资产`
          : "已删除企业";
      toast.success(msg);
      refresh();
    } catch (e) {
      toast.error("删除失败：" + String((e as Error)?.message ?? e));
    } finally {
      setCompanyDeleting(false);
      setCompanyDeleteTarget(null);
      setCompanyDeleteAssets(false);
    }
  };

  React.useEffect(() => {
    loadMeta();
  }, [loadMeta]);

  // Reset query + page + selection when switching tabs
  // biome-ignore lint/correctness/useExhaustiveDependencies: tab changes intentionally reset tab-local controls.
  React.useEffect(() => {
    setQuery("");
    setDslError("");
    setSelected(new Set());
    setRows([]);
    setRowsTab("");
    setTotal(0);
    setLoaded(false);
  }, [tab]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: these controls intentionally reset server pagination.
  React.useEffect(() => setPage(0), [tab, size, query, untestedOnly]);

  const dslMode = query.trim() !== "";

  // 「只看未测」复用同一套 DSL 语法：把 untested=true 与用户自己的查询用
  // AND 组合。必须加括号——DSL 里 AND 比 OR 结合更紧，不加括号会把
  // 「A OR B」的口径改掉。
  const effectiveDsl = React.useMemo(() => {
    const base = query.trim();
    if (!untestedOnly) return base;
    if (!base) return "untested=true";
    return `(${base}) AND untested=true`;
  }, [query, untestedOnly]);

  // Server-side paginated page loader for the active data tab (company tab excluded).
  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    if (tab === "company") return;
    const request = ++assetsRequestRef.current;
    const dsl = effectiveDsl;
    setLoading(true);
    const offset = page * size;
    const run = async () => {
      try {
        const r = dsl ? await api.searchAssets(dsl, tab, size, offset) : await api.assets(tab, size, offset);
        if (assetsRequestRef.current !== request) return;
        setRows(r.assets);
        setRowsTab(tab);
        setTotal(r.total);
        setDslError("");
      } catch (e) {
        if (assetsRequestRef.current !== request) return;
        setDslError(String((e as Error)?.message ?? e));
        setRows([]);
        setRowsTab(tab);
        setTotal(0);
      } finally {
        if (assetsRequestRef.current === request) {
          setLoading(false);
          setLoaded(true);
        }
      }
    };
    const tid = setTimeout(run, dsl ? 400 : 0);
    return () => {
      clearTimeout(tid);
      if (assetsRequestRef.current === request) assetsRequestRef.current++;
    };
  }, [tab, page, size, effectiveDsl, refreshKey]);

  React.useEffect(() => {
    if (tab === "company") return;
    const lastPage = Math.max(0, Math.ceil(total / size) - 1);
    if (page > lastPage) setPage(lastPage);
  }, [page, size, tab, total]);

  const companyById = React.useMemo(() => {
    const m = new Map<number, string>();
    for (const c of companies) m.set(c.id, c.name);
    return m;
  }, [companies]);

  const companyName = (id?: number) => (id ? (companyById.get(id) ?? "") : "");

  // 覆盖度：跟随当前标签页与 DSL（但不受「只看未测」影响——那个开关是
  // 列表筛选，卡片要展示的是整个视图的覆盖情况）。
  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey 是显式的手动刷新触发器。
  React.useEffect(() => {
    if (tab === "company") {
      setCoverage(null);
      return;
    }
    let cancelled = false;
    setCoverageLoading(true);
    assetsApi
      .coverage({ dsl: query.trim(), type: tab })
      .then((r) => {
        if (!cancelled) setCoverage(r);
      })
      .catch(() => {
        if (!cancelled) setCoverage(null);
      })
      .finally(() => {
        if (!cancelled) setCoverageLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [tab, query, refreshKey]);

  // 血缘：只取当前页的资产 id，避免全表扫描。
  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey 是显式的手动刷新触发器。
  React.useEffect(() => {
    if (rows.length === 0) {
      setLineageMap({});
      return;
    }
    let cancelled = false;
    assetsApi
      .lineage({ ids: rows.map((r) => r.id) })
      .then((r) => {
        if (cancelled) return;
        const map: Record<number, AssetLineage> = {};
        for (const item of r.assets) map[item.id] = item;
        setLineageMap(map);
      })
      .catch(() => {
        if (!cancelled) setLineageMap({});
      });
    return () => {
      cancelled = true;
    };
  }, [rows, refreshKey]);

  // POC 联动：勾选的资产优先，没勾选就按当前 DSL 结果匹配。
  const runPocMatch = React.useCallback(async () => {
    const ids = Array.from(selected);
    const dsl = effectiveDsl;
    if (ids.length === 0 && !dsl) {
      toast.error("请先勾选资产，或用 DSL 搜索限定范围");
      return;
    }
    setPocOpen(true);
    setPocLoading(true);
    setPocResult(null);
    try {
      const result = await assetsApi.pocMatch({
        asset_ids: ids.length > 0 ? ids : undefined,
        dsl: ids.length > 0 ? undefined : dsl,
        type: ids.length > 0 ? undefined : tab,
        limit: 50,
      });
      setPocResult(result);
      if (result.candidates.length === 0) {
        toast.info("没有匹配的 POC 候选");
      }
    } catch (e) {
      toast.error("POC 匹配失败：" + String((e as Error)?.message ?? e));
    } finally {
      setPocLoading(false);
    }
  }, [selected, effectiveDsl, tab]);

  // 导出 CSV：导出当前页（或已选中的资产）。
  const exportCsv = React.useCallback(() => {
    const picked = selected.size > 0 ? rows.filter((r) => selected.has(r.id)) : rows;
    if (picked.length === 0) {
      toast.error("没有可导出的资产");
      return;
    }
    const header = ["type", "domain", "root_domain", "ip", "port", "url", "technologies", "company"];
    const lines = [header.join(",")];
    for (const a of picked) {
      lines.push(
        [
          a.type,
          a.domain ?? "",
          a.root_domain ?? "",
          a.ip ?? "",
          a.port ?? "",
          a.url ?? "",
          (a.technologies ?? []).join("|"),
          a.company_id ? (companyById.get(a.company_id) ?? "") : "",
        ]
          .map(csvCell)
          .join(","),
      );
    }
    const blob = new Blob([`﻿${lines.join("\n")}`], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `assets-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`已导出 ${picked.length} 条资产`);
  }, [rows, selected, companyById]);

  // 批量改企业归属。
  const confirmAttribute = React.useCallback(async () => {
    const ids = Array.from(selected);
    if (ids.length === 0) return;
    setAttributing(true);
    try {
      const res = await assetsApi.attribute(ids, Number(attributeCompany) || 0);
      toast.success(`已更新 ${res.updated} 条资产的企业归属`);
      setAttributeOpen(false);
      setSelected(new Set());
      refresh();
    } catch (e) {
      toast.error("改归属失败：" + String((e as Error)?.message ?? e));
    } finally {
      setAttributing(false);
    }
  }, [selected, attributeCompany, refresh]);

  // 重新认领：把企业范围里声明的域名/IP 补落成资产，再按当前范围重算全部归属
  // （人工指定的 explicit 归属不会被覆盖）。
  const reattribute = React.useCallback(async () => {
    setReattributing(true);
    try {
      const result = await api.reattributeAssets();
      const materialized = result.assets_materialized ?? 0;
      toast.success(
        materialized > 0
          ? `已按当前企业范围重新归属，并补登记 ${materialized} 条范围资产`
          : "已按当前企业范围重新归属资产",
      );
      refresh();
    } catch (e) {
      toast.error("重新认领失败：" + String((e as Error)?.message ?? e));
    } finally {
      setReattributing(false);
    }
  }, [refresh]);

  // 批量加入资产拦截（全局黑名单）：按域名 / URL / IP 生成精确规则。
  const addIntercept = React.useCallback(async () => {
    const picked = rows.filter((r) => selected.has(r.id));
    if (picked.length === 0) {
      toast.error("请先勾选资产");
      return;
    }
    const rules = new Map<string, { kind: string; pattern: string }>();
    for (const a of picked) {
      if (a.domain) rules.set(`exact_domain:${a.domain}`, { kind: "exact_domain", pattern: a.domain });
      else if (a.url) rules.set(`exact_url:${a.url}`, { kind: "exact_url", pattern: a.url });
      else if (a.ip) rules.set(`exact_ip:${a.ip}`, { kind: "exact_ip", pattern: a.ip });
    }
    if (rules.size === 0) {
      toast.error("选中的资产没有域名 / URL / IP，无法生成拦截规则");
      return;
    }
    let created = 0;
    let failed = 0;
    for (const rule of rules.values()) {
      try {
        await api.createAssetInterceptRule({
          enabled: true,
          kind: rule.kind as "exact_domain" | "exact_url" | "exact_ip",
          pattern: rule.pattern,
          note: "从资产页批量加入",
        });
        created++;
      } catch {
        failed++;
      }
    }
    if (created > 0) toast.success(`已加入 ${created} 条拦截规则`);
    if (failed > 0) toast.warning(`${failed} 条规则创建失败`);
  }, [rows, selected]);

  const tabCounts: Record<string, number> = { ...counts, company: companies.length };
  const totalAssets = Object.values(counts).reduce((a, b) => a + b, 0);

  // rows are already the current server-side page.
  const tabData = (type: string): Asset[] => (rowsTab === type ? rows : []);
  const currentRows = tabData(tab);
  const slice = <T,>(list: T[]) => list;

  const searchBox = (
    <AssetDslSearch
      query={query}
      onChange={setQuery}
      loading={loading}
      error={dslError}
      count={dslMode ? total : undefined}
    />
  );

  // 资产表格上方的操作条：POC 联动 + 导出 CSV + 批量操作。
  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      <Button variant="outline" size="sm" onClick={() => void runPocMatch()} disabled={pocLoading}>
        <ShieldAlertIcon className="size-3.5" /> POC 联动
      </Button>
      <Button variant="outline" size="sm" onClick={exportCsv}>
        <DownloadIcon className="size-3.5" /> 导出 CSV
      </Button>
      <Button variant="outline" size="sm" onClick={() => setAttributeOpen(true)} disabled={selected.size === 0}>
        <BuildingIcon className="size-3.5" /> 改归属
      </Button>
      <Button variant="outline" size="sm" onClick={() => void reattribute()} disabled={reattributing}>
        <RotateCcwIcon className="size-3.5" /> 重新认领
      </Button>
      <Button variant="outline" size="sm" onClick={addIntercept} disabled={selected.size === 0}>
        <BanIcon className="size-3.5" /> 加入拦截
      </Button>
      <span className="text-xs text-muted-foreground">
        {selected.size > 0 ? `已选 ${selected.size} 条` : "未勾选时按当前 DSL 结果匹配"}
      </span>
    </div>
  );

  return (
    <div className="flex h-[calc(100vh-6rem)] min-h-0 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">资产</h1>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-muted-foreground">
            共 <span className="tabular-nums">{totalAssets}</span> 项资产
          </span>
          {selected.size > 0 && (
            <Button variant="destructive" size="sm" onClick={() => openDelete(Array.from(selected) as number[])}>
              <Trash2Icon className="size-3.5" /> 删除已选 ({selected.size})
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
            <RefreshCwIcon className={cn("size-4", loading && "animate-spin")} /> 刷新
          </Button>
          <RegisterAssetsDialog companies={companies} onSaved={refresh} />
          <CompanyDialog onSaved={refresh} />
        </div>
      </div>

      {/* 覆盖度卡片：范围内总数 / 已测 / 未测 + 只看未测 */}
      {tab !== "company" && (
        <CoverageCard
          coverage={coverage}
          loading={coverageLoading}
          untestedOnly={untestedOnly}
          onUntestedOnlyChange={setUntestedOnly}
        />
      )}

      <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col gap-4">
        <div className="overflow-x-auto overflow-y-hidden">
          <TabsList variant="default">
            {TABS.map((t) => (
              <TabsTrigger key={t.key} value={t.key}>
                <t.icon className="size-3.5" />
                {t.label}
                <span className="ml-1 tabular-nums text-muted-foreground">{tabCounts[t.key]}</span>
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        {/* 企业 */}
        <TabsContent value="company" className="mt-0 flex min-h-0 flex-1 flex-col">
          <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
            <div className="min-h-0 flex-1 overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>企业</TableHead>
                    <TableHead className="w-24 text-right">资产数</TableHead>
                    <TableHead>资产范围</TableHead>
                    <TableHead className="w-36 text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {companies.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <CompanyAvatar name={c.name} logo={c.logo} />
                          <span className="font-medium">{c.name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right text-sm">
                        <div className="tabular-nums">{c.asset_count}</div>
                        {c.asset_count === 0 ? (
                          <div className="text-[11px] font-normal text-muted-foreground">未命中资产</div>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        {c.scope?.length ? (
                          <div className="flex flex-wrap gap-1">
                            {c.scope.map((s, i) => (
                              <Badge key={i} variant="secondary" className="font-mono text-[11px]">
                                {s.raw}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">未设置范围</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <EditScopeDialog company={c} onSaved={refresh} />
                          <AppendScopeDialog company={c} onSaved={refresh} />
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7 text-muted-foreground hover:text-destructive"
                            onClick={() => {
                              setCompanyDeleteTarget(c);
                              setCompanyDeleteAssets(false);
                            }}
                            aria-label={`删除企业 ${c.name}`}
                          >
                            <Trash2Icon className="size-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {companies.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">
                        还没有企业。点击右上角「新增企业」并填写资产范围，系统会自动认领命中的资产。
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          </Card>
        </TabsContent>

        {/* 根域名 */}
        <TabsContent value="root_domain" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          {toolbar}
          <AssetCard
            cols={["", "域名", "ICP 备案", "归属企业", "来源", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("root_domain")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="font-mono text-xs font-medium">{a.domain}</TableCell>
                <TableCell className="text-xs">{a.icp || "—"}</TableCell>
                <TableCell className="text-xs">
                  {companyName(a.company_id) || <span className="text-muted-foreground">未归属</span>}
                </TableCell>
                <TableCell>
                  <LineageCell lineage={lineageMap[a.id]} onOpen={setLineageTarget} />
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.domain || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* IP */}
        <TabsContent value="ip" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          {toolbar}
          <AssetCard
            cols={["", "IP", "C段", "绑定域名", "开放端口", "来源", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("ip")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="font-mono text-xs font-medium">{a.ip}</TableCell>
                <TableCell className="font-mono text-xs">{a.c_segment || "—"}</TableCell>
                <TableCell>
                  <Chips items={a.bound_domains ?? []} mono />
                </TableCell>
                <TableCell>
                  <Chips
                    items={(a.open_ports ?? []).map((p) => (p.service ? `${p.port}/${p.service}` : String(p.port)))}
                    mono
                  />
                </TableCell>
                <TableCell>
                  <LineageCell lineage={lineageMap[a.id]} onOpen={setLineageTarget} />
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.ip || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 子域名 */}
        <TabsContent value="subdomain" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          {toolbar}
          <AssetCard
            cols={["", "域名", "根域名", "解析类型", "解析值", "来源", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("subdomain")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="font-mono text-xs font-medium">{a.domain}</TableCell>
                <TableCell className="font-mono text-xs">{a.root_domain || "—"}</TableCell>
                <TableCell className="text-xs">{a.record_type || "—"}</TableCell>
                <TableCell className="max-w-xs truncate font-mono text-xs">
                  {(Array.isArray(a.record_value) ? a.record_value.join(", ") : a.record_value) || "—"}
                </TableCell>
                <TableCell>
                  <LineageCell lineage={lineageMap[a.id]} onOpen={setLineageTarget} />
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.domain || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 应用 */}
        <TabsContent value="app" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          {toolbar}
          <AssetCard
            cols={["", "应用名", "Bundle ID", "分类", "ICP 备案", "来源", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("app")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="text-xs font-medium">{a.app_name || "—"}</TableCell>
                <TableCell className="font-mono text-xs">{a.bundle_id || "—"}</TableCell>
                <TableCell className="text-xs">{a.category || "—"}</TableCell>
                <TableCell className="text-xs">{a.app_icp || "—"}</TableCell>
                <TableCell>
                  <LineageCell lineage={lineageMap[a.id]} onOpen={setLineageTarget} />
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.app_name || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 服务 */}
        <TabsContent value="service" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          {toolbar}
          <AssetCard
            cols={["", "服务", "域名", "IP", "端口", "状态码", "标题", "指纹", "认证", "来源", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("service")).map((a) => {
              const isHttp = a.service_type === "http";
              const svc = a.service_name || (isHttp ? "http" : "") || a.service_type || "";
              let domainCell: React.ReactNode = "—";
              if (isHttp && a.url) {
                domainCell = (
                  <a
                    href={a.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-blue-600 hover:underline dark:text-blue-400"
                  >
                    {a.domain || a.url}
                  </a>
                );
              } else if (a.domain) {
                domainCell = a.domain;
              }
              return (
                <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                  <TableCell className="w-8 pr-0">
                    <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                  </TableCell>
                  <TableCell className="text-xs">
                    <Badge variant={isHttp ? "default" : "secondary"} className="font-mono text-[10px]">
                      {svc || "—"}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[14rem] truncate font-mono text-xs" title={a.domain || a.url}>
                    {domainCell}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{a.ip || "—"}</TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">{a.port || "—"}</TableCell>
                  <TableCell>
                    {a.status_code != null ? (
                      <span className={cn("font-mono text-xs font-semibold tabular-nums", statusTone(a.status_code))}>
                        {a.status_code}
                      </span>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell className="max-w-[12rem] truncate text-xs" title={a.page_title}>
                    {a.page_title || "—"}
                  </TableCell>
                  <TableCell>
                    <Chips items={a.technologies ?? []} />
                  </TableCell>
                  <TableCell>
                    {(a.auth ?? []).length === 0 ? (
                      <span className="text-xs text-muted-foreground">—</span>
                    ) : (
                      (a.auth ?? []).map((authItem, i) => {
                        const item = authItem as Record<string, string>;
                        const label = item.type || item.username || "认证";
                        return (
                          <span key={i} className="inline-flex items-center gap-1 text-[11px]">
                            <KeyRoundIcon className="size-3 text-muted-foreground" />
                            <span className="font-mono">{label}</span>
                          </span>
                        );
                      })
                    )}
                  </TableCell>
                  <TableCell>
                    <LineageCell lineage={lineageMap[a.id]} onOpen={setLineageTarget} />
                  </TableCell>
                  <TableCell className="w-8 pl-0">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7 text-muted-foreground hover:text-destructive"
                      onClick={() => openDelete([a.id])}
                      aria-label={`删除资产 ${a.url || a.id}`}
                    >
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })}
          </AssetCard>
        </TabsContent>

        {/* 接口 */}
        <TabsContent value="endpoint" className="mt-0 flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          {toolbar}
          <AssetCard
            cols={["", "方法", "完整地址", "参数", "来源", ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onSize={setSize}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("endpoint")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="w-16">
                  <MethodBadge method={a.method || ""} />
                </TableCell>
                <TableCell className="max-w-sm truncate font-mono text-xs" title={a.url}>
                  {a.url || "—"}
                </TableCell>
                <TableCell>
                  <Chips
                    items={(a.params ?? []).map((p) => {
                      const item = p as Record<string, string>;
                      return item.name ? `${item.name}(${item.location || "?"})` : "?";
                    })}
                    mono
                  />
                </TableCell>
                <TableCell>
                  <LineageCell lineage={lineageMap[a.id]} onOpen={setLineageTarget} />
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 text-muted-foreground hover:text-destructive"
                    onClick={() => openDelete([a.id])}
                    aria-label={`删除资产 ${a.url || a.id}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>
      </Tabs>

      {/* 血缘抽屉：点「来源」列的徽章打开 */}
      <LineageSheet lineage={lineageTarget} onClose={() => setLineageTarget(null)} />

      {/* POC 联动弹窗 */}
      <PocMatchDialog open={pocOpen} onOpenChange={setPocOpen} loading={pocLoading} result={pocResult} />

      {/* 批量改企业归属 */}
      <Dialog open={attributeOpen} onOpenChange={setAttributeOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>批量改企业归属</DialogTitle>
            <DialogDescription>
              将选中的 {selected.size} 条资产改到指定企业（人工指定，后续范围重算不会覆盖）。
            </DialogDescription>
          </DialogHeader>
          <FieldGroup className="py-2">
            <Field>
              <FieldLabel htmlFor="attr-company">目标企业</FieldLabel>
              <Select value={attributeCompany} onValueChange={setAttributeCompany}>
                <SelectTrigger id="attr-company" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="0">取消归属</SelectItem>
                    {companies.map((c) => (
                      <SelectItem key={c.id} value={String(c.id)}>
                        {c.name}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAttributeOpen(false)} disabled={attributing}>
              取消
            </Button>
            <Button onClick={() => void confirmAttribute()} disabled={attributing || selected.size === 0}>
              {attributing ? "保存中…" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除</AlertDialogTitle>
            <AlertDialogDescription>
              将永久删除 <span className="font-semibold tabular-nums">{deleteIds.length}</span>{" "}
              条资产记录，此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                void confirmDelete();
              }}
              disabled={deleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleting ? "删除中…" : "确认删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={!!companyDeleteTarget}
        onOpenChange={(o) => {
          if (!o) {
            setCompanyDeleteTarget(null);
            setCompanyDeleteAssets(false);
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除企业 · {companyDeleteTarget?.name}</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-3">
                <p>此操作将永久删除该企业及其资产范围配置，不可撤销。</p>
                <label
                  htmlFor="delete-assets-opt"
                  className="flex cursor-pointer items-center gap-2.5 rounded-md border p-3 hover:bg-muted/50"
                >
                  <Checkbox
                    id="delete-assets-opt"
                    checked={companyDeleteAssets}
                    onCheckedChange={(v) => setCompanyDeleteAssets(!!v)}
                  />
                  <span className="text-sm leading-snug">
                    同时删除该企业下的所有资产
                    <span className="block text-xs text-muted-foreground">不勾选则保留资产，仅取消归属关系</span>
                  </span>
                </label>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={companyDeleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                void confirmDeleteCompany();
              }}
              disabled={companyDeleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {companyDeleting ? "删除中…" : "确认删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function AssetCard({
  cols,
  loaded,
  total,
  page,
  size,
  onSize,
  onPage,
  rows: dataRows,
  selected,
  onToggleAll,
  children,
}: {
  cols: string[];
  loaded: boolean;
  total: number;
  page: number;
  size: number;
  onSize: React.Dispatch<React.SetStateAction<number>>;
  onPage: React.Dispatch<React.SetStateAction<number>>;
  rows?: Asset[];
  selected?: Set<number>;
  onToggleAll?: (ids: number[]) => void;
  children: React.ReactNode;
}) {
  const childRows = React.Children.toArray(children);
  const pageCount = Math.max(1, Math.ceil(total / size));
  const start = total === 0 ? 0 : page * size + 1;
  const end = page * size + childRows.length;

  const pageIds = dataRows?.map((r) => r.id) ?? [];
  const allSelected = pageIds.length > 0 && selected != null && pageIds.every((id) => selected.has(id));
  const someSelected = selected != null && pageIds.some((id) => selected.has(id));

  return (
    <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
      <div className="min-h-0 flex-1 overflow-auto scrollbar-thin scrollbar-track-transparent">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-card">
            <TableRow>
              {cols.map((c, i) =>
                c === "" && i === 0 && onToggleAll ? (
                  <TableHead key={i} className="w-8 pr-0">
                    <Checkbox
                      checked={allSelected ? true : someSelected ? "indeterminate" : false}
                      onCheckedChange={() => onToggleAll(pageIds)}
                    />
                  </TableHead>
                ) : (
                  <TableHead key={c + i}>{c}</TableHead>
                ),
              )}
            </TableRow>
          </TableHeader>
          <TableBody>
            {childRows.length > 0 ? (
              childRows
            ) : (
              <TableRow>
                <TableCell colSpan={cols.length} className="py-12 text-center text-sm text-muted-foreground">
                  {loaded ? "暂无数据。" : "加载中…"}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      {total > 0 && (
        <div className="flex shrink-0 items-center gap-2 border-t px-3 py-1.5 text-xs text-muted-foreground">
          <Select value={String(size)} onValueChange={(v) => onSize(Number(v))}>
            <SelectTrigger size="sm" className="h-7 w-24">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {PAGE_SIZES.map((n) => (
                  <SelectItem key={n} value={String(n)}>
                    {n} / 页
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <span className="tabular-nums">
            {start}–{end} / {total}
          </span>
          {pageCount > 1 && (
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="icon"
                className="size-7"
                disabled={page <= 0}
                onClick={() => onPage((p) => Math.max(0, p - 1))}
              >
                <ChevronLeftIcon />
              </Button>
              <span className="tabular-nums">
                {page + 1} / {pageCount}
              </span>
              <Button
                variant="outline"
                size="icon"
                className="size-7"
                disabled={page + 1 >= pageCount}
                onClick={() => onPage((p) => Math.min(pageCount - 1, p + 1))}
              >
                <ChevronRightIcon />
              </Button>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function Chips({ items, mono }: { items: string[]; mono?: boolean }) {
  const clean = items.filter(Boolean);
  if (clean.length === 0) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {clean.map((s, i) => (
        <Badge key={i} variant="outline" className={cn("text-[10px]", mono && "font-mono")}>
          {s}
        </Badge>
      ))}
    </div>
  );
}

function CompanyAvatar({ name, logo }: { name: string; logo?: string }) {
  const initial = (name.trim()[0] ?? "?").toUpperCase();
  return (
    <Avatar className="size-7 shrink-0">
      {logo ? <AvatarImage src={logo} alt={name} /> : null}
      <AvatarFallback className="text-xs">{initial}</AvatarFallback>
    </Avatar>
  );
}

// 后端返回的 warnings 说的是既有数据问题（不是本次提交的行有错），保存本身已经
// 成功。给更长的停留时间，因为它需要用户去处理具体的资产，扫一眼标题不够。
function showScopeWarnings(warnings?: string[]) {
  for (const warning of warnings ?? []) {
    toast.warning(warning, { duration: 15000 });
  }
}

// 企业范围的资产数反馈。域名/IP 规则会在保存时立刻落成资产行，所以正常情况这里
// 不会是 0；仍然是 0 说明这次只写了 CIDR/ICP/关键词——它们只做匹配条件，不落资产。
// 必须把原因和下一步说清楚，不能用一个 success toast 让操作员以为生效了。
const ZERO_ASSET_HINT =
  "（这次的范围里没有可落成资产的域名/IP：CIDR/ICP/关键词只是匹配条件；想让它有资产，请用「新增资产」贴域名/IP，或直接建任务按范围域名开测）";

function toastScopeResult(message: string, assetCount?: number, hasInvalid = false) {
  const count = typeof assetCount === "number" ? ` · 当前企业名下 ${assetCount} 个资产` : "";
  if (assetCount === 0) {
    toast.warning(`${message}${count}${ZERO_ASSET_HINT}`, { duration: 15000 });
    return;
  }
  if (hasInvalid) {
    toast.warning(`${message}${count}`);
    return;
  }
  toast.success(`${message}${count}`);
}

function savedScopeRules(company: Company): CompanyScopeRule[] {
  return (company.scope ?? [])
    .map((scope) => ({ kind: scope.kind, value: scope.raw.trim() }))
    .filter((scope) => scope.value);
}

function savedScopeText(company: Company): string {
  return savedScopeRules(company)
    .map((scope) => scope.value)
    .join("\n");
}

// 新增资产：人给什么就记什么。域名/IP 直接建成资产（不做 DNS 解析 / HTTP 探测等
// 自动延伸）；CIDR/ICP/关键词是企业范围规则，只有选了企业才有落点，否则明确告诉
// 操作员「需要先选择企业」，而不是把它们悄悄丢掉。
function RegisterAssetsDialog({ companies, onSaved }: { companies: Company[]; onSaved: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [companyId, setCompanyId] = React.useState("0");
  const [scopeText, setScopeText] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const parsedScope = React.useMemo(() => parseCompanyScopeText(scopeText), [scopeText]);

  React.useEffect(() => {
    if (!open) return;
    setCompanyId("0");
    setScopeText("");
  }, [open]);

  const submit = async () => {
    if (parsedScope.rules.length === 0) {
      toast.error("请先粘贴要入库的域名或 IP");
      return;
    }
    if (parsedScope.errors.length > 0) {
      toast.error("请修正无效的资产范围");
      return;
    }
    setBusy(true);
    try {
      const res = await api.registerAssets(parsedScope.rules, Number(companyId) || 0);
      const scopeNote = res.company_scope_added > 0 ? ` · 写入 ${res.company_scope_added} 条企业范围` : "";
      toast.success(`已添加 ${res.assets.length} 个资产${scopeNote}`);
      // 没写进去的条目必须逐条说明原因（最多列 3 条），否则操作员会以为全都入库了。
      const notes = [
        ...res.skipped.map((item) => `${item.kind} ${item.value}：${item.reason}`),
        ...res.invalid.map((item) => `第 ${item.index} 条 ${item.kind || ""} ${item.value}：${item.error}`),
      ];
      if (notes.length > 0) {
        const more = notes.length > 3 ? ` 等 ${notes.length} 条` : "";
        toast.warning(`${notes.slice(0, 3).join("；")}${more}`, { duration: 12000 });
      }
      setOpen(false);
      onSaved();
    } catch (e) {
      toast.error(`新增失败：${String((e as Error)?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="outline" size="sm">
          <PlusIcon data-icon="inline-start" /> 新增资产
        </Button>
      </SheetTrigger>
      <SheetContent className="w-full! max-w-none! gap-0 p-0 sm:w-[520px]! sm:max-w-[520px]!">
        <SheetHeader className="border-b p-6">
          <SheetTitle>新增资产</SheetTitle>
          <SheetDescription>
            粘贴域名或 IP 原样入库，不做 DNS 解析、HTTP 探测等自动延伸。CIDR、ICP
            备案和关键词是企业范围规则，需要先选择企业。
          </SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto p-6">
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="ra-company">归属企业</FieldLabel>
              <Select value={companyId} onValueChange={setCompanyId}>
                <SelectTrigger id="ra-company" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="0">不归属（只入资产库）</SelectItem>
                    {companies.map((c) => (
                      <SelectItem key={c.id} value={String(c.id)}>
                        {c.name}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <ScopeTextEditor id="ra-scope" value={scopeText} onValueChange={setScopeText} parsed={parsedScope} />
          </FieldGroup>
        </div>
        <SheetFooter className="flex-row justify-end gap-2 border-t p-4">
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            取消
          </Button>
          <Button
            onClick={() => void submit()}
            disabled={busy || parsedScope.rules.length === 0 || parsedScope.errors.length > 0}
          >
            {busy ? "保存中…" : "保存"}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

// 新增企业使用与任务、LLM 编辑一致的右侧抽屉。
function CompanyDialog({ onSaved }: { onSaved: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [scopeText, setScopeText] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const parsedScope = React.useMemo(() => parseCompanyScopeText(scopeText), [scopeText]);

  React.useEffect(() => {
    if (!open) return;
    setName("");
    setScopeText("");
  }, [open]);

  const submit = async () => {
    if (!name.trim()) {
      toast.error("请填写企业名称");
      return;
    }
    if (parsedScope.errors.length > 0) {
      toast.error("请修正无效的资产范围");
      return;
    }
    setBusy(true);
    try {
      const res = await api.createCompany(name.trim(), parsedScope.rules);
      const added = res.scope_added ?? 0;
      const invalid = res.scope_invalid ?? 0;
      toastScopeResult(
        `已创建企业，添加 ${added} 条范围${invalid > 0 ? `；${invalid} 行无效` : ""}`,
        res.asset_count,
        invalid > 0,
      );
      setOpen(false);
      onSaved();
    } catch (e) {
      const msg = String((e as Error)?.message ?? e);
      if (/:\s*409$/.test(msg)) toast.error("企业已存在，请换个名称");
      else toast.error(`保存失败：${msg}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button size="sm">
          <BuildingIcon data-icon="inline-start" /> 新增企业
        </Button>
      </SheetTrigger>
      <SheetContent className="w-full! max-w-none! gap-0 p-0 sm:w-[520px]! sm:max-w-[520px]!">
        <SheetHeader className="border-b p-6">
          <SheetTitle>新增企业</SheetTitle>
          <SheetDescription>配置企业及其资产范围。关键词只作为 Agent 提示，不会自动归属资产。</SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto p-6">
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="cn-name">企业名称</FieldLabel>
              <Input
                id="cn-name"
                placeholder="如 Acme Corp（名称唯一）"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <ScopeTextEditor id="cn-scope" value={scopeText} onValueChange={setScopeText} parsed={parsedScope} />
          </FieldGroup>
        </div>
        <SheetFooter className="flex-row justify-end gap-2 border-t p-4">
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            取消
          </Button>
          <Button onClick={submit} disabled={busy || !name.trim() || parsedScope.errors.length > 0}>
            {busy ? "保存中…" : "保存"}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

// 编辑（覆盖）资产范围弹窗
function EditScopeDialog({ company, onSaved }: { company: Company; onSaved: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [scopeText, setScopeText] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const preservedScopeRules = React.useMemo(() => savedScopeRules(company), [company]);
  const parsedScope = React.useMemo(
    () => parseCompanyScopeText(scopeText, { preservedRules: preservedScopeRules }),
    [preservedScopeRules, scopeText],
  );

  React.useEffect(() => {
    if (!open) return;
    setScopeText(savedScopeText(company));
    setReason("");
  }, [open, company]);

  const submit = async () => {
    if (parsedScope.errors.length > 0) {
      toast.error("请修正无效的资产范围");
      return;
    }
    setBusy(true);
    try {
      const res = await api.updateCompanyScope(company.id, parsedScope.rules, reason);
      const errCount = res.invalid ?? 0;
      toastScopeResult(
        `范围已更新，共 ${res.added} 条${errCount > 0 ? `；${errCount} 行无效` : ""}`,
        res.asset_count,
        errCount > 0,
      );
      showScopeWarnings(res.warnings);
      setOpen(false);
      onSaved();
    } catch (e) {
      toast.error(`保存失败：${String((e as Error)?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="h-7">
          编辑
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>编辑资产范围 · {company.name}</DialogTitle>
          <DialogDescription>
            编辑后将替换全部现有范围。ICP 精确匹配资产，企业关键词仅作为 Agent 提示。
          </DialogDescription>
        </DialogHeader>
        <FieldGroup className="py-2">
          <ScopeTextEditor
            id={`edit-company-scope-${company.id}`}
            value={scopeText}
            onValueChange={setScopeText}
            parsed={parsedScope}
          />
          <Field>
            <FieldLabel htmlFor="es-reason">归属依据（可选）</FieldLabel>
            <Input
              id="es-reason"
              placeholder="如 证书 / whois / ASN 佐证"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            取消
          </Button>
          <Button onClick={submit} disabled={busy || parsedScope.errors.length > 0}>
            {busy ? "保存中…" : "覆盖保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// 追加资产范围弹窗
function AppendScopeDialog({ company, onSaved }: { company: Company; onSaved: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [scopeText, setScopeText] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const parsedScope = React.useMemo(() => parseCompanyScopeText(scopeText), [scopeText]);

  React.useEffect(() => {
    if (!open) return;
    setScopeText("");
    setReason("");
  }, [open]);

  const submit = async () => {
    if (parsedScope.rules.length === 0) {
      toast.error("请填写要追加的范围");
      return;
    }
    if (parsedScope.errors.length > 0) {
      toast.error("请修正无效的资产范围");
      return;
    }
    setBusy(true);
    try {
      const res = await api.addCompanyScope(company.id, parsedScope.rules, reason);
      const errCount = res.invalid ?? 0;
      toastScopeResult(
        `已追加 ${res.added} 条范围${errCount > 0 ? `；${errCount} 行无效` : ""}`,
        res.asset_count,
        errCount > 0,
      );
      showScopeWarnings(res.warnings);
      setOpen(false);
      onSaved();
    } catch (e) {
      toast.error(`保存失败：${String((e as Error)?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="h-7">
          追加
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>追加资产范围 · {company.name}</DialogTitle>
          <DialogDescription>新范围会追加到现有范围。ICP 精确匹配资产，企业关键词仅作为 Agent 提示。</DialogDescription>
        </DialogHeader>
        <FieldGroup className="py-2">
          <ScopeTextEditor
            id={`append-company-scope-${company.id}`}
            value={scopeText}
            onValueChange={setScopeText}
            parsed={parsedScope}
          />
          <Field>
            <FieldLabel htmlFor="as-reason">归属依据（可选）</FieldLabel>
            <Input
              id="as-reason"
              placeholder="如 证书 / whois / ASN 佐证"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            取消
          </Button>
          <Button onClick={submit} disabled={busy || parsedScope.rules.length === 0 || parsedScope.errors.length > 0}>
            {busy ? "保存中…" : "追加"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// =====================================================================
// 血缘（发现来源）
// =====================================================================

// LineageCell 是表格里的「来源」列：任务名 + 企业，多来源折叠成 +N。
// 点一下打开完整血缘抽屉。
function LineageCell({ lineage, onOpen }: { lineage?: AssetLineage; onOpen: (lineage: AssetLineage) => void }) {
  if (!lineage) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }
  const sources = lineage.sources ?? [];
  const first = sources[0];
  const extra = sources.length - 1;
  const company = lineage.company_name;
  return (
    <button
      type="button"
      className="flex max-w-[16rem] items-center gap-1 text-left"
      onClick={() => onOpen(lineage)}
      title="查看发现来源"
    >
      {first ? (
        <Badge variant="secondary" className="max-w-[9rem] truncate text-[10px]">
          {first.task_name}
        </Badge>
      ) : (
        <Badge variant="outline" className="text-[10px] text-muted-foreground">
          未关联任务
        </Badge>
      )}
      {company ? (
        <Badge variant="outline" className="max-w-[7rem] truncate text-[10px]">
          {company}
        </Badge>
      ) : null}
      {extra > 0 && (
        <Badge variant="outline" className="text-[10px] text-muted-foreground">
          +{extra}
        </Badge>
      )}
    </button>
  );
}

// LineageSheet 展示一条资产的完整血缘。
function LineageSheet({ lineage, onClose }: { lineage: AssetLineage | null; onClose: () => void }) {
  return (
    <Sheet open={!!lineage} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full! max-w-none! gap-0 p-0 sm:w-[520px]! sm:max-w-[520px]!">
        <SheetHeader className="border-b p-6">
          <SheetTitle className="flex items-center gap-2">
            <GitBranchIcon className="size-4" /> 发现血缘
          </SheetTitle>
          <SheetDescription>{lineage ? lineage.label : ""}</SheetDescription>
        </SheetHeader>
        {lineage ? (
          <div className="flex-1 space-y-4 overflow-y-auto p-6">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <LineageField label="资产类型" value={ASSET_TYPE_LABEL[lineage.type] ?? lineage.type} />
              <LineageField label="首次发现" value={formatTime(lineage.created_at)} />
              <LineageField label="最近出现" value={formatTime(lineage.last_seen)} />
              <LineageField label="最后更新" value={formatTime(lineage.updated_at)} />
              <LineageField label="归属企业" value={lineage.company_name || "未归属"} />
              <LineageField
                label="归属方式"
                value={COMPANY_SOURCE_LABEL[lineage.company_source ?? ""] ?? lineage.company_source ?? "—"}
              />
              <LineageField label="同根域名兄弟资产" value={`${lineage.sibling_count} 条`} />
              <LineageField label="Bundle ID" value={lineage.bundle_id || "—"} />
            </div>

            {(lineage.technologies ?? []).length > 0 && (
              <div>
                <p className="mb-1.5 text-xs font-medium text-muted-foreground">技术指纹</p>
                <Chips items={lineage.technologies ?? []} />
              </div>
            )}

            <Separator />

            <div>
              <p className="mb-2 text-xs font-medium text-muted-foreground">
                发现任务（{lineage.sources?.length ?? 0}）
              </p>
              {(lineage.sources ?? []).length === 0 ? (
                <p className="text-xs text-muted-foreground">这条资产还没有任务关联（可能是手工登记或历史数据）。</p>
              ) : (
                <ul className="space-y-2">
                  {(lineage.sources ?? []).map((s) => (
                    <li key={`${s.task_id}-${s.linked_at ?? ""}`} className="rounded-md border p-3">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{s.task_name}</span>
                        <Badge variant="outline" className="text-[10px]">
                          {ASSET_SOURCE_LABEL[s.source] ?? s.source}
                        </Badge>
                        {s.task_status && (
                          <Badge variant="secondary" className="text-[10px]">
                            {s.task_status}
                          </Badge>
                        )}
                      </div>
                      {s.source_summary && <p className="mt-1 text-xs text-muted-foreground">{s.source_summary}</p>}
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        关联时间 {formatTime(s.linked_at)}
                        {s.source_node_id ? ` · 节点 #${s.source_node_id}` : ""}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ) : (
          <div className="flex-1 p-6" />
        )}
        <SheetFooter className="flex-row justify-end border-t p-4">
          <Button variant="outline" onClick={onClose}>
            关闭
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

function LineageField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-2">
      <p className="text-[11px] text-muted-foreground">{label}</p>
      <p className="mt-0.5 truncate font-medium">{value}</p>
    </div>
  );
}

function formatTime(raw?: string): string {
  if (!raw) return "—";
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return raw;
  return parsed.toLocaleString();
}

// =====================================================================
// 覆盖度卡片
// =====================================================================

// CoverageCard 是页面顶部的覆盖度卡片：进度条 + 已测/未测 + 只看未测开关。
function CoverageCard({
  coverage,
  loading,
  untestedOnly,
  onUntestedOnlyChange,
}: {
  coverage: AssetCoverage | null;
  loading: boolean;
  untestedOnly: boolean;
  onUntestedOnlyChange: (v: boolean) => void;
}) {
  const total = coverage?.denominator ?? 0;
  const tested = coverage?.tested ?? 0;
  const untested = coverage?.untested ?? 0;
  const pct = coverage?.pct != null ? Math.round(coverage.pct * 100) : 0;
  return (
    <Card size="sm" className="gap-3 py-3">
      <CardHeader className="px-4">
        <CardTitle className="text-sm">覆盖度</CardTitle>
        <CardDescription className="text-xs">
          {coverage
            ? coverage.scope === "task"
              ? "任务范围内资产的测试覆盖（已测 = 被事实锚点覆盖）"
              : "当前视图内资产的测试覆盖（已测 = 被事实锚点覆盖）"
            : "已测 = 被事实锚点覆盖的资产"}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-4 px-4">
        <div className="min-w-[12rem] flex-1">
          <Progress value={pct} className={cn("h-1.5", loading && "opacity-60")} />
          <div className="mt-1.5 flex items-center gap-3 text-xs text-muted-foreground">
            <span>
              已测 <span className="font-semibold tabular-nums text-foreground">{tested}</span>
            </span>
            <span>
              未测 <span className="font-semibold tabular-nums text-foreground">{untested}</span>
            </span>
            <span>
              共 <span className="font-semibold tabular-nums text-foreground">{total}</span>
            </span>
            <span className="tabular-nums">{pct}%</span>
          </div>
        </div>
        <label htmlFor="coverage-untested" className="flex cursor-pointer items-center gap-2 text-xs">
          <Switch id="coverage-untested" checked={untestedOnly} onCheckedChange={onUntestedOnlyChange} size="sm" />
          只看未测
        </label>
      </CardContent>
    </Card>
  );
}

// =====================================================================
// POC 联动
// =====================================================================

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
  high: "bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-300",
  medium: "bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300",
  low: "bg-sky-100 text-sky-700 dark:bg-sky-950 dark:text-sky-300",
  info: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
};

const TIER_CLASS: Record<string, string> = {
  A: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
  B: "bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-300",
  C: "bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300",
  D: "bg-sky-100 text-sky-700 dark:bg-sky-950 dark:text-sky-300",
  E: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
};

// PocMatchDialog 展示指纹 → POC 的候选模板。
//
// 「验证」按钮把目标与模板带到 Nuclei 页面的自动匹配区：
//   /function/nuclei/?target=<目标>&templates=<模板 id>&asset_ids=<资产 id>
function PocMatchDialog({
  open,
  onOpenChange,
  loading,
  result,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  loading: boolean;
  result: PocMatchResult | null;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlertIcon className="size-4" /> POC 联动
          </DialogTitle>
          <DialogDescription>
            按资产指纹（技术栈 / 标题 / 服务名）反查 Nuclei 模板，只放行 high / critical / medium 且与
            RCE、文件上传、反序列化、命令注入、SQL 注入相关的模板。
          </DialogDescription>
        </DialogHeader>
        <div className="max-h-[60vh] overflow-auto">
          {loading ? (
            <p className="py-10 text-center text-sm text-muted-foreground">匹配中…</p>
          ) : !result ? (
            <p className="py-10 text-center text-sm text-muted-foreground">暂无结果。</p>
          ) : result.candidates.length === 0 ? (
            <p className="py-10 text-center text-sm text-muted-foreground">
              没有匹配的 POC 候选（模板库扫描 {result.templates_scanned} 个，命中可用类别 {result.templates_eligible}{" "}
              个）。
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>严重度</TableHead>
                  <TableHead>模板</TableHead>
                  <TableHead>命中指纹</TableHead>
                  <TableHead>目标</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.candidates.map((c) => (
                  <PocCandidateRow key={`${c.asset_id}-${c.template_id}`} candidate={c} />
                ))}
              </TableBody>
            </Table>
          )}
        </div>
        <DialogFooter>
          {result && result.candidates.length > 0 && (
            <span className="mr-auto self-center text-xs text-muted-foreground">
              共 {result.total} 个候选
              {result.total > result.candidates.length ? `，显示前 ${result.candidates.length} 个` : ""}
            </span>
          )}
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            关闭
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PocCandidateRow({ candidate }: { candidate: PocCandidate }) {
  const href = `/function/nuclei/?${new URLSearchParams({
    target: candidate.target,
    templates: candidate.template_id,
    asset_ids: String(candidate.asset_id),
  }).toString()}`;
  return (
    <TableRow>
      <TableCell>
        <div className="flex flex-col gap-1">
          <span
            className={cn(
              "inline-block w-fit rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase",
              SEVERITY_CLASS[candidate.severity] ?? "bg-muted text-muted-foreground",
            )}
          >
            {candidate.severity}
          </span>
          <span
            className={cn(
              "inline-block w-fit rounded px-1.5 py-0.5 text-[10px] font-semibold",
              TIER_CLASS[candidate.tier] ?? "bg-muted text-muted-foreground",
            )}
            title={candidate.advice}
          >
            {candidate.tier} 级
          </span>
        </div>
      </TableCell>
      <TableCell>
        <div className="max-w-sm">
          <p className="truncate font-mono text-xs font-medium" title={candidate.template_id}>
            {candidate.template_id}
          </p>
          <p className="truncate text-xs text-muted-foreground" title={candidate.name}>
            {candidate.name || "—"}
          </p>
          <p className="truncate font-mono text-[10px] text-muted-foreground" title={candidate.tier_label}>
            {candidate.tier_label}
          </p>
        </div>
      </TableCell>
      <TableCell>
        <Chips items={candidate.matched ?? []} mono />
      </TableCell>
      <TableCell>
        <span className="block max-w-[16rem] truncate font-mono text-xs" title={candidate.target}>
          {candidate.target || candidate.asset_label}
        </span>
      </TableCell>
      <TableCell className="text-right">
        <Button asChild size="sm" variant="outline">
          <Link href={href}>
            <ShieldAlertIcon className="size-3.5" /> 验证
          </Link>
        </Button>
      </TableCell>
    </TableRow>
  );
}

// csvCell 转义 CSV 单元格（引号 / 逗号 / 换行）。
function csvCell(value: string | number): string {
  const text = value == null ? "" : String(value);
  if (/[",\n\r]/.test(text)) {
    return `"${text.replaceAll('"', '""')}"`;
  }
  return text;
}
