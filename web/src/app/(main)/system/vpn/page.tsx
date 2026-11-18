"use client";

// VPN 出口独立成页：这是"任务从哪个地址出去"的开关，埋在系统配置的长列表里
// 没人找得到。上传 .ovpn、填默认账号、连接并确认实测出口 IP 都在这页完成。

import * as React from "react";
import { ShieldCheckIcon } from "lucide-react";

import { VpnEgressPanel } from "@/components/vpn-egress-panel";

export default function VpnPage() {
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center gap-2">
        <ShieldCheckIcon className="size-5 text-muted-foreground" />
        <h1 className="text-xl font-semibold tracking-tight">VPN 出口</h1>
      </div>
      <p className="text-sm text-muted-foreground">
        这里管理平台（360 众测、漏洞盒子等）发的 OpenVPN 配置。新建任务时在「出口」里选一条，
        该任务的出网流量就走这条隧道；账号密码按项目填在任务里，因为每个项目的凭据不同。
      </p>
      <VpnEgressPanel />
    </div>
  );
}
