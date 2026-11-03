package device

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// 本文件把「移动端设备接入」暴露成 host 工具：和流量工具（traffic）同一层级——
// 不依赖任务上下文，任何绑定了这些工具的 agent 都能直接调用。
// 工具的 key（device_list / device_shell …）与 handler 死绑，tools 表只改说明与绑定。

const (
	toolList        = "device_list"
	toolConnect     = "device_connect"
	toolDisconnect  = "device_disconnect"
	toolInfo        = "device_info"
	toolShell       = "device_shell"
	toolScreenshot  = "device_screenshot"
	toolInstall     = "device_install"
	toolUninstall   = "device_uninstall"
	toolPull        = "device_pull"
	toolPush        = "device_push"
	toolLogs        = "device_logs"
	toolForward     = "device_forward"
	toolProxy       = "device_proxy"
	toolUI          = "device_ui"
	toolMiniOpen    = "mini_open"
	toolMiniInspect = "mini_inspect"

	toolCaptureStart  = "device_capture_start"
	toolCaptureStatus = "device_capture_status"
	toolCapturePull   = "device_capture_pull"

	toolApps     = "device_apps"
	toolAppStart = "device_app_start"
	toolAppInfo  = "device_app_info"
	toolURLOpen  = "device_url_open"
)

func objSchema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func strParam(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func intParam(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func roTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: desc,
		Schema:      schema,
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision { return permission.Allowed() },
		Run:         run,
	})
}

func wrTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: desc,
		Schema:      schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision { return permission.Allowed() },
		Run:         run,
	})
}

func jsonToolResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// Tools 返回移动端设备接入的 host 工具集。
func (h *Hub) Tools() []actool.CoreTool {
	return []actool.CoreTool{
		h.toolList(),
		h.toolConnect(),
		h.toolDisconnect(),
		h.toolInfo(),
		h.toolShell(),
		h.toolScreenshot(),
		h.toolInstall(),
		h.toolUninstall(),
		h.toolPull(),
		h.toolPush(),
		h.toolLogs(),
		h.toolForward(),
		h.toolProxy(),
		h.toolUI(),
		h.toolMiniOpen(),
		h.toolMiniInspect(),
		h.toolCaptureStart(),
		h.toolCaptureStatus(),
		h.toolCapturePull(),
		h.toolApps(),
		h.toolAppStart(),
		h.toolAppInfo(),
		h.toolURLOnOpen(),
	}
}

// SeedToolMetas 返回在「零值 Hub」上构建的工具，仅用于播种 tools 表的元数据。
// handler 闭包捕获了这个 Hub，但 seed 实例永不被调用，故安全。
func SeedToolMetas() []actool.CoreTool { return NewHub(nil).Tools() }

func (h *Hub) toolList() actool.CoreTool {
	return roTool(toolList,
		"列出已接入 ARTEX 的移动设备（Android via ADB、iOS via libimobiledevice、以及回连的接入代理设备）。返回 id/platform/state/model/name/transport 等。做移动端测试前先调它拿 device id。",
		objSchema(map[string]any{
			"platform": strParam("按平台过滤：android / ios；省略 = 全部"),
		}),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Platform string }
			_ = json.Unmarshal(in, &a)
			devs := h.List(ctx)
			if p := strings.TrimSpace(a.Platform); p != "" {
				filtered := devs[:0:0]
				for _, d := range devs {
					if string(d.Platform) == p {
						filtered = append(filtered, d)
					}
				}
				devs = filtered
			}
			if len(devs) == 0 {
				return actool.Text("没有已接入的设备。先用 device_connect 接入 Android（adb connect）或让设备跑 artex-device-agent 接入代理。"), nil
			}
			return jsonToolResult(devs)
		})
}

func (h *Hub) toolConnect() actool.CoreTool {
	return wrTool(toolConnect,
		"接入一台设备。platform=android 时 address 填手机 IP:端口（无线调试）或 serial（USB 直连，宿主机 adb server 需已识别）；platform=ios 时 address 填 UDID（宿主机需能访问 usbmux）。接入后设备进入登记表，可用 device_list 确认。",
		objSchema(map[string]any{
			"platform": strParam("android 或 ios"),
			"address":  strParam("Android: IP:端口（如 192.168.1.7:5555）或 serial；iOS: UDID"),
			"name":     strParam("给设备起的名字（可选）"),
			"note":     strParam("备注（可选）"),
		}, "platform", "address"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Platform, Address, Name, Note string }
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			d, err := h.Connect(ctx, Platform(strings.TrimSpace(a.Platform)), a.Address, a.Name, a.Note)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonToolResult(d)
		})
}

func (h *Hub) toolDisconnect() actool.CoreTool {
	return wrTool(toolDisconnect,
		"把一台设备从登记表移除（不会真的断开 USB/网络连接）。",
		objSchema(map[string]any{"device": strParam("设备 id / serial / udid")}, "device"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device string }
			_ = json.Unmarshal(in, &a)
			if err := h.Disconnect(a.Device); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("已移除设备 " + a.Device), nil
		})
}

func (h *Hub) toolInfo() actool.CoreTool {
	return roTool(toolInfo,
		"取设备详细信息：机型/系统版本/屏幕尺寸/已安装第三方应用（Android），或机型/系统/电量等（iOS）。做静态与动态分析前先看清目标环境。",
		objSchema(map[string]any{"device": strParam("设备 id / serial / udid")}, "device"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device string }
			_ = json.Unmarshal(in, &a)
			info, err := h.Info(ctx, a.Device)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonToolResult(info)
		})
}

func (h *Hub) toolShell() actool.CoreTool {
	return wrTool(toolShell,
		"在设备上执行一条 shell 命令（Android 走 adb shell；接入代理设备走设备本机 shell；iOS 需越狱并已配好 SSH）。用于读配置、看进程、跑自带工具。返回 stdout 与退出码。",
		objSchema(map[string]any{
			"device":   strParam("设备 id / serial / udid"),
			"cmd":      strParam("要执行的命令"),
			"timeout":  intParam("超时秒数（默认 60）"),
			"max_chars": intParam("最多返回字符数（默认 8000）"),
		}, "device", "cmd"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Device   string
				Cmd      string
				Timeout  int
				MaxChars int
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Cmd) == "" {
				return actool.Errorf("cmd 为必填参数"), nil
			}
			timeout := a.Timeout
			if timeout <= 0 {
				timeout = 60
			}
			cctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer cancel()
			out, err := h.Shell(cctx, a.Device, a.Cmd)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(clipText(out, a.MaxChars)), nil
		})
}

func (h *Hub) toolScreenshot() actool.CoreTool {
	return roTool(toolScreenshot,
		"给设备截屏并保存为 PNG，返回文件路径。用于留证（配合 report_finding 的 evidence）。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"name":   strParam("文件名（不含扩展名，默认 screenshot）"),
		}, "device"),
		func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Name string }
			_ = json.Unmarshal(in, &a)
			data, err := h.Screenshot(ctx, a.Device)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dir := tc.OutputDir
			if dir == "" {
				dir = tc.WorkingDir
			}
			if dir == "" {
				dir = "."
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			name := strings.TrimSpace(a.Name)
			if name == "" {
				name = "screenshot"
			}
			path := filepath.Join(dir, name+".png")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("截图已保存: %s（%d 字节）", path, len(data))), nil
		})
}

func (h *Hub) toolInstall() actool.CoreTool {
	return wrTool(toolInstall,
		"给设备安装应用包（Android: APK 绝对路径；iOS: IPA 绝对路径）。安装前先确认该包确实来自被测目标。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"path":   strParam("安装包在 ARTEX 主机上的绝对路径"),
		}, "device", "path"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Path string }
			_ = json.Unmarshal(in, &a)
			out, err := h.Install(ctx, a.Device, a.Path)
			if err != nil {
				return actool.Errorf(err.Error()+"\n"+clipText(out, 2000)), nil
			}
			return actool.Text(clipText(out, 4000)), nil
		})
}

func (h *Hub) toolUninstall() actool.CoreTool {
	return wrTool(toolUninstall,
		"卸载设备上的应用（Android: 包名；iOS: bundle id）。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"pkg":    strParam("包名 / bundle id"),
		}, "device", "pkg"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Pkg string }
			_ = json.Unmarshal(in, &a)
			out, err := h.Uninstall(ctx, a.Device, a.Pkg)
			if err != nil {
				return actool.Errorf(err.Error()+"\n"+clipText(out, 2000)), nil
			}
			return actool.Text(clipText(out, 4000)), nil
		})
}

func (h *Hub) toolPull() actool.CoreTool {
	return wrTool(toolPull,
		"从设备拉取文件到 ARTEX 主机目录（Android via ADB）。用于取 APK、配置、数据库、证书等证据。返回落地路径。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"remote": strParam("设备上的文件路径"),
			"dest":   strParam("落地目录（默认当前工作目录）"),
		}, "device", "remote"),
		func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Remote, Dest string }
			_ = json.Unmarshal(in, &a)
			dest := strings.TrimSpace(a.Dest)
			if dest == "" {
				dest = tc.WorkingDir
			}
			if dest == "" {
				dest = "."
			}
			path, err := h.Pull(ctx, a.Device, a.Remote, dest)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("已拉取: " + path), nil
		})
}

func (h *Hub) toolPush() actool.CoreTool {
	return wrTool(toolPush,
		"把 ARTEX 主机上的文件推到设备（Android via ADB）。用于投放测试脚本、Frida 脚本、证书等。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"local":  strParam("主机上的文件绝对路径"),
			"remote": strParam("设备上的目标路径"),
		}, "device", "local", "remote"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Local, Remote string }
			_ = json.Unmarshal(in, &a)
			out, err := h.Push(ctx, a.Device, a.Local, a.Remote)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("已推送: " + out), nil
		})
}

func (h *Hub) toolLogs() actool.CoreTool {
	return roTool(toolLogs,
		"采集设备日志（Android: logcat；iOS: syslog）。用于找崩溃、敏感信息、明文流量线索。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"filter": strParam("过滤关键字（Android 为 logcat 参数，如 'AndroidRuntime:E *:S'；iOS 为 syslog 匹配）"),
			"lines":  intParam("返回行数（默认 200）"),
		}, "device"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Device string
				Filter string
				Lines  int
			}
			_ = json.Unmarshal(in, &a)
			out, err := h.Logs(ctx, a.Device, a.Filter, a.Lines)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(clipText(out, 12000)), nil
		})
}

func (h *Hub) toolForward() actool.CoreTool {
	return wrTool(toolForward,
		"给设备做端口转发。direction=reverse 时手机侧的 127.0.0.1:<device_port> 流量会从宿主 <host_port> 进来——这是把手机流量接入 ARTEX 记录代理的标准做法（配合 device_proxy）。",
		objSchema(map[string]any{
			"device":    strParam("设备 id / serial / udid"),
			"direction": strParam("reverse（设备→主机，默认）或 forward（主机→设备）"),
			"local":     strParam("主机侧端口（reverse 模式下即设备要连的端口对应的宿主端口）"),
			"remote":    strParam("设备侧端口（默认 8080 之类按需填写）"),
		}, "device", "local", "remote"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Direction, Local, Remote string }
			_ = json.Unmarshal(in, &a)
			if err := h.Forward(ctx, a.Device, a.Direction, a.Local, a.Remote); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("已建立 %s 转发: %s <-> %s", a.Direction, a.Local, a.Remote)), nil
		})
}

func (h *Hub) toolProxy() actool.CoreTool {
	return wrTool(toolProxy,
		"把设备的系统代理指向 ARTEX 的记录代理（action=set），或清除代理（action=clear）。set 时需要 proxy_addr 形如 192.168.1.10:8788——必须是手机能访问到的宿主机地址；配合 device_forward(reverse) 与 CA 证书安装即可解出 HTTPS 明文。",
		objSchema(map[string]any{
			"device":     strParam("设备 id / serial / udid"),
			"action":     strParam("set 或 clear"),
			"proxy_addr": strParam("代理地址 host:port（action=set 时必填）"),
			"ca_path":    strParam("ARTEX 记录代理的 CA 证书路径（可选，返回给操作者以便安装到设备）"),
		}, "device", "action"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Action, ProxyAddr, CAPath string }
			_ = json.Unmarshal(in, &a)
			switch strings.ToLower(strings.TrimSpace(a.Action)) {
			case "clear":
				out, err := h.ClearProxy(ctx, a.Device)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return actool.Text(clipText(out, 2000)), nil
			default:
				out, err := h.SetProxy(ctx, a.Device, a.ProxyAddr, a.CAPath)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return actool.Text(clipText(out, 2000)), nil
			}
		})
}

func (h *Hub) toolUI() actool.CoreTool {
	return roTool(toolUI,
		"导出设备当前界面结构（Android uiautomator dump，XML）。用于定位控件、确认当前页面、找入口。",
		objSchema(map[string]any{"device": strParam("设备 id / serial / udid")}, "device"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device string }
			_ = json.Unmarshal(in, &a)
			out, err := h.UIDump(ctx, a.Device)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(clipText(out, 12000)), nil
		})
}

func (h *Hub) toolMiniOpen() actool.CoreTool {
	return wrTool(toolMiniOpen,
		"在 Android 设备上打开微信小程序（target 传小程序页面链接，如 weixin://dl/business/?t=xxx，或小程序码内容）。打开后用 mini_inspect 看界面、配合 device_proxy + ARTEX 记录代理抓小程序后端接口。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"target": strParam("小程序页面链接 / scheme / 小程序标识"),
		}, "device", "target"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Target string }
			_ = json.Unmarshal(in, &a)
			out, err := h.StartActivity(ctx, a.Device, a.Target)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(clipText(out, 4000)), nil
		})
}

func (h *Hub) toolMiniInspect() actool.CoreTool {
	return roTool(toolMiniInspect,
		"采集小程序当前页面的现场信息：界面结构 XML（uiautomator）+ 截图路径 + 设备上与小程序相关的进程/日志线索。用于确认小程序已打开、定位控件、提取请求域名。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"logs":   strParam("是否附带采集小程序相关日志（true/false，默认 false）"),
		}, "device"),
		func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Device string
				Logs   bool
			}
			_ = json.Unmarshal(in, &a)
			out := map[string]any{"device": a.Device}
			if xml, err := h.UIDump(ctx, a.Device); err == nil {
				out["ui"] = clipText(xml, 8000)
			} else {
				out["ui_error"] = err.Error()
			}
			if png, err := h.Screenshot(ctx, a.Device); err == nil {
				dir := tc.OutputDir
				if dir == "" {
					dir = tc.WorkingDir
				}
				if dir == "" {
					dir = "."
				}
				_ = os.MkdirAll(dir, 0o755)
				path := filepath.Join(dir, "miniprogram.png")
				if err := os.WriteFile(path, png, 0o644); err == nil {
					out["screenshot"] = path
				}
			}
			if a.Logs {
				if logs, err := h.Logs(ctx, a.Device, "", 300); err == nil {
					out["logs"] = clipText(logs, 6000)
				}
			}
			return jsonToolResult(out)
		})
}

func (h *Hub) toolCaptureStart() actool.CoreTool {
	return wrTool(toolCaptureStart,
		"在设备上开 tcpdump 抓包（需要 root + tcpdump，当前走接入代理的 APK/agent）。抓的是整机流量，HTTPS 只能看到端点；要明文就配合 device_proxy 走 ARTEX 记录代理，或用 frida hook。抓完调 device_capture_pull 停止并取回 pcap。",
		objSchema(map[string]any{
			"device":  strParam("设备 id / serial / udid"),
			"iface":   strParam("网卡，默认 any；Wi-Fi 常用 wlan0，蜂窝常用 rmnet_data0"),
			"seconds": intParam("预计抓多久（秒，只作记录；实际由 device_capture_pull 停止）"),
		}, "device"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Device  string
				Iface   string
				Seconds int
			}
			_ = json.Unmarshal(in, &a)
			out, err := h.CaptureStart(ctx, a.Device, a.Iface, a.Seconds)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("已开始抓包（%s）\n%s", a.Iface, clipText(out, 2000))), nil
		})
}

func (h *Hub) toolCaptureStatus() actool.CoreTool {
	return roTool(toolCaptureStatus,
		"查看设备上的抓包状态：tcpdump 是否在跑、pcap 文件多大。",
		objSchema(map[string]any{"device": strParam("设备 id / serial / udid")}, "device"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device string }
			_ = json.Unmarshal(in, &a)
			out, err := h.CaptureStatus(ctx, a.Device)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(clipText(out, 4000)), nil
		})
}

func (h *Hub) toolCapturePull() actool.CoreTool {
	return wrTool(toolCapturePull,
		"停止设备上的抓包，把 pcap 拉回 ARTEX 并落盘（默认放到当前工作目录）。返回本地路径与大小，作为证据可直接引用。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"dest":   strParam("落盘目录（可选，默认当前工作目录）"),
		}, "device"),
		func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Dest string }
			_ = json.Unmarshal(in, &a)
			dir := strings.TrimSpace(a.Dest)
			if dir == "" {
				dir = tc.OutputDir
			}
			if dir == "" {
				dir = tc.WorkingDir
			}
			if dir == "" {
				dir = "."
			}
			path, size, err := h.CapturePull(ctx, a.Device, dir)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonToolResult(map[string]any{
				"path":        path,
				"bytes":       size,
				"device":      a.Device,
				"hint":        "HTTPS 是密文，pcap 里只能看到端点；明文要靠 device_proxy 走记录代理或 frida。",
			})
		})
}

func (h *Hub) toolApps() actool.CoreTool {
	return roTool(toolApps,
		"列出 Android 设备上的应用：包名 / 名称 / 版本 / 系统还是用户应用。接入代理设备走 PackageManager，不需要 root；ADB 设备走 pm。",
		objSchema(map[string]any{
			"device":      strParam("设备 id / serial / udid"),
			"third_party": map[string]any{"type": "boolean", "description": "只看第三方应用（默认 true）"},
		}, "device"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Device     string
				ThirdParty *bool `json:"third_party"`
			}
			_ = json.Unmarshal(in, &a)
			third := true
			if a.ThirdParty != nil {
				third = *a.ThirdParty
			}
			out, err := h.Apps(ctx, a.Device, third)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(clipText(out, 20000)), nil
		})
}

func (h *Hub) toolAppStart() actool.CoreTool {
	return wrTool(toolAppStart,
		"按包名启动一个应用（接入代理走 PackageManager 的启动 Intent，ADB 走 monkey）。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"pkg":    strParam("包名，如 com.tencent.mm"),
		}, "device", "pkg"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Pkg string }
			_ = json.Unmarshal(in, &a)
			out, err := h.AppStart(ctx, a.Device, a.Pkg)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(clipText(out, 4000)), nil
		})
}

func (h *Hub) toolAppInfo() actool.CoreTool {
	return roTool(toolAppInfo,
		"查看单个应用的信息：版本、安装路径（sourceDir，拉 APK 用）、UID、是否系统应用。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"pkg":    strParam("包名"),
		}, "device", "pkg"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Pkg string }
			_ = json.Unmarshal(in, &a)
			out, err := h.AppInfo(ctx, a.Device, a.Pkg)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(clipText(out, 8000)), nil
		})
}

func (h *Hub) toolURLOnOpen() actool.CoreTool {
	return wrTool(toolURLOpen,
		"在设备上打开一个 URL / scheme（微信小程序、deep link 都用它）。接入代理走 ACTION_VIEW，ADB 走 am start。",
		objSchema(map[string]any{
			"device": strParam("设备 id / serial / udid"),
			"target": strParam("URL 或 scheme，如 weixin://dl/business/?t=xxx 或 https://example.com"),
		}, "device", "target"),
		func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ Device, Target string }
			_ = json.Unmarshal(in, &a)
			out, err := h.URLOpen(ctx, a.Device, a.Target)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(clipText(out, 4000)), nil
		})
}

// clipText 按字符数裁剪输出（避免一次日志把上下文打爆）。
func clipText(s string, max int) string {
	if max <= 0 {
		max = 8000
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + fmt.Sprintf("\n…[已截断，共 %d 字符]", len(r))
}
