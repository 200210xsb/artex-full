//go:build !linux

package vpn

import (
	"context"
	"errors"
)

// 非 Linux 平台没有网络命名空间，VPN 出口不可用。保留同签名实现，让上层
// （设置页、任务出口下拉）在 macOS/Windows 上仍能正常编译，只是启用时报错。

// Supported reports whether this platform can host VPN tunnels.
func Supported() bool { return false }

// CleanupStale is a no-op without network namespaces.
func (m *Manager) CleanupStale() {}

func (m *Manager) bringUp(_ context.Context, _ *instance) error { return ErrUnsupported }

func (m *Manager) teardown(inst *instance) {
	inst.socksAddr = ""
	inst.egressIP = ""
}

func probeVia(_, _ string) (string, error) { return "", ErrUnsupported }

// probeRawVia 在非 Linux 平台没有隧道可探，与 probeVia 同签名地报不支持。
func probeRawVia(_, _ string) (string, int, error) { return "", 0, ErrUnsupported }

// tunnelTrafficBytes 在非 Linux 平台没有隧道可探。
func (m *Manager) tunnelTrafficBytes(_ *instance) (uint64, bool) { return 0, false }

var _ = errors.New
