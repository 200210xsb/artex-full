package db

import (
	"regexp"
	"testing"
)

// TestDeleteSystemDirPattern 守住「删除系统关键目录」这条内置拦截规则。
//
// 背景：v1 的正则第一个分支是裸 "/"，导致 `rm -f /tmp/foo.log`、`rm -f
// /opt/artex/data/tasks/17/xxx/brute.log` 全部被拦——agent 连自己的临时日志都
// 清不掉（任务 17 现场实测）。V4 改成按目录边界匹配。
func TestDeleteSystemDirPattern(t *testing.T) {
	re := regexp.MustCompile(deleteSystemDirPattern)
	denied := []string{
		"rm -f /etc/passwd",
		"rm -rf /etc/nginx",
		"rm -rf /usr/local/bin",
		"rm -rf /var/log/syslog",
		"rm -rf /bin",
		"rm -rf /root",
		"rm -rf /usr",
		"rm -rf /dev/sda",
		"rm -rf /proc/1",
		"rm -rf /boot/vmlinuz",
		"rm -rf /lib/x86_64-linux-gnu",
		"rm -rf /sbin/init",
		// 常见写法变体
		"rm -fr /etc/passwd",
		"rm  -rf  /etc",
		`rm -rf "/etc/nginx"`,
		"rm -rf /etc/nginx; reboot",
		// 目录本身（后面是边界）
		"rm -rf /etc",
	}
	for _, cmd := range denied {
		if !re.MatchString(cmd) {
			t.Errorf("应拦但没拦: %q", cmd)
		}
	}

	allowed := []string{
		// agent 自己的工作区，清自己的临时文件是正常操作
		"rm -f /opt/artex/data/tasks/17/i2575/ifmgr_brute.log",
		"rm -f /opt/artex/data/tasks/17/i2575/ifmgr_brute.log /opt/artex/data/tasks/17/i2575/ifmgr_brute_run.log",
		"rm -rf /opt/artex/data/tasks/17/i2535",
		"rm /opt/artex/data/tasks/17/x.log",
		// 普通临时文件
		"rm -f /tmp/foo.log",
		"rm -rf /tmp/build",
		// 前缀相同的普通目录，不该误伤
		"rm -rf /variable",
		"rm -rf /etcetera",
		"rm -rf /usrshare",
		"rm -rf /development",
	}
	for _, cmd := range allowed {
		if re.MatchString(cmd) {
			t.Errorf("不该拦但拦了: %q", cmd)
		}
	}
}
