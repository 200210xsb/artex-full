package server

import "testing"

// 这些正则是在包初始化时编译的：写错一个（比如 RE2 的重复上限 1000 被越过）
// 就会在进程启动时 panic，把服务打成崩溃循环。这个测试用来把那种事故挡在部署前。
func TestDiscoveryRegexesCompile(t *testing.T) {
	for name, re := range map[string]interface{ String() string }{
		"url":    discURLRE,
		"method": discMethodRE,
		"name":   discNameRE,
		"body":   discBodyRE,
	} {
		if re == nil || re.String() == "" {
			t.Fatalf("%s regex not compiled", name)
		}
	}
}

func TestExtractBody(t *testing.T) {
	cmd := `./probe2.sh e1_getfileurl "https://x.test/base/getFileUrl" '{"remoteFileIdList":["a.bin"]}'`
	if got := extractBody(cmd); got != `{"remoteFileIdList":["a.bin"]}` {
		t.Fatalf("unexpected body: %q", got)
	}
	if got := extractBody(`curl -X POST https://x.test/a`); got != "" {
		t.Fatalf("expected empty body, got %q", got)
	}
}

func TestQueryPairs(t *testing.T) {
	got := queryPairs("https://x.test/a?b=1&c=2")
	if len(got) != 2 || got[0] != "b=1" || got[1] != "c=2" {
		t.Fatalf("unexpected pairs: %v", got)
	}
	if len(queryPairs("https://x.test/a")) != 0 {
		t.Fatal("expected no pairs")
	}
}
