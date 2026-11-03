package server

import "testing"

// TestParseTargetRejectsFileNames pins the production failure mode: file names in
// free text ("robots.txt 静态目录泄露") used to be parsed as a host and became the
// task's only target, creating the garbage assets https://robots.txt.
func TestParseTargetRejectsFileNames(t *testing.T) {
	cases := []struct {
		name     string
		text     string
		wantOK   bool
		wantHost string
	}{
		{name: "robots note", text: "robots.txt 静态目录泄露", wantOK: false},
		{name: "index file", text: "index.php", wantOK: false},
		{name: "numeric php", text: "1.php", wantOK: false},
		{name: "readme", text: "README.md", wantOK: false},
		{name: "url", text: "https://a.example.com/x", wantOK: true, wantHost: "a.example.com"},
		{name: "ip port", text: "10.0.0.1:8080", wantOK: true, wantHost: "10.0.0.1"},
		{name: "bare domain", text: "example.com", wantOK: true, wantHost: "example.com"},
		// The file name is skipped and the real domain further in the text wins.
		{name: "file then domain", text: "先读 robots.txt 再测 ys7.com", wantOK: true, wantHost: "ys7.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, host, _, ok := parseTarget(tc.text)
			if ok != tc.wantOK {
				t.Fatalf("parseTarget(%q) ok=%v want %v (host=%q)", tc.text, ok, tc.wantOK, host)
			}
			if tc.wantOK && host != tc.wantHost {
				t.Fatalf("parseTarget(%q) host=%q want %q", tc.text, host, tc.wantHost)
			}
		})
	}
}

func TestPlausibleTargetHost(t *testing.T) {
	ok := []string{"example.com", "a.example.com", "ys7.com", "xn--fiqs8s.cn"}
	bad := []string{"", "localhost", "robots.txt", "index.php", "README.md", "a..com", ".com", "a.c"}
	for _, host := range ok {
		if !plausibleTargetHost(host) {
			t.Errorf("plausibleTargetHost(%q)=false want true", host)
		}
	}
	for _, host := range bad {
		if plausibleTargetHost(host) {
			t.Errorf("plausibleTargetHost(%q)=true want false", host)
		}
	}
}
