// Package testdb guards the database that the test suites are allowed to write to.
//
// Why this exists: the test suites create and delete rows (fixtures, cleanup by
// id, table-wide deletes). They get their DSN from the same configuration the
// running server uses — the ARTEX_PG_DSN environment variable or the config
// file. Point that at a live database and the suite will happily create
// fixtures in it and clean up rows it did not create.
//
// That is not hypothetical: pointing ARTEX_PG_DSN at the production database
// once deleted the live LLM profiles (the suite's cleanup removed the rows the
// server was using) and littered the production database with dozens of
// "task-list-metrics" style test tasks.
//
// So: refuse to hand a writable DSN to the tests unless the target database
// clearly looks like a test database. Set ARTEX_TEST_ALLOW_PROD=1 to override
// deliberately (for example when running the suite against a disposable
// snapshot whose name happens not to contain "test").
package testdb

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// AllowEnv overrides the guard. It is intentionally spelled out rather than
// inferred, so that overriding it is a conscious act.
const AllowEnv = "ARTEX_TEST_ALLOW_PROD"

// Guard returns the DSN unchanged when it is safe for tests to write to, and an
// error otherwise.
//
// A DSN is considered safe when the database name contains "test" (case
// insensitively). The system "postgres" database and the empty name are always
// rejected.
func Guard(dsn string) (string, error) {
	if os.Getenv(AllowEnv) == "1" {
		return dsn, nil
	}
	name := DatabaseName(dsn)
	if name == "" {
		return "", fmt.Errorf("DSN 里没有数据库名，无法确认是测试库")
	}
	if strings.EqualFold(name, "postgres") {
		return "", fmt.Errorf("拒绝在系统库 %q 上跑测试", name)
	}
	if !strings.Contains(strings.ToLower(name), "test") {
		return "", fmt.Errorf("拒绝在非测试库 %q 上跑测试（数据库名需包含 \"test\"；确认要跑请设 %s=1）", name, AllowEnv)
	}
	return dsn, nil
}

// DatabaseName extracts the database name from a postgres DSN. It accepts both
// URL form (postgres://user:pw@host:5432/name) and key/value form
// (host=... dbname=name). It returns "" when no name can be found.
func DatabaseName(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return ""
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return ""
		}
		return strings.TrimPrefix(u.Path, "/")
	}
	for _, kv := range strings.Fields(dsn) {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "dbname" {
			return v
		}
	}
	return ""
}
