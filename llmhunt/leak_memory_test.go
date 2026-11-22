package llmhunt

import (
	"strconv"
	"testing"
	"time"
)

// TestLeakAlreadyHandled 锁住跨轮记忆的关键语义：**只有真正抓成功过的** URL
// 才算"已处理"。
//
// 旧实现在"收集候选"阶段就把 URL 标记为已抓过，而 Hunter/Quake 查的是静态
// 数据集，每轮返回同一批 URL —— 于是第 1 轮之后候选集被自己清空，后面每一轮
// 都是"抓取 0 个 URL"（线上实测连续空转 477 轮），白烧测绘配额还被限流。
func TestLeakAlreadyHandled(t *testing.T) {
	s := &Scanner{seenLeak: map[string]time.Time{}}

	// 刚收集到、还没抓过的候选：不算已处理，下一轮还会再取。
	if s.leakAlreadyHandled("http://a.example/.env") {
		t.Fatal("a candidate that was never fetched must not count as handled")
	}

	// 抓成功过 → 算已处理，不再重复发请求。
	s.markLeakHandled("http://a.example/.env")
	if !s.leakAlreadyHandled("http://a.example/.env") {
		t.Fatal("a successfully fetched url must count as handled")
	}

	// 超过 TTL → 允许重抓（泄漏页面会更新）。
	s.mu.Lock()
	s.seenLeak["http://b.example/.env"] = time.Now().Add(-leakSeenTTL - time.Minute)
	s.mu.Unlock()
	if s.leakAlreadyHandled("http://b.example/.env") {
		t.Fatal("an expired entry must be re-fetchable")
	}
}

// TestPruneSeenLeakDropsExpired 锁住 TTL 修剪：过期条目要能被剪掉。
func TestPruneSeenLeakDropsExpired(t *testing.T) {
	s := &Scanner{seenLeak: map[string]time.Time{
		"http://old.example/.env": time.Now().Add(-leakSeenTTL - time.Hour),
		"http://new.example/.env": time.Now(),
	}}
	s.pruneSeenLeak()
	if _, ok := s.seenLeak["http://old.example/.env"]; ok {
		t.Fatal("expired entry must be pruned")
	}
	if _, ok := s.seenLeak["http://new.example/.env"]; !ok {
		t.Fatal("fresh entry must be kept")
	}
}

// TestPruneSeenLeakCapsSize 锁住记忆表上限：超过上限要砍掉最旧的一半，
// 否则每轮收集候选都要全表扫描。
func TestPruneSeenLeakCapsSize(t *testing.T) {
	s := &Scanner{seenLeak: map[string]time.Time{}}
	base := time.Now()
	for i := 0; i < leakSeenMax+50; i++ {
		s.seenLeak["u"+strconv.Itoa(i)] = base.Add(time.Duration(i) * time.Second)
	}
	s.pruneSeenLeak()
	if len(s.seenLeak) > leakSeenMax {
		t.Fatalf("memory not capped: %d > %d", len(s.seenLeak), leakSeenMax)
	}
}
