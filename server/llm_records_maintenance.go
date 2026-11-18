package server

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

// LLM 调用记录会随任务量线性增长：每次调用都写一行，正文是整段 prompt。一个
// 忙碌的任务日就能写进几万行、几十 GB——曾经把数据盘写满，连带 PostgreSQL
// 掉进崩溃循环，整个后端都连不上。这里做两件事：
//
//  1. 保留窗口：默认只留 3 天，超期删除（0 = 永久保留）；
//  2. 回收空间：DELETE 只是把行标成死元组，文件不会变小，必须 VACUUM FULL
//     才会把空间还给文件系统——这正是那张表能涨到 45GB TOAST 的原因。
//
// 同时盯着数据盘水位：低于阈值时记一条 error/告警，日志里第一时间能看到，
// 不用等用户来说"连不上后端"。
const (
	llmRecordSweepInterval = 30 * time.Minute

	// defaultLLMRecordsRetentionDays 调用记录默认保留天数。
	defaultLLMRecordsRetentionDays = 3
	// defaultLLMRecordMaxBodyKB 单条正文默认保留上限（KB）。
	defaultLLMRecordMaxBodyKB = 16

	// llmRecordsVacuumThreshold 表体积超过这个值才值得 VACUUM 一次。
	llmRecordsVacuumThreshold = 1 << 30
	// llmRecordsVacuumMinFree VACUUM FULL 需要临时空间（大约是表的体积），
	// 磁盘不够时宁可不回收，也不能把盘写满。
	llmRecordsVacuumMinFree = 2 << 30
	// llmRecordsVacuumMinInterval 两次回收之间的最小间隔。VACUUM FULL 是重活，
	// 不值得反复做。
	llmRecordsVacuumMinInterval = 6 * time.Hour
	// llmRecordsFirstSweepDelay 启动后先等一会儿再扫：启动那阵子数据库最忙，
	// 不跟业务抢锁。
	llmRecordsFirstSweepDelay = 2 * time.Minute

	// diskWarnFreeRatio / diskCriticalFreeRatio 数据盘剩余水位告警阈值。
	diskWarnFreeRatio     = 0.15
	diskCriticalFreeRatio = 0.08
)

// startLLMRecordsMaintenance 启动后台保留策略：定期清理超期的调用记录，
// 必要时把空间还给文件系统，并检查数据盘水位。
func (s *Server) startLLMRecordsMaintenance() {
	s.archiveWG.Add(1)
	go func() {
		defer s.archiveWG.Done()
		// 启动后先等一会儿再扫：上一次进程被杀时往往还留着该清的行，
		// 但启动那阵子数据库最忙，别跟业务抢锁。
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(llmRecordsFirstSweepDelay):
		}
		s.sweepLLMRecords()
		ticker := time.NewTicker(llmRecordSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.sweepLLMRecords()
			}
		}
	}()
}

// sweepLLMRecords 执行一次保留策略维护。
func (s *Server) sweepLLMRecords() {
	pg := s.m.PG()
	if pg == nil {
		return
	}
	if days := s.m.LLMRecordsRetentionDays(); days > 0 {
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		n, err := pg.PruneLLMRecords(cutoff)
		if err != nil {
			log.Printf("[llm-records] 清理超期记录失败: %v", err)
		} else if n > 0 {
			log.Printf("[llm-records] 已清理 %d 条超过 %d 天的调用记录", n, days)
		}
	}
	size, err := pg.LLMRecordsSize()
	if err != nil {
		log.Printf("[llm-records] 读取表体积失败: %v", err)
		return
	}
	free, total := diskFree(s.m.dir)
	if size > llmRecordsVacuumThreshold && free > llmRecordsVacuumMinFree+size {
		if err := vacuumLLMRecords(pg); err != nil {
			log.Printf("[llm-records] 回收表空间跳过: %v", err)
		} else {
			free, _ = diskFree(s.m.dir)
			log.Printf("[llm-records] 已回收表空间（原 %s，可用 %s）", humanBytes(size), humanBytes(free))
		}
	}
	if total > 0 {
		ratio := float64(free) / float64(total)
		switch {
		case ratio < diskCriticalFreeRatio:
			log.Printf("[llm-records] 严重告警：数据盘剩余空间不足 %.1f%%（可用 %s / 共 %s）", ratio*100, humanBytes(free), humanBytes(total))
		case ratio < diskWarnFreeRatio:
			log.Printf("[llm-records] 告警：数据盘剩余空间偏低（%.1f%%，可用 %s / 共 %s）", ratio*100, humanBytes(free), humanBytes(total))
		}
	}
}

// llmRecordsLastVacuum 记录上一次回收的时间戳（unix 秒），用来给两次回收拉开间隔。
var llmRecordsLastVacuum atomic.Int64

// vacuumLLMRecords 重写 llm_records，把删掉的空间还给文件系统。
//
// VACUUM FULL 要 ACCESS EXCLUSIVE 锁，会挡住正在写的会话，所以这里给它一个很短的
// lock_timeout：抢不到锁就放弃这一轮（下一轮再来），绝不把别人的写入卡住。
func vacuumLLMRecords(pg *pgdb.DB) error {
	last := llmRecordsLastVacuum.Load()
	if last > 0 && time.Since(time.Unix(last, 0)) < llmRecordsVacuumMinInterval {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	conn, err := pg.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SET lock_timeout = '5s'`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `VACUUM FULL llm_records`); err != nil {
		return err
	}
	llmRecordsLastVacuum.Store(time.Now().Unix())
	return nil
}
