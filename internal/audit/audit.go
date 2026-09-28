// Package audit records send metadata and prunes it after the retention period.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/tut1vog/email-me/internal/store"
)

type Writer struct {
	st         *store.Store
	logSubject bool
	log        *slog.Logger
}

func NewWriter(st *store.Store, logSubject bool, log *slog.Logger) *Writer {
	return &Writer{st: st, logSubject: logSubject, log: log}
}

// Record stores an audit row. The subject is dropped unless audit.log_subject
// is enabled. Failures are logged, never surfaced to the agent.
func (w *Writer) Record(ctx context.Context, e *store.AuditEntry) {
	if !w.logSubject {
		e.Subject = ""
	}
	// Use a detached context: the row must be written even if the client
	// disconnected after the upstream accepted the message.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := w.st.InsertAudit(ctx, e); err != nil {
		w.log.Error("writing audit row", "err", err, "agent_id", e.AgentID, "status", e.Status)
	}
}

// RunRetention prunes rows older than the retention period, hourly, until ctx ends.
func RunRetention(ctx context.Context, st *store.Store, retention time.Duration, log *slog.Logger) {
	prune := func() {
		n, err := st.PruneAudit(ctx, time.Now().Add(-retention))
		if err != nil {
			log.Error("pruning audit log", "err", err)
		} else if n > 0 {
			log.Info("pruned audit log", "rows", n)
		}
	}
	prune()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}
