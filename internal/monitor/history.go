package monitor

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kilasos/kilasos/internal/storage"
)

const (
	historyMax     = 120
	sampleInterval = 15 * time.Second
)

type PoolSample struct {
	Name    string  `json:"name"`
	UsedPct float64 `json:"used_pct"`
	Used    int64   `json:"used"`
	Total   int64   `json:"total"`
}

type MetricSample struct {
	Time          int64        `json:"time"`
	CPU           float64      `json:"cpu"`
	MemPct        float64      `json:"mem_pct"`
	RxBytesPerSec float64      `json:"rx_bps"`
	TxBytesPerSec float64      `json:"tx_bps"`
	Pools         []PoolSample `json:"pools,omitempty"`
}

type MetricsHistory struct {
	mu      sync.RWMutex
	samples []MetricSample
}

func NewMetricsHistory() *MetricsHistory {
	return &MetricsHistory{}
}

func (h *MetricsHistory) Start(ctx context.Context, p storage.Provider) {
	go func() {
		h.sample(ctx, p)
		t := time.NewTicker(sampleInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.sample(ctx, p)
			}
		}
	}()
}

func (h *MetricsHistory) Add(s MetricSample) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.samples = append(h.samples, s)
	if len(h.samples) > historyMax {
		h.samples = h.samples[len(h.samples)-historyMax:]
	}
}

func (h *MetricsHistory) Samples() []MetricSample {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]MetricSample, len(h.samples))
	copy(out, h.samples)
	return out
}

func (h *MetricsHistory) sample(ctx context.Context, p storage.Provider) {
	m, err := p.Metrics(ctx)
	if err != nil {
		slog.Error("metrics sample failed", "err", err)
		return
	}
	memPct := 0.0
	if m.MemTotal > 0 {
		memPct = float64(m.MemUsed) / float64(m.MemTotal) * 100
	}
	var rx, tx float64
	for _, iface := range m.NetInterfaces {
		rx += iface.RxBytesPerSec
		tx += iface.TxBytesPerSec
	}
	var pools []PoolSample
	for _, pu := range m.PoolUsage {
		pct := 0.0
		if pu.Total > 0 {
			pct = float64(pu.Used) / float64(pu.Total) * 100
		}
		pools = append(pools, PoolSample{Name: pu.Name, UsedPct: pct, Used: pu.Used, Total: pu.Total})
	}
	h.Add(MetricSample{
		Time:          time.Now().Unix(),
		CPU:           m.CPUPercent,
		MemPct:        memPct,
		RxBytesPerSec: rx,
		TxBytesPerSec: tx,
		Pools:         pools,
	})
}
