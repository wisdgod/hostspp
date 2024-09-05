package metrics

import (
	"sync"
	"time"
)

type Metrics struct {
	RequestCount      int64
	SuccessCount      int64
	FailureCount      int64
	TotalResponseTime time.Duration
	mu                sync.Mutex
}

var (
	instance *Metrics
	once     sync.Once
)

func GetInstance() *Metrics {
	once.Do(func() {
		instance = &Metrics{}
	})
	return instance
}

func (m *Metrics) IncrementRequestCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestCount++
}

func (m *Metrics) IncrementSuccessCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SuccessCount++
}

func (m *Metrics) IncrementFailureCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FailureCount++
}

func (m *Metrics) AddResponseTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalResponseTime += duration
}

func (m *Metrics) GetStats() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	avgResponseTime := float64(m.TotalResponseTime) / float64(time.Millisecond) / float64(m.RequestCount)
	return map[string]interface{}{
		"total_requests":       m.RequestCount,
		"successful_requests":  m.SuccessCount,
		"failed_requests":      m.FailureCount,
		"avg_response_time_ms": avgResponseTime,
	}
}
