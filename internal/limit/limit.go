package limit

import (
	"sync"
	"time"
)

type entry struct {
	tokens   float64
	at       time.Time
	failures int
	until    time.Time
}
type Limiter struct {
	mu      sync.Mutex
	entries map[string]entry
	Clock   func() time.Time
}

func New() *Limiter { return &Limiter{entries: map[string]entry{}, Clock: time.Now} }
func (l *Limiter) Allow(key string, rate float64, burst float64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Clock()
	if len(l.entries) > 10000 {
		for k, v := range l.entries {
			if now.Sub(v.at) > time.Hour {
				delete(l.entries, k)
			}
		}
		if len(l.entries) > 10000 {
			return time.Minute
		}
	}
	e, ok := l.entries[key]
	if !ok {
		e = entry{tokens: burst, at: now}
	}
	e.tokens += now.Sub(e.at).Seconds() * rate
	if e.tokens > burst {
		e.tokens = burst
	}
	e.at = now
	if e.until.After(now) {
		l.entries[key] = e
		return e.until.Sub(now)
	}
	if e.tokens < 1 {
		l.entries[key] = e
		return time.Duration((1 - e.tokens) / rate * float64(time.Second))
	}
	e.tokens--
	l.entries[key] = e
	return 0
}
func (l *Limiter) Failure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	e.failures++
	e.at = l.Clock()
	if e.failures >= 5 {
		e.until = e.at.Add(15 * time.Minute)
	} else {
		e.until = e.at.Add(time.Duration(1<<uint(e.failures-1)) * time.Second)
	}
	l.entries[key] = e
}
func (l *Limiter) Success(key string) { l.mu.Lock(); defer l.mu.Unlock(); delete(l.entries, key) }
