package limit

import (
	"sync"
	"testing"
	"time"
)

func TestBurstBackoffAndRecovery(t *testing.T) {
	l := New()
	now := time.Unix(1000, 0)
	l.Clock = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if l.Allow("ip", 1, 5) != 0 {
			t.Fatal("early limit")
		}
	}
	if l.Allow("ip", 1, 5) == 0 {
		t.Fatal("missing burst limit")
	}
	for i := 0; i < 5; i++ {
		l.Failure("user")
	}
	if d := l.Allow("user", 1, 5); d != 15*time.Minute {
		t.Fatal(d)
	}
	now = now.Add(16 * time.Minute)
	if l.Allow("user", 1, 5) != 0 {
		t.Fatal("lockout did not expire")
	}
}
func TestConcurrentBudget(t *testing.T) {
	l := New()
	n := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("shared", .0001, 3) == 0 {
				mu.Lock()
				n++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if n != 3 {
		t.Fatal(n)
	}
}
