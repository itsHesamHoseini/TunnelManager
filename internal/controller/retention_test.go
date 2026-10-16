package controller

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRetentionKeepsObservedAveragesAndGaps(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved)VALUES('n','Synthetic','foreign',$1,true)", make([]byte, 32))
	base := time.Now().UTC().Truncate(24 * time.Hour).Add(-12 * time.Hour)
	for _, v := range []struct {
		at  time.Time
		cpu float64
	}{{base, 10}, {base.Add(time.Minute), 30}, {base.Add(-3 * time.Hour), 80}, {base.Add(-10 * 24 * time.Hour), 40}} {
		raw, _ := json.Marshal(map[string]any{"cpu_percent": v.cpu, "ram_used": 100, "ram_total": 1000, "disk_free": 10000})
		s.DB.Exec(ctx, "INSERT INTO measurements(node_id,at,data)VALUES('n',$1,$2)", v.at, raw)
	}
	if e := s.retain(ctx); e != nil {
		t.Fatal(e)
	}
	var count int
	var raw []byte
	s.DB.QueryRow(ctx, "SELECT count(*) FROM measurement_rollups WHERE node_id='n'").Scan(&count)
	if count != 3 {
		t.Fatal("missing intervals were interpolated or observations dropped")
	}
	s.DB.QueryRow(ctx, "SELECT data FROM measurement_rollups WHERE node_id='n' AND at=$1", base).Scan(&raw)
	var data struct {
		CPU     float64 `json:"cpu_percent"`
		Samples int     `json:"samples"`
	}
	json.Unmarshal(raw, &data)
	if data.CPU != 20 || data.Samples != 2 {
		t.Fatal("observed average incorrect")
	}
	s.DB.QueryRow(ctx, "SELECT count(*) FROM measurements WHERE at<now()-interval '7 days'").Scan(&count)
	if count != 0 {
		t.Fatal("raw sample retention failed")
	}
	if e := s.retain(ctx); e != nil {
		t.Fatal("repeat retention failed", e)
	}
	s.DB.QueryRow(ctx, "SELECT count(*) FROM measurement_rollups WHERE node_id='n'").Scan(&count)
	if count != 3 {
		t.Fatal("repeated rollup lost old observations")
	}
	r := httptest.NewRequest("GET", "/api/nodes/n/history?days=30", nil)
	r.SetPathValue("id", "n")
	w := httptest.NewRecorder()
	if !s.aggregateHistory(w, r) || w.Code != 200 {
		t.Fatal("aggregated history API failed", w.Code)
	}
	var points []struct {
		Data struct {
			CPU     float64 `json:"cpu_percent"`
			Samples int     `json:"samples"`
		} `json:"data"`
	}
	if json.Unmarshal(w.Body.Bytes(), &points) != nil || len(points) != 2 {
		t.Fatal("daily history invented missing days or lost data")
	}
	for _, point := range points {
		if point.Data.CPU != 40 {
			t.Fatal("daily CPU average was not weighted by observed sample count")
		}
	}
}
