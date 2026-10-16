package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) retain(ctx context.Context) error {
	days := s.settingsCopy().RetentionDays
	if days != 7 && days != 30 && days != 90 {
		days = 30
	}
	_, e := s.DB.Exec(ctx, `INSERT INTO measurement_rollups(node_id,at,data)
 SELECT node_id,date_trunc('hour',at,'UTC'),jsonb_build_object('cpu_percent',avg((data->>'cpu_percent')::double precision),'cpu_samples',count(data->>'cpu_percent'),'ram_used',avg((data->>'ram_used')::double precision),'ram_total',max((data->>'ram_total')::double precision),'disk_free',avg((data->>'disk_free')::double precision),'samples',count(*),'first',min(at),'last',max(at),'scope','hourly observed host averages; missing intervals absent')
 FROM measurements WHERE at<date_trunc('hour',now(),'UTC') GROUP BY node_id,date_trunc('hour',at,'UTC') ON CONFLICT(node_id,at) DO UPDATE SET data=EXCLUDED.data WHERE (EXCLUDED.data->>'samples')::bigint >= (measurement_rollups.data->>'samples')::bigint`)
	if e != nil {
		return e
	}
	for _, q := range []string{"DELETE FROM measurements WHERE at<now()-interval '7 days'", "DELETE FROM measurement_rollups WHERE at<now()-$1*interval '1 day'", "DELETE FROM checks WHERE at<now()-$1*interval '1 day'", "DELETE FROM commands WHERE expires<now()-interval '7 days' AND operation_id IN(SELECT id FROM operations WHERE phase IN('succeeded','failed','reverted','expired','cancelled'))", "DELETE FROM telegram_actions WHERE expires<now()", "DELETE FROM commands WHERE operation_id IN(SELECT id FROM operations WHERE updated<now()-$1*interval '1 day' AND phase IN('succeeded','failed','reverted','expired','cancelled'))", "DELETE FROM operations WHERE updated<now()-$1*interval '1 day' AND phase IN('succeeded','failed','reverted','expired','cancelled')", "DELETE FROM alerts WHERE NOT active AND updated<now()-$1*interval '1 day'"} {
		if containsParameter(q) {
			_, e = s.DB.Exec(ctx, q, days)
		} else {
			_, e = s.DB.Exec(ctx, q)
		}
		if e != nil {
			return e
		}
	}
	return nil
}
func containsParameter(q string) bool {
	for i := 1; i < len(q); i++ {
		if q[i-1] == '$' && q[i] == '1' {
			return true
		}
	}
	return false
}
func (s *Server) aggregateHistory(w http.ResponseWriter, r *http.Request) bool {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days == 0 {
		return false
	}
	if days != 7 && days != 30 && days != 90 {
		fail(w, 400, "invalid_history_range", "Choose 7, 30 or 90 days.", "بازهٔ ۷، ۳۰ یا ۹۰ روز را انتخاب کنید.")
		return true
	}
	unit := "hour"
	if days > 7 {
		unit = "day"
	}
	rows, e := s.DB.Query(r.Context(), `WITH points AS(
 SELECT at,data FROM measurement_rollups WHERE node_id=$1 AND at>now()-$2*interval '1 day'
 UNION ALL SELECT date_trunc('hour',at,'UTC'),jsonb_build_object('cpu_percent',avg((data->>'cpu_percent')::double precision),'cpu_samples',count(data->>'cpu_percent'),'ram_used',avg((data->>'ram_used')::double precision),'disk_free',avg((data->>'disk_free')::double precision),'samples',count(*),'first',min(at),'last',max(at)) FROM measurements WHERE node_id=$1 AND at>=date_trunc('hour',now(),'UTC') GROUP BY date_trunc('hour',at,'UTC'))
 SELECT date_trunc($3,at,'UTC'),jsonb_build_object('cpu_percent',sum((data->>'cpu_percent')::double precision*(data->>'cpu_samples')::bigint)/NULLIF(sum((data->>'cpu_samples')::bigint),0),'ram_used',sum((data->>'ram_used')::double precision*(data->>'samples')::bigint)/NULLIF(sum((data->>'samples')::bigint),0),'disk_free',sum((data->>'disk_free')::double precision*(data->>'samples')::bigint)/NULLIF(sum((data->>'samples')::bigint),0),'samples',sum((data->>'samples')::bigint),'first',min(data->>'first'),'last',max(data->>'last'),'scope',$3||' observed host averages; empty intervals absent') FROM points GROUP BY date_trunc($3,at,'UTC') ORDER BY date_trunc($3,at,'UTC') DESC LIMIT 200`, r.PathValue("id"), days, unit)
	if e != nil {
		badOperation(w, e)
		return true
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var at time.Time
		var data []byte
		rows.Scan(&at, &data)
		out = append(out, map[string]any{"at": at, "data": json.RawMessage(data), "aggregation": unit})
	}
	write(w, out)
	return true
}
