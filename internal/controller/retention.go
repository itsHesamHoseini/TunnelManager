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
 SELECT node_id,date_trunc('hour',at,'UTC'),jsonb_build_object('cpu_percent',avg((data->>'cpu_percent')::double precision),'cpu_samples',count(data->>'cpu_percent'),'ram_used',avg((data->>'ram_used')::double precision),'ram_total',max((data->>'ram_total')::double precision),'disk_free',avg((data->>'disk_free')::double precision),'rx_rate',avg((jsonb_path_query_first(data,'$.networks[*] ? (@.primary == true)')->>'rx_bytes_per_second')::double precision),'tx_rate',avg((jsonb_path_query_first(data,'$.networks[*] ? (@.primary == true)')->>'tx_bytes_per_second')::double precision),'samples',count(*),'first',min(at),'last',max(at),'scope','hourly observed host averages; missing intervals absent')
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
	if days != 1 && days != 7 && days != 30 && days != 90 {
		fail(w, 400, "invalid_history_range", "Choose 24 hours, 7, 30 or 90 days.", "بازهٔ ۲۴ ساعت، ۷، ۳۰ یا ۹۰ روز را انتخاب کنید.")
		return true
	}
	if days == 1 {
		// At most 288 measured five-minute buckets, never generated zero bins.
		// Detailed samples remain available for seven days under retention policy.
		rows, e := s.DB.Query(r.Context(), `SELECT date_bin(interval '5 minutes',at,timestamptz '2000-01-01'),jsonb_build_object('cpu_percent',avg((data->>'cpu_percent')::double precision),'ram_used',avg((data->>'ram_used')::double precision),'disk_free',avg((data->>'disk_free')::double precision),'rx_rate',avg((jsonb_path_query_first(data,'$.networks[*] ? (@.primary == true)')->>'rx_bytes_per_second')::double precision),'tx_rate',avg((jsonb_path_query_first(data,'$.networks[*] ? (@.primary == true)')->>'tx_bytes_per_second')::double precision),'samples',count(*),'first',min(at),'last',max(at),'scope','five-minute observed host averages; empty intervals absent') FROM measurements WHERE node_id=$1 AND at>now()-interval '24 hours' GROUP BY 1 ORDER BY 1 DESC LIMIT 289`, r.PathValue("id"))
		if e != nil {
			badOperation(w, e)
			return true
		}
		defer rows.Close()
		out := []any{}
		for rows.Next() {
			var at time.Time
			var data []byte
			if e = rows.Scan(&at, &data); e != nil {
				badOperation(w, e)
				return true
			}
			out = append(out, map[string]any{"at": at, "data": json.RawMessage(data), "aggregation": "5 minutes"})
		}
		if e = rows.Err(); e != nil {
			badOperation(w, e)
			return true
		}
		write(w, out)
		return true
	}
	unit := "hour"
	if days > 7 {
		unit = "day"
	}
	rows, e := s.DB.Query(r.Context(), `WITH points AS(
 SELECT at,data FROM measurement_rollups WHERE node_id=$1 AND at>now()-$2*interval '1 day'
 UNION ALL SELECT date_trunc('hour',at,'UTC'),jsonb_build_object('cpu_percent',avg((data->>'cpu_percent')::double precision),'cpu_samples',count(data->>'cpu_percent'),'ram_used',avg((data->>'ram_used')::double precision),'disk_free',avg((data->>'disk_free')::double precision),'rx_rate',avg((jsonb_path_query_first(data,'$.networks[*] ? (@.primary == true)')->>'rx_bytes_per_second')::double precision),'tx_rate',avg((jsonb_path_query_first(data,'$.networks[*] ? (@.primary == true)')->>'tx_bytes_per_second')::double precision),'samples',count(*),'first',min(at),'last',max(at)) FROM measurements WHERE node_id=$1 AND at>=date_trunc('hour',now(),'UTC') GROUP BY date_trunc('hour',at,'UTC'))
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
