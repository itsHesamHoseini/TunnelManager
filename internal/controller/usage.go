package controller

import (
	"context"
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"github.com/jackc/pgx/v5"
	"math"
	"time"
)

func recordUsage(ctx context.Context, tx pgx.Tx, id string, previous []byte, current *protocol.Telemetry) error {
	var old protocol.Telemetry
	if json.Unmarshal(previous, &old) != nil || current.Boot == "" || old.Boot != current.Boot || old.At.IsZero() || !current.At.After(old.At) || current.At.UTC().Format("2006-01") != old.At.UTC().Format("2006-01") {
		return nil
	}
	for _, n := range current.Networks {
		if !n.Primary {
			continue
		}
		for _, o := range old.Networks {
			if o.Name != n.Name || !o.Primary || n.RX < o.RX || n.TX < o.TX {
				continue
			}
			rx, txBytes := n.RX-o.RX, n.TX-o.TX
			if rx > math.MaxInt64 || txBytes > math.MaxInt64 {
				return nil
			}
			_, e := tx.Exec(ctx, "INSERT INTO node_usage(node_id,month,rx,tx,started,ended,interface)VALUES($1,$2,$3,$4,$5,$6,$7)ON CONFLICT(node_id,month)DO UPDATE SET rx=node_usage.rx+EXCLUDED.rx,tx=node_usage.tx+EXCLUDED.tx,ended=EXCLUDED.ended", id, current.At.UTC().Format("2006-01"), int64(rx), int64(txBytes), old.At, current.At, n.Name)
			return e
		}
	}
	return nil
}
func (s *Server) usage(ctx context.Context, id string) map[string]any {
	var rx, tx int64
	var start, end time.Time
	var iface string
	month := time.Now().UTC().Format("2006-01")
	if s.DB.QueryRow(ctx, "SELECT rx,tx,started,ended,interface FROM node_usage WHERE node_id=$1 AND month=$2", id, month).Scan(&rx, &tx, &start, &end, &iface) != nil {
		return map[string]any{"measured": false, "month": month}
	}
	return map[string]any{"measured": true, "month": month, "rx": rx, "tx": tx, "started": start, "ended": end, "interface": iface, "scope": "primary host interface; observed cumulative byte deltas; partial UTC month"}
}
