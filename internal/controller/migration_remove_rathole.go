package controller

// Migration 5 removes Rathole records at the owner's request. It never calls a
// node, systemd, SSH, an engine executable, or a host-file cleanup operation.
import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"github.com/jackc/pgx/v5"
)

const retiredEngineName = "rathole"
const retirementPurpose = "database-retirement-snapshot-v1"

type RetirementReport struct {
	AlreadyApplied bool   `json:"already_applied"`
	Tunnels        int    `json:"removed_tunnels"`
	Services       int    `json:"removed_services"`
	Operations     int    `json:"removed_operations"`
	Backup         string `json:"backup"`
}

var ownedTables = []string{"schema_version", "admins", "recovery", "sessions", "challenges", "auth_failures", "audit", "settings", "enrollment", "nodes", "measurements", "measurement_rollups", "node_usage", "tunnels", "tunnel_versions", "operations", "commands", "port_reservations", "certificates", "certificate_links", "alerts", "checks", "recovery_rules", "telegram_actions", "telegram_cursor"}

// RetireEngine is called before starting command delivery. backupPath must be a
// new absolute file, outside PostgreSQL storage. The caller retains master.key
// separately and still takes the normal independent installer backup on update.
func (s *Server) RetireEngine(ctx context.Context, backupPath string) (RetirementReport, error) {
	report := RetirementReport{}
	tx, e := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if e != nil {
		return report, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "LOCK TABLE schema_version IN ACCESS EXCLUSIVE MODE"); e != nil {
		return report, e
	}
	var applied bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_version WHERE version=5)").Scan(&applied); e != nil {
		return report, e
	}
	if applied {
		report.AlreadyApplied = true
		return report, nil
	}
	// Finish earlier work with the earlier binary. Never discard an armed local
	// rollback or queued mutation merely to permit a new software version.
	for _, table := range ownedTables[1:] {
		if _, e = tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{table}.Sanitize()+" IN ACCESS EXCLUSIVE MODE"); e != nil {
			return report, e
		}
	}
	if e = retirementPendingMutations(ctx, tx, s.Config.Key); e != nil {
		return report, e
	}
	var pending int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM commands WHERE state<>'completed' AND expires>now() AND kind NOT IN('inventory','diagnostic','instance.status','instance.config','logs.read','tools.status')`).Scan(&pending); e != nil {
		return report, e
	}
	if pending > 0 {
		return report, errors.New("finish_pending_commands_before_engine_retirement")
	}
	nodeRows, e := backupRetirementRows(ctx, tx, backupPath, s.Config.Key)
	if e != nil {
		return report, e
	}
	report.Backup = backupPath
	retired := map[string]bool{}
	supported := map[string]bool{}
	retiredPairs := map[string]bool{}
	retiredInstances := map[string]bool{}
	supportedInstances := map[string]bool{}
	tunnelIDs := []string{}
	// PostgreSQL JSON bytea is hexadecimal; read encrypted values through pgx
	// rather than treating that representation as base64.
	rows, e := tx.Query(ctx, "SELECT id,cipher FROM tunnels")
	if e != nil {
		return report, e
	}
	for rows.Next() {
		var id string
		var cipher []byte
		if e = rows.Scan(&id, &cipher); e != nil {
			rows.Close()
			return report, e
		}
		raw, e := secure.Open(s.Config.Key, "tunnel:"+id, cipher)
		if e != nil {
			rows.Close()
			return report, errors.New("retirement_encrypted_state_unavailable")
		}
		var rec map[string]any
		if decodeRetirementJSON(raw, &rec) != nil {
			rows.Close()
			return report, errors.New("retirement_invalid_tunnel_record")
		}
		if spec, _ := rec["spec"].(map[string]any); spec != nil && spec["engine"] == retiredEngineName {
			retired[id] = true
			tunnelIDs = append(tunnelIDs, id)
			instances, _ := rec["instances"].(map[string]any)
			for node, value := range instances {
				if instance, ok := value.(string); ok {
					retiredInstances[instance] = true
					retiredPairs[node+":"+instance] = true
				}
			}
		}
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		return report, e
	}
	rows.Close()
	// Include unmatched discovered services, not only paired tunnel instances.

	for _, node := range nodeRows {
		inventory, _ := node["inventory"].(map[string]any)
		instances, _ := inventory["instances"].([]any)
		for _, v := range instances {
			m, _ := v.(map[string]any)
			if m["engine"] == retiredEngineName {
				if id, ok := m["id"].(string); ok {
					retiredInstances[id] = true
					retiredPairs[node["id"].(string)+":"+id] = true
					report.Services++
				}
			} else if m["engine"] == "backhaul" {
				if id, ok := m["id"].(string); ok {
					supportedInstances[id] = true
					supported[node["id"].(string)+":"+id] = true
				}
			}
		}
	}
	// Never prune an identifier shared by a supported record. Such corrupt or
	// ambiguous ownership needs a manual review, not a broad string deletion.
	rows, e = tx.Query(ctx, "SELECT id,cipher FROM tunnels")
	if e != nil {
		return report, e
	}
	for rows.Next() {
		var id string
		var cipher []byte
		rows.Scan(&id, &cipher)
		if retired[id] {
			continue
		}
		supported[id] = true
		var r TunnelRecord
		if s.openValue("tunnel:"+id, cipher, &r) != nil {
			rows.Close()
			return report, errors.New("retirement_encrypted_state_unavailable")
		}
		for node, instance := range r.Instances {
			if retiredPairs[node+":"+instance] {
				rows.Close()
				return report, errors.New("retirement_ownership_conflict_requires_review")
			}
			supportedInstances[instance] = true
			supported[node+":"+instance] = true
		}
	}
	rows.Close()
	for id := range retiredInstances {
		if !supportedInstances[id] {
			retired[id] = true
		}
	}
	for id := range supportedInstances {
		if !retiredInstances[id] {
			supported[id] = true
		}
	}
	for pair := range retiredPairs {
		retired[pair] = true
	}
	for pair := range retiredPairs {
		node, instance, _ := strings.Cut(pair, ":")
		if _, e = tx.Exec(ctx, "DELETE FROM certificate_links WHERE node_id=$1 AND instance_id=$2", node, instance); e != nil {
			return report, e
		}
		if _, e = tx.Exec(ctx, "DELETE FROM recovery_rules WHERE node_id=$1 AND instance_id=$2", node, instance); e != nil {
			return report, e
		}
	}
	for _, id := range tunnelIDs {
		if _, e = tx.Exec(ctx, "DELETE FROM tunnels WHERE id=$1", id); e != nil {
			return report, e
		}
		report.Tunnels++
	}
	// Retired-only jobs and their reservations/receipts are removed. Mixed
	// completed history retains supported members, with only retired data pruned.
	rows, e = tx.Query(ctx, "SELECT id,target,cipher,result,steps FROM operations")
	if e != nil {
		return report, e
	}
	type job struct {
		id, target            string
		cipher, result, steps []byte
	}
	jobs := []job{}
	for rows.Next() {
		var j job
		if e = rows.Scan(&j.id, &j.target, &j.cipher, &j.result, &j.steps); e != nil {
			rows.Close()
			return report, e
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	for _, j := range jobs {
		raw, e := secure.Open(s.Config.Key, "operation:"+j.id, j.cipher)
		if e != nil {
			return report, errors.New("retirement_encrypted_state_unavailable")
		}
		var v any
		if decodeRetirementJSON(raw, &v) != nil {
			return report, errors.New("retirement_invalid_operation")
		}
		hasOld, hasSupported := retirementEngines(v)
		hasSupported = hasSupported || referencesRetirementID(v, supported)
		pruned, changed := pruneRetired(v, retired)
		if retired[j.target] || ((hasOld || changed) && !hasSupported) || pruned == nil {
			if _, e = tx.Exec(ctx, "DELETE FROM telegram_actions WHERE operation_id=$1", j.id); e != nil {
				return report, e
			}
			if _, e = tx.Exec(ctx, "DELETE FROM port_reservations WHERE plan_id=$1", j.id); e != nil {
				return report, e
			}
			if _, e = tx.Exec(ctx, "DELETE FROM commands WHERE operation_id=$1", j.id); e != nil {
				return report, e
			}
			if _, e = tx.Exec(ctx, "DELETE FROM operations WHERE id=$1", j.id); e != nil {
				return report, e
			}
			retired[j.id] = true
			report.Operations++
			continue
		}
		if changed {
			b, _ := json.Marshal(pruned)
			sealed, e := secure.Seal(s.Config.Key, "operation:"+j.id, b)
			if e != nil {
				return report, e
			}
			if _, e = tx.Exec(ctx, "UPDATE operations SET cipher=$1 WHERE id=$2", sealed, j.id); e != nil {
				return report, e
			}
		}
		for _, field := range []struct {
			name string
			raw  []byte
		}{{"result", j.result}, {"steps", j.steps}} {
			var doc any
			if decodeRetirementJSON(field.raw, &doc) != nil {
				return report, errors.New("retirement_invalid_operation_history")
			}
			p, c := pruneRetired(doc, retired)
			if c {
				if p == nil {
					if field.name == "steps" {
						p = []any{}
					} else {
						p = map[string]any{}
					}
				}
				b, _ := json.Marshal(p)
				if _, e = tx.Exec(ctx, "UPDATE operations SET "+pgx.Identifier{field.name}.Sanitize()+"=$1 WHERE id=$2", b, j.id); e != nil {
					return report, e
				}
			}
		}
	}
	// Completed command payloads/results in mixed historical operations must not
	// retain an actionable legacy instance. All outstanding commands were refused.
	rows, e = tx.Query(ctx, "SELECT id,node_id,cipher,result_cipher FROM commands")
	if e != nil {
		return report, e
	}
	type commandHistory struct {
		id, node       string
		cipher, result []byte
	}
	commandRows := []commandHistory{}
	for rows.Next() {
		var c commandHistory
		if e = rows.Scan(&c.id, &c.node, &c.cipher, &c.result); e != nil {
			rows.Close()
			return report, e
		}
		commandRows = append(commandRows, c)
	}
	rows.Close()
	for _, c := range commandRows {
		for _, field := range []struct {
			name, purpose string
			raw           []byte
		}{{"cipher", "command:", c.cipher}, {"result_cipher", "result:", c.result}} {
			if len(field.raw) == 0 {
				continue
			}
			raw, e := secure.Open(s.Config.Key, field.purpose+c.id, field.raw)
			if e != nil {
				return report, errors.New("retirement_encrypted_state_unavailable")
			}
			var v any
			if decodeRetirementJSON(raw, &v) != nil {
				return report, errors.New("retirement_invalid_command_history")
			}
			p, changed := pruneRetiredAt(v, retired, c.node)
			if !changed {
				continue
			}
			if p == nil {
				p = map[string]any{"retired": true}
			}
			b, _ := json.Marshal(p)
			sealed, e := secure.Seal(s.Config.Key, field.purpose+c.id, b)
			if e != nil {
				return report, e
			}
			if _, e = tx.Exec(ctx, "UPDATE commands SET "+pgx.Identifier{field.name}.Sanitize()+"=$1 WHERE id=$2", sealed, c.id); e != nil {
				return report, e
			}
		}
	}
	// Node telemetry remains truthful and listeners remain present for generic
	// port conflicts; only unsupported engine inventories/process labels retire.
	for _, node := range nodeRows {
		for _, field := range []string{"inventory", "telemetry"} {
			if node[field] == nil {
				continue
			}
			v, changed := pruneRetiredAt(node[field], retired, node["id"].(string))
			if !changed {
				continue
			}
			b, _ := json.Marshal(v)
			if _, e = tx.Exec(ctx, "UPDATE nodes SET "+pgx.Identifier{field}.Sanitize()+"=$1 WHERE id=$2", b, node["id"]); e != nil {
				return report, e
			}
		}
	}
	for id := range retired {
		if _, e = tx.Exec(ctx, "DELETE FROM alerts WHERE target=$1", id); e != nil {
			return report, e
		}
		if _, e = tx.Exec(ctx, "DELETE FROM audit WHERE target=$1", id); e != nil {
			return report, e
		}
		if _, e = tx.Exec(ctx, "DELETE FROM checks WHERE target=$1", id); e != nil {
			return report, e
		}
	}
	if _, e = tx.Exec(ctx, "INSERT INTO schema_version(version)VALUES(5)"); e != nil {
		return report, e
	}
	if e = tx.Commit(ctx); e != nil {
		return report, e
	}
	return report, nil
}

func retirementPendingMutations(ctx context.Context, tx pgx.Tx, key []byte) error {
	rows, e := tx.Query(ctx, `SELECT id,kind,cipher,COALESCE(deadline>now(),false) FROM operations WHERE phase NOT IN('succeeded','failed','reverted','expired','cancelled','released') OR deadline>now()`)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var id, kind string
		var cipher []byte
		var armed bool
		if e = rows.Scan(&id, &kind, &cipher, &armed); e != nil {
			return e
		}
		if armed {
			return errors.New("finish_pending_operations_before_engine_retirement")
		}
		if kind == "tunnel-check" {
			continue
		}
		if kind == "node" {
			raw, e := secure.Open(key, "operation:"+id, cipher)
			if e != nil {
				return errors.New("retirement_encrypted_state_unavailable")
			}
			var q JobPayload
			if json.Unmarshal(raw, &q) != nil {
				return errors.New("retirement_invalid_operation")
			}
			switch q.Kind {
			case "inventory", "diagnostic", "instance.status", "instance.config", "logs.read", "tools.status":
				continue
			}
		}
		return errors.New("finish_pending_operations_before_engine_retirement")
	}
	return rows.Err()
}

func retirementEngines(v any) (old, supported bool) {
	switch m := v.(type) {
	case map[string]any:
		if name, ok := m["engine"].(string); ok {
			old = name == retiredEngineName
			supported = name == "backhaul"
		}
		for _, x := range m {
			a, b := retirementEngines(x)
			old = old || a
			supported = supported || b
		}
	case []any:
		for _, x := range m {
			a, b := retirementEngines(x)
			old = old || a
			supported = supported || b
		}
	}
	return
}

func retirementNode(m map[string]any, inherited string) string {
	for _, key := range []string{"Node", "node", "node_id"} {
		if node, ok := m[key].(string); ok && node != "" {
			return node
		}
	}
	return inherited
}
func referencesRetirementID(v any, ids map[string]bool) bool {
	return referencesRetirementAt(v, ids, "")
}
func referencesRetirementAt(v any, ids map[string]bool, node string) bool {
	switch m := v.(type) {
	case string:
		return ids[m] || node != "" && ids[node+":"+m]
	case map[string]any:
		node = retirementNode(m, node)
		for k, x := range m {
			if value, ok := x.(string); ok && ids[k+":"+value] {
				return true
			}
			if referencesRetirementAt(x, ids, node) {
				return true
			}
		}
	case []any:
		for _, x := range m {
			if referencesRetirementAt(x, ids, node) {
				return true
			}
		}
	}
	return false
}
func pruneRetired(v any, ids map[string]bool) (any, bool) { return pruneRetiredAt(v, ids, "") }
func pruneRetiredAt(v any, ids map[string]bool, node string) (any, bool) {
	switch m := v.(type) {
	case map[string]any:
		if m["engine"] == retiredEngineName {
			return nil, true
		}
		node = retirementNode(m, node)
		for _, key := range []string{"id", "ID", "instance", "Instance", "instance_id"} {
			if id, ok := m[key].(string); ok && (ids[id] || node != "" && ids[node+":"+id]) {
				return nil, true
			}
		}
		out := map[string]any{}
		changed := false
		for k, x := range m {
			if k == "process" {
				if name, ok := x.(string); ok && strings.Contains(strings.ToLower(name), retiredEngineName) {
					out[k] = ""
					changed = true
					continue
				}
			}
			if ids[k] {
				changed = true
				continue
			}
			if value, ok := x.(string); ok && ids[k+":"+value] {
				changed = true
				continue
			}
			p, c := pruneRetiredAt(x, ids, node)
			changed = changed || c
			if p != nil {
				out[k] = p
			}
		}
		return out, changed
	case []any:
		out := []any{}
		changed := false
		for _, x := range m {
			p, c := pruneRetiredAt(x, ids, node)
			changed = changed || c
			if p != nil {
				out = append(out, p)
			}
		}
		return out, changed
	case string:
		if ids[m] || node != "" && ids[node+":"+m] {
			return nil, true
		}
	}
	return v, false
}
