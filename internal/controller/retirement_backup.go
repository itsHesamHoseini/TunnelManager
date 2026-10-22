package controller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"github.com/jackc/pgx/v5"
)

const retirementFrameLimit = 4 << 20
const retirementBackupLimit = 512 << 20

type retirementFrame struct {
	Table string          `json:"table,omitempty"`
	Row   json.RawMessage `json:"row,omitempty"`
	Final bool            `json:"final,omitempty"`
	Count int             `json:"count,omitempty"`
}

func decodeRetirementJSON(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(value)
}

// Row-wise AEAD frames avoid holding the full history/database in memory.
// Each frame binds its index and previous ciphertext hash; an authenticated
// final frame is mandatory, so truncation/reordering cannot be accepted.
func backupRetirementRows(ctx context.Context, tx pgx.Tx, path string, key []byte) ([]map[string]any, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("retirement_requires_absolute_backup_path")
	}
	dir := filepath.Dir(path)
	for current := dir; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e == nil && st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("retirement_backup_symlink_rejected")
		}
		if e != nil && !os.IsNotExist(e) {
			return nil, errors.New("retirement_backup_directory_unavailable")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, errors.New("retirement_backup_directory_unavailable")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, errors.New("retirement_backup_must_be_new_file")
	}
	defer f.Close()
	if _, e = f.WriteString("TMRS2\n"); e != nil {
		return nil, errors.New("retirement_backup_write_failed")
	}
	index, total := 0, 6
	previous := ""
	write := func(frame retirementFrame) error {
		plain, e := json.Marshal(frame)
		if e != nil {
			return e
		}
		sealed, e := secure.Seal(key, fmt.Sprintf("%s:%d:%s", retirementPurpose, index, previous), plain)
		if e != nil {
			return e
		}
		if len(sealed) > retirementFrameLimit || total+len(sealed)+4 > retirementBackupLimit {
			return errors.New("retirement_snapshot_exceeds_limit")
		}
		if e = binary.Write(f, binary.BigEndian, uint32(len(sealed))); e != nil {
			return errors.New("retirement_backup_write_failed")
		}
		if _, e = f.Write(sealed); e != nil {
			return errors.New("retirement_backup_write_failed")
		}
		previous = secure.Hash(string(sealed))
		index++
		total += len(sealed) + 4
		return nil
	}
	for _, table := range ownedTables {
		rows, e := tx.Query(ctx, "SELECT to_jsonb(t) FROM "+pgx.Identifier{table}.Sanitize()+" t")
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var row []byte
			if e = rows.Scan(&row); e != nil {
				rows.Close()
				return nil, e
			}
			if e = write(retirementFrame{Table: table, Row: row}); e != nil {
				rows.Close()
				return nil, e
			}
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return nil, e
		}
		rows.Close()
	}
	if e = write(retirementFrame{Final: true, Count: index}); e != nil {
		return nil, e
	}
	if e = f.Sync(); e != nil {
		return nil, errors.New("retirement_backup_sync_failed")
	}
	if e = f.Close(); e != nil {
		return nil, errors.New("retirement_backup_close_failed")
	}
	nodes := []map[string]any{}
	e = verifyRetirementBackup(path, key, func(table string, row json.RawMessage) error {
		if table == "nodes" {
			var n map[string]any
			if e := decodeRetirementJSON(row, &n); e != nil {
				return e
			}
			nodes = append(nodes, n)
		}
		return nil
	})
	if e != nil {
		return nil, errors.New("retirement_backup_verification_failed")
	}
	return nodes, nil
}

func verifyRetirementBackup(path string, key []byte, visit func(string, json.RawMessage) error) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > retirementBackupLimit {
		return errors.New("invalid_retirement_backup_size")
	}
	r := bufio.NewReader(f)
	header := make([]byte, 6)
	if _, e = io.ReadFull(r, header); e != nil || string(header) != "TMRS2\n" {
		return errors.New("invalid_retirement_backup_header")
	}
	index := 0
	previous := ""
	allowed := map[string]bool{}
	for _, table := range ownedTables {
		allowed[table] = true
	}
	for {
		var size uint32
		if e = binary.Read(r, binary.BigEndian, &size); e != nil {
			return errors.New("incomplete_retirement_backup")
		}
		if size == 0 || size > retirementFrameLimit {
			return errors.New("invalid_retirement_backup_frame")
		}
		sealed := make([]byte, size)
		if _, e = io.ReadFull(r, sealed); e != nil {
			return errors.New("incomplete_retirement_backup")
		}
		plain, e := secure.Open(key, fmt.Sprintf("%s:%d:%s", retirementPurpose, index, previous), sealed)
		if e != nil {
			return errors.New("invalid_retirement_backup_authentication")
		}
		var frame retirementFrame
		if json.Unmarshal(plain, &frame) != nil {
			return errors.New("invalid_retirement_backup_frame")
		}
		if frame.Final {
			if frame.Count != index {
				return errors.New("invalid_retirement_backup_count")
			}
			if _, e = r.ReadByte(); e != io.EOF {
				return errors.New("trailing_retirement_backup_data")
			}
			return nil
		}
		if !allowed[frame.Table] || !json.Valid(frame.Row) {
			return errors.New("invalid_retirement_backup_table")
		}
		if visit != nil {
			if e = visit(frame.Table, frame.Row); e != nil {
				return e
			}
		}
		previous = secure.Hash(string(sealed))
		index++
	}
}
