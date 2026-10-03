package manager

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"radman/internal/proto"
)

// Node logging. Each node has a log level and a log age (both pushed to it in its config), and a user can
// ask for a bundle of its log files: the request is handed to the node at its next check-in, the node
// uploads a zip in chunks, and the manager keeps it for a while so it can be downloaded.

var nodeLogLevels = []string{"error", "warning", "info", "debug"}

const (
	maxLogRetentionDays  = 365
	logBundleKeepDays    = 14 // how long a collected bundle stays downloadable
	logBundlePendingDays = 7  // a request the node never answered is marked failed after this
	maxLogBundlesPerNode = 5
	maxLogChunks         = proto.MaxLogBundleSize/proto.LogChunkBytes + 1
)

// finalizing bounds how many bundles are being checked at once (each is held in memory while it is validated).
var finalizing = make(chan struct{}, 2)

type logBundleRow struct {
	ID, Status, By, Error string
	Requested, Completed  *time.Time
	Size                  int64
}

func validLogLevel(s string) bool { return contains(nodeLogLevels, s) }

// nodeSupportsLogs reports whether the node said, in its last check-in, that it can deliver log bundles.
func nodeSupportsLogs(stats []byte) bool {
	var st proto.Stats
	json.Unmarshal(stats, &st)
	return contains(st.Features, proto.FeatureLogs)
}

// pendingLogBundle is the bundle the node should be building, if any.
func (a *App) pendingLogBundle(ctx context.Context, nodeID string) string {
	var id string
	a.St.DB.QueryRow(ctx, `SELECT id::text FROM node_log_bundles WHERE node_id=$1::uuid AND status IN ('requested','receiving') ORDER BY requested_at LIMIT 1`, nodeID).Scan(&id)
	return id
}

// receiveLogs stores one chunk of a bundle uploaded by an authenticated node, and finishes the bundle on the last chunk.
func (a *App) receiveLogs(ctx context.Context, id *nodeIdentity, u *proto.LogUpload) error {
	if u == nil || !isUUID(u.ID) {
		return errBadRequest
	}
	var status string
	if err := a.St.DB.QueryRow(ctx, `SELECT status FROM node_log_bundles WHERE id=$1::uuid AND node_id=$2::uuid`, u.ID, id.ID).Scan(&status); err != nil {
		return errors.New("unknown log bundle")
	}
	if status == "ready" || status == "failed" {
		return nil // already settled; a retried or late chunk is harmless
	}
	fail := func(msg string) error {
		a.St.DB.Exec(ctx, `UPDATE node_log_bundles SET status='failed', error=$2, completed_at=now() WHERE id=$1::uuid`, u.ID, truncate(msg, 300))
		a.St.DB.Exec(ctx, `DELETE FROM node_log_chunks WHERE bundle_id=$1::uuid`, u.ID)
		return nil
	}
	if u.Error != "" {
		return fail("node could not build the bundle: " + u.Error)
	}
	if u.Index < 0 || u.Index >= maxLogChunks || len(u.Data) > proto.LogChunkBytes {
		return errBadRequest
	}
	var others int64
	a.St.DB.QueryRow(ctx, `SELECT COALESCE(sum(length(data)),0) FROM node_log_chunks WHERE bundle_id=$1::uuid AND idx<>$2`, u.ID, u.Index).Scan(&others)
	if others+int64(len(u.Data)) > proto.MaxLogBundleSize {
		return fail("bundle exceeds the size limit")
	}
	if u.Index == 0 && !bytes.HasPrefix(u.Data, []byte("PK\x03\x04")) {
		return fail("bundle is not a zip file")
	}
	if _, err := a.St.DB.Exec(ctx, `INSERT INTO node_log_chunks(bundle_id,idx,data) VALUES($1::uuid,$2,$3) ON CONFLICT(bundle_id,idx) DO UPDATE SET data=EXCLUDED.data`, u.ID, u.Index, u.Data); err != nil {
		return err
	}
	if !u.Final {
		a.St.DB.Exec(ctx, `UPDATE node_log_bundles SET status='receiving' WHERE id=$1::uuid`, u.ID)
		return nil
	}

	// last chunk: drop leftovers from an earlier, longer attempt, then make sure nothing is missing
	a.St.DB.Exec(ctx, `DELETE FROM node_log_chunks WHERE bundle_id=$1::uuid AND idx>$2`, u.ID, u.Index)
	var n int
	var size int64
	a.St.DB.QueryRow(ctx, `SELECT count(*), COALESCE(sum(length(data)),0) FROM node_log_chunks WHERE bundle_id=$1::uuid`, u.ID).Scan(&n, &size)
	if n != u.Index+1 {
		return fmt.Errorf("log bundle incomplete: have %d of %d chunks", n, u.Index+1)
	}
	select {
	case finalizing <- struct{}{}:
		defer func() { <-finalizing }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := a.checkLogBundle(ctx, u.ID); err != nil {
		return fail("rejected bundle: " + err.Error())
	}
	a.St.DB.Exec(ctx, `UPDATE node_log_bundles SET status='ready', chunks=$2, size=$3, error='', completed_at=now() WHERE id=$1::uuid`, u.ID, n, size)
	a.Audit(ctx, "node:"+id.ID, "node.logs_collected", fmt.Sprintf("bundle %s, %d bytes", u.ID, size))
	return nil
}

var logEntryName = regexp.MustCompile(`^(info\.txt|logs/node-[A-Za-z0-9._-]+\.log)$`)

// checkLogBundle makes sure what a node uploaded is a plain zip of log files. The manager never unpacks it, but
// people will, so entries that could escape the target folder (or a zip bomb) are refused.
func (a *App) checkLogBundle(ctx context.Context, bundleID string) error {
	rows, err := a.St.DB.Query(ctx, `SELECT data FROM node_log_chunks WHERE bundle_id=$1::uuid ORDER BY idx`, bundleID)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for rows.Next() {
		var d []byte
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return err
		}
		buf.Write(d)
	}
	rows.Close()
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		return errors.New("not a valid zip file")
	}
	if len(zr.File) == 0 || len(zr.File) > 500 {
		return errors.New("unexpected number of files")
	}
	var total uint64
	for _, f := range zr.File {
		if !logEntryName.MatchString(f.Name) {
			return fmt.Errorf("unexpected file name %q", truncate(f.Name, 60))
		}
		total += f.UncompressedSize64
	}
	if total > 4<<30 {
		return errors.New("uncompressed size is too large")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// cleanupLogBundles expires unanswered requests and old bundles, and keeps the newest few per node.
func (a *App) cleanupLogBundles(ctx context.Context) {
	a.St.DB.Exec(ctx, `UPDATE node_log_bundles SET status='failed', error='the node did not deliver the logs in time', completed_at=now()
		WHERE status IN ('requested','receiving') AND requested_at < now() - make_interval(days => $1)`, logBundlePendingDays)
	a.St.DB.Exec(ctx, `DELETE FROM node_log_bundles WHERE requested_at < now() - make_interval(days => $1)`, logBundleKeepDays)
	a.St.DB.Exec(ctx, `DELETE FROM node_log_bundles WHERE id IN (
		SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY node_id ORDER BY requested_at DESC) AS rn FROM node_log_bundles) x WHERE rn > $1)`, maxLogBundlesPerNode)
}

func (a *App) logBundles(ctx context.Context, nodeID string) []logBundleRow {
	rows, err := a.St.DB.Query(ctx, `SELECT id::text, status, requested_by, error, requested_at, completed_at, size FROM node_log_bundles WHERE node_id=$1::uuid ORDER BY requested_at DESC LIMIT $2`, nodeID, maxLogBundlesPerNode)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []logBundleRow
	for rows.Next() {
		var b logBundleRow
		if rows.Scan(&b.ID, &b.Status, &b.By, &b.Error, &b.Requested, &b.Completed, &b.Size) == nil {
			out = append(out, b)
		}
	}
	return out
}

// ---- web handlers ----

// nodeLogging saves the node's log level and log age; the node applies them at its next check-in.
func (s *server) nodeLogging(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	level := strings.ToLower(strings.TrimSpace(r.PostFormValue("log_level")))
	if !validLogLevel(level) {
		s.back(w, r, "/nodes/"+id, "err", "Log level must be error, warning, info or debug.")
		return
	}
	days, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("log_retention_days")))
	if err != nil || days < 1 || days > maxLogRetentionDays {
		s.back(w, r, "/nodes/"+id, "err", fmt.Sprintf("Log age must be between 1 and %d days.", maxLogRetentionDays))
		return
	}
	if _, err := s.a.St.DB.Exec(r.Context(), `UPDATE nodes SET log_level=$2, log_retention_days=$3 WHERE id=$1::uuid`, id, level, days); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(r.Context(), u.Email, "node.logging", fmt.Sprintf("%s level=%s retention=%dd", id, level, days))
	s.back(w, r, "/nodes/"+id, "ok", "Logging settings saved; the node applies them at its next check-in.")
}

// nodeLogsCollect asks the node for its logs at its next check-in.
func (s *server) nodeLogsCollect(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	var status string
	var stats []byte
	if err := s.a.St.DB.QueryRow(r.Context(), `SELECT status, stats FROM nodes WHERE id=$1::uuid`, id).Scan(&status, &stats); err != nil {
		s.fail(w, r, u, err)
		return
	}
	if status != "active" {
		s.back(w, r, "/nodes/"+id, "err", "Logs can only be collected from an enrolled, active node.")
		return
	}
	if !nodeSupportsLogs(stats) {
		s.back(w, r, "/nodes/"+id, "err", "This node's version does not support log collection yet. Deploy the current node binary first.")
		return
	}
	if s.a.pendingLogBundle(r.Context(), id) != "" {
		s.back(w, r, "/nodes/"+id, "ok", "A log collection is already waiting for the node's next check-in.")
		return
	}
	if _, err := s.a.St.DB.Exec(r.Context(), `INSERT INTO node_log_bundles(node_id,requested_by) VALUES($1::uuid,$2)`, id, u.Email); err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(r.Context(), u.Email, "node.logs_request", id)
	s.back(w, r, "/nodes/"+id, "ok", "Log collection requested. The node uploads its logs at its next check-in; the download appears here when they arrive.")
}

func (s *server) nodeLogsDownload(w http.ResponseWriter, r *http.Request, u *User) {
	id, bid := r.PathValue("id"), r.PathValue("bid")
	if !isUUID(bid) {
		http.NotFound(w, r)
		return
	}
	var status, name string
	var size int64
	var done *time.Time
	err := s.a.St.DB.QueryRow(r.Context(), `SELECT b.status, b.size, b.completed_at, n.name FROM node_log_bundles b JOIN nodes n ON n.id=b.node_id WHERE b.id=$1::uuid AND b.node_id=$2::uuid`, bid, id).Scan(&status, &size, &done, &name)
	if err != nil || status != "ready" {
		http.NotFound(w, r)
		return
	}
	rows, err := s.a.St.DB.Query(r.Context(), `SELECT data FROM node_log_chunks WHERE bundle_id=$1::uuid ORDER BY idx`, bid)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	defer rows.Close()
	s.a.Audit(r.Context(), u.Email, "node.logs_download", id+" bundle "+bid)
	stamp := time.Now().UTC()
	if done != nil {
		stamp = done.UTC()
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="radman-node-%s-logs-%s.zip"`, slug(name), stamp.Format("20060102-150405")))
	w.Header().Set("Cache-Control", "no-store")
	for rows.Next() {
		var d []byte
		if rows.Scan(&d) != nil {
			return
		}
		if _, err := w.Write(d); err != nil {
			return
		}
	}
}

func (s *server) nodeLogsDelete(w http.ResponseWriter, r *http.Request, u *User) {
	id, bid := r.PathValue("id"), r.PathValue("bid")
	if isUUID(bid) {
		s.a.St.DB.Exec(r.Context(), `DELETE FROM node_log_bundles WHERE id=$1::uuid AND node_id=$2::uuid`, bid, id)
		s.a.Audit(r.Context(), u.Email, "node.logs_delete", id+" bundle "+bid)
	}
	s.back(w, r, "/nodes/"+id, "ok", "Log bundle deleted.")
}
