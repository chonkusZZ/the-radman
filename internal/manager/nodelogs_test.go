package manager

import (
	"archive/zip"
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"

	"radman/internal/proto"
)

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		fw, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func goodZip(t *testing.T) []byte {
	return makeZip(t, map[string]string{"logs/node-2026-05-01.log": strings.Repeat("a log line\n", 200), "info.txt": "host: test\n"})
}

func (w *world) newBundle(t *testing.T, node string) string {
	t.Helper()
	var id string
	if err := w.a.St.DB.QueryRow(w.ctx, `INSERT INTO node_log_bundles(node_id,requested_by) VALUES($1::uuid,'tester') RETURNING id::text`, node).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (w *world) bundleStatus(bid string) (status, errText string) {
	w.a.St.DB.QueryRow(w.ctx, `SELECT status, error FROM node_log_bundles WHERE id=$1::uuid`, bid).Scan(&status, &errText)
	return
}

func (w *world) identity(name string) *nodeIdentity {
	return &nodeIdentity{ID: w.node[name], SiteID: w.site[name], TenantID: w.tenant[name].ID, Name: name + " node"}
}

func (w *world) supportLogs(node string) {
	w.a.St.DB.Exec(w.ctx, `UPDATE nodes SET stats='{"features":["logs"]}' WHERE id=$1::uuid`, node)
}

// ---- settings ----

func TestNodeLoggingSettings(t *testing.T) {
	w := newWorld(t)
	A, B := "Alpha", "Bravo"
	aadmin := w.as(t, "aadmin", A)

	// a node starts at the defaults and they are part of the config it is sent
	cfg, err := w.a.BuildNodeConfig(w.ctx, w.site[A], w.node[A])
	if err != nil || cfg.LogLevel != "info" || cfg.LogRetentionDays != 30 {
		t.Fatalf("default node config: %+v %v", cfg, err)
	}
	before := proto.HashConfig(cfg)

	code, _ := aadmin.do(t, "POST", "/nodes/"+w.node[A]+"/logging", url.Values{"log_level": {"debug"}, "log_retention_days": {"7"}})
	expect(t, "save logging", code, 303)
	cfg, _ = w.a.BuildNodeConfig(w.ctx, w.site[A], w.node[A])
	if cfg.LogLevel != "debug" || cfg.LogRetentionDays != 7 {
		t.Fatalf("settings did not reach the node config: %+v", cfg)
	}
	if proto.HashConfig(cfg) == before {
		t.Error("changing the logging settings must change the config hash, or the node never receives them")
	}
	if w.count(`SELECT count(*) FROM audit WHERE actor='aadmin@test' AND action='node.logging'`) != 1 {
		t.Error("logging change not audited")
	}

	// every accepted level, and nothing else
	for _, lvl := range []string{"error", "warning", "info", "debug", "DEBUG"} {
		c, _ := aadmin.do(t, "POST", "/nodes/"+w.node[A]+"/logging", url.Values{"log_level": {lvl}, "log_retention_days": {"30"}})
		expect(t, "level "+lvl, c, 303)
	}
	var lvl string
	var days int
	w.a.St.DB.QueryRow(w.ctx, `SELECT log_level, log_retention_days FROM nodes WHERE id=$1::uuid`, w.node[A]).Scan(&lvl, &days)
	if lvl != "debug" || days != 30 {
		t.Fatalf("stored %q/%d", lvl, days)
	}
	for _, bad := range []url.Values{
		{"log_level": {"trace"}, "log_retention_days": {"7"}},
		{"log_level": {""}, "log_retention_days": {"7"}},
		{"log_level": {"info"}, "log_retention_days": {"0"}},
		{"log_level": {"info"}, "log_retention_days": {"-1"}},
		{"log_level": {"info"}, "log_retention_days": {"366"}},
		{"log_level": {"info"}, "log_retention_days": {"abc"}},
		{"log_level": {"info"}, "log_retention_days": {""}},
		{"log_level": {"info'; DROP TABLE nodes;--"}, "log_retention_days": {"7"}},
	} {
		aadmin.do(t, "POST", "/nodes/"+w.node[A]+"/logging", bad)
		w.a.St.DB.QueryRow(w.ctx, `SELECT log_level, log_retention_days FROM nodes WHERE id=$1::uuid`, w.node[A]).Scan(&lvl, &days)
		if lvl != "debug" || days != 30 {
			t.Errorf("invalid input %v was stored as %q/%d", bad, lvl, days)
		}
	}

	// another tenant's node: not found, unchanged
	c, _ := aadmin.do(t, "POST", "/nodes/"+w.node[B]+"/logging", url.Values{"log_level": {"error"}, "log_retention_days": {"1"}})
	expect(t, "cross-tenant logging", c, 404)
	if w.count(`SELECT count(*) FROM nodes WHERE id=$1::uuid AND log_level='info' AND log_retention_days=30`, w.node[B]) != 1 {
		t.Error("tenant B's node logging settings changed by tenant A")
	}

	// read-only: sees the values, cannot change them, gets no controls
	aro := w.as(t, "aro", A)
	c, body := aro.do(t, "GET", "/nodes/"+w.node[A], nil)
	expect(t, "read-only node page", c, 200)
	if strings.Contains(body, "Save logging settings") || strings.Contains(body, `action="/nodes/`+w.node[A]+`/logs/collect"`) {
		t.Error("logging controls rendered for a read-only user")
	}
	if !strings.Contains(body, "Logging") {
		t.Error("logging section missing for read-only user")
	}
	c, _ = aro.do(t, "POST", "/nodes/"+w.node[A]+"/logging", url.Values{"log_level": {"error"}, "log_retention_days": {"1"}})
	expect(t, "read-only save logging", c, 403)
	w.a.St.DB.QueryRow(w.ctx, `SELECT log_level, log_retention_days FROM nodes WHERE id=$1::uuid`, w.node[A]).Scan(&lvl, &days)
	if lvl != "debug" || days != 30 {
		t.Error("read-only user changed the logging settings")
	}
	// the writer sees the form
	c, body = aadmin.do(t, "GET", "/nodes/"+w.node[A], nil)
	if c != 200 || !strings.Contains(body, "Save logging settings") {
		t.Error("tenant admin does not get the logging form")
	}
}

// ---- requesting, delivering, downloading ----

func TestCollectLogsRequestAndDownload(t *testing.T) {
	w := newWorld(t)
	A, B := "Alpha", "Bravo"
	aadmin, aro, badmin := w.as(t, "aadmin", A), w.as(t, "aro", A), w.as(t, "badmin", B)
	collect := "/nodes/" + w.node[A] + "/logs/collect"

	// a node that never said it can send logs is not asked
	c, _ := aadmin.do(t, "POST", collect, nil)
	expect(t, "collect from old node", c, 303)
	if w.count(`SELECT count(*) FROM node_log_bundles WHERE node_id=$1::uuid`, w.node[A]) != 0 {
		t.Fatal("log collection requested from a node that does not support it")
	}
	// ...nor one that is not enrolled
	w.supportLogs(w.node[A])
	w.a.St.DB.Exec(w.ctx, `UPDATE nodes SET status='pending' WHERE id=$1::uuid`, w.node[A])
	aadmin.do(t, "POST", collect, nil)
	if w.count(`SELECT count(*) FROM node_log_bundles WHERE node_id=$1::uuid`, w.node[A]) != 0 {
		t.Fatal("log collection requested from a node that is not active")
	}
	w.a.St.DB.Exec(w.ctx, `UPDATE nodes SET status='active' WHERE id=$1::uuid`, w.node[A])

	// read-only users and other tenants cannot ask
	c, _ = aro.do(t, "POST", collect, nil)
	expect(t, "read-only collect", c, 403)
	c, _ = badmin.do(t, "POST", collect, nil)
	expect(t, "other tenant collect", c, 404)
	if w.count(`SELECT count(*) FROM node_log_bundles`) != 0 {
		t.Fatal("unauthorised log collection request was stored")
	}

	// the writer asks; asking twice does not queue twice
	c, _ = aadmin.do(t, "POST", collect, nil)
	expect(t, "collect", c, 303)
	aadmin.do(t, "POST", collect, nil)
	if w.count(`SELECT count(*) FROM node_log_bundles WHERE node_id=$1::uuid AND status='requested' AND requested_by='aadmin@test'`, w.node[A]) != 1 {
		t.Fatal("expected exactly one pending request recorded against the user")
	}
	if w.count(`SELECT count(*) FROM audit WHERE action='node.logs_request'`) != 1 {
		t.Error("request not audited")
	}
	var bid string
	w.a.St.DB.QueryRow(w.ctx, `SELECT id::text FROM node_log_bundles WHERE node_id=$1::uuid`, w.node[A]).Scan(&bid)
	c, body := aadmin.do(t, "GET", "/nodes/"+w.node[A], nil)
	if c != 200 || !strings.Contains(body, "waiting for the node") {
		t.Error("node page does not show the pending request")
	}

	// it reaches the node at its next check-in, but only a node that can handle it
	id := w.identity(A)
	r, err := w.a.checkin(w.ctx, id, &proto.CheckinReq{Stats: proto.Stats{Features: []string{proto.FeatureLogs}}, ConfigHash: "x"}, "10.0.0.5")
	if err != nil || r.CollectLogs != bid {
		t.Fatalf("check-in did not carry the request: %+v %v", r, err)
	}
	r, err = w.a.checkin(w.ctx, id, &proto.CheckinReq{ConfigHash: "x"}, "10.0.0.5")
	if err != nil || r.CollectLogs != "" {
		t.Fatalf("an old node must not be handed a request: %+v %v", r, err)
	}
	if r, _ = w.a.checkin(w.ctx, w.identity(B), &proto.CheckinReq{Stats: proto.Stats{Features: []string{proto.FeatureLogs}}, ConfigHash: "x"}, "10.0.0.6"); r.CollectLogs != "" {
		t.Fatal("another node was handed this node's request")
	}

	// delivery (two chunks, the first one repeated: retries are harmless)
	z := goodZip(t)
	half := len(z) / 2
	if err := w.a.receiveLogs(w.ctx, id, &proto.LogUpload{ID: bid, Index: 0, Data: z[:half]}); err != nil {
		t.Fatal(err)
	}
	if err := w.a.receiveLogs(w.ctx, id, &proto.LogUpload{ID: bid, Index: 0, Data: z[:half]}); err != nil {
		t.Fatal(err)
	}
	if st, _ := w.bundleStatus(bid); st != "receiving" {
		t.Fatalf("status after first chunk: %s", st)
	}
	if r, _ := w.a.checkin(w.ctx, id, &proto.CheckinReq{Stats: proto.Stats{Features: []string{proto.FeatureLogs}}, ConfigHash: "x"}, "10.0.0.5"); r.CollectLogs != bid {
		t.Fatal("a half-delivered bundle must still be requested")
	}
	if err := w.a.receiveLogs(w.ctx, id, &proto.LogUpload{ID: bid, Index: 1, Final: true, Data: z[half:]}); err != nil {
		t.Fatal(err)
	}
	if st, e := w.bundleStatus(bid); st != "ready" || e != "" {
		t.Fatalf("status after final chunk: %s %q", st, e)
	}
	if r, _ := w.a.checkin(w.ctx, id, &proto.CheckinReq{Stats: proto.Stats{Features: []string{proto.FeatureLogs}}, ConfigHash: "x"}, "10.0.0.5"); r.CollectLogs != "" {
		t.Fatal("a delivered bundle is still being requested")
	}
	// a late duplicate after completion changes nothing
	if err := w.a.receiveLogs(w.ctx, id, &proto.LogUpload{ID: bid, Index: 1, Final: true, Data: []byte("garbage")}); err != nil {
		t.Fatal(err)
	}
	if st, _ := w.bundleStatus(bid); st != "ready" {
		t.Fatal("late chunk changed a finished bundle")
	}

	// download: exactly the bytes the node sent, as a zip attachment
	dl := "/nodes/" + w.node[A] + "/logs/" + bid + "/download"
	for _, who := range []*actor{aadmin, aro} {
		resp, err := who.cl.Get(who.w.srv.URL + dl)
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		got.ReadFrom(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/zip" || !bytes.Equal(got.Bytes(), z) {
			t.Fatalf("download: status %d type %q, %d bytes (want %d)", resp.StatusCode, resp.Header.Get("Content-Type"), got.Len(), len(z))
		}
		if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="radman-node-alpha-node-logs-`) || !strings.HasSuffix(cd, `.zip"`) {
			t.Errorf("Content-Disposition %q", cd)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Error("log bundles must not be cached")
		}
	}
	if w.count(`SELECT count(*) FROM audit WHERE action='node.logs_download'`) != 2 {
		t.Error("downloads not audited")
	}
	// the node page now offers it
	_, body = aadmin.do(t, "GET", "/nodes/"+w.node[A], nil)
	if !strings.Contains(body, dl) {
		t.Error("download link missing on the node page")
	}
	// another tenant, and another node's URL, cannot reach it
	c, _ = badmin.do(t, "GET", dl, nil)
	expect(t, "other tenant download", c, 404)
	c, _ = badmin.do(t, "GET", "/nodes/"+w.node[B]+"/logs/"+bid+"/download", nil)
	expect(t, "download via another node's path", c, 404)
	c, _ = aadmin.do(t, "GET", "/nodes/"+w.node[A]+"/logs/not-a-uuid/download", nil)
	expect(t, "malformed bundle id", c, 404)

	// delete: needs write access in the owning tenant
	del := "/nodes/" + w.node[A] + "/logs/" + bid + "/delete"
	c, _ = aro.do(t, "POST", del, nil)
	expect(t, "read-only delete", c, 403)
	c, _ = badmin.do(t, "POST", del, nil)
	expect(t, "other tenant delete", c, 404)
	if w.count(`SELECT count(*) FROM node_log_bundles WHERE id=$1::uuid`, bid) != 1 {
		t.Fatal("bundle deleted by someone without permission")
	}
	c, _ = aadmin.do(t, "POST", del, nil)
	expect(t, "delete", c, 303)
	if w.count(`SELECT count(*) FROM node_log_bundles WHERE id=$1::uuid`, bid)+w.count(`SELECT count(*) FROM node_log_chunks WHERE bundle_id=$1::uuid`, bid) != 0 {
		t.Fatal("bundle or its chunks survived deletion")
	}
}

// ---- what a node is allowed to upload ----

func TestReceiveLogsRejectsBadUploads(t *testing.T) {
	w := newWorld(t)
	A, B := "Alpha", "Bravo"
	a, ctx := w.a, w.ctx
	idA, idB := w.identity(A), w.identity(B)
	good := goodZip(t)

	// a node cannot write into another node's request, or an invented one
	bid := w.newBundle(t, w.node[A])
	if err := a.receiveLogs(ctx, idB, &proto.LogUpload{ID: bid, Index: 0, Final: true, Data: good}); err == nil {
		t.Error("node B delivered into node A's request")
	}
	if st, _ := w.bundleStatus(bid); st != "requested" || w.count(`SELECT count(*) FROM node_log_chunks`) != 0 {
		t.Error("foreign upload left a trace")
	}
	for _, id := range []string{"", "nope", "00000000-0000-0000-0000-000000000000", "' OR 1=1 --"} {
		if err := a.receiveLogs(ctx, idA, &proto.LogUpload{ID: id, Final: true, Data: good}); err == nil {
			t.Errorf("upload for bundle id %q accepted", id)
		}
	}
	if err := a.receiveLogs(ctx, idA, nil); err == nil {
		t.Error("nil upload accepted")
	}

	// malformed chunks
	for name, up := range map[string]*proto.LogUpload{
		"negative index": {ID: bid, Index: -1, Data: good},
		"huge index":     {ID: bid, Index: 100000, Data: good},
		"oversize chunk": {ID: bid, Index: 0, Data: make([]byte, proto.LogChunkBytes+1)},
	} {
		if err := a.receiveLogs(ctx, idA, up); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// content that is not a plain zip of node logs fails the bundle (and says why), and leaves no data behind
	bad := map[string][]byte{
		"not a zip":        []byte("this is not a zip file at all"),
		"truncated zip":    good[:len(good)-30],
		"path traversal":   makeZip(t, map[string]string{"../../etc/cron.d/x": "boom", "info.txt": "i"}),
		"absolute path":    makeZip(t, map[string]string{"/etc/passwd": "x"}),
		"unexpected name":  makeZip(t, map[string]string{"logs/../../x.log": "x"}),
		"executable":       makeZip(t, map[string]string{"run.sh": "#!/bin/sh"}),
		"nested directory": makeZip(t, map[string]string{"logs/sub/node-2026-01-01.log": "x"}),
		"empty zip":        makeZip(t, nil),
	}
	for name, z := range bad {
		b := w.newBundle(t, w.node[A])
		err := a.receiveLogs(ctx, idA, &proto.LogUpload{ID: b, Index: 0, Final: true, Data: z})
		st, msg := w.bundleStatus(b)
		if err != nil || st != "failed" || msg == "" {
			t.Errorf("%s: err=%v status=%s error=%q (want failed with a reason)", name, err, st, msg)
		}
		if w.count(`SELECT count(*) FROM node_log_chunks WHERE bundle_id=$1::uuid`, b) != 0 {
			t.Errorf("%s: chunks kept for a failed bundle", name)
		}
		resp, _ := w.as(t, "gadmin", "").cl.Get(w.srv.URL + "/nodes/" + w.node[A] + "/logs/" + b + "/download")
		if resp != nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				t.Errorf("%s: a failed bundle can be downloaded", name)
			}
		}
	}

	// a final chunk with a gap is refused and the bundle stays open so the node can retry
	b := w.newBundle(t, w.node[A])
	a.receiveLogs(ctx, idA, &proto.LogUpload{ID: b, Index: 0, Data: good[:10]})
	if err := a.receiveLogs(ctx, idA, &proto.LogUpload{ID: b, Index: 2, Final: true, Data: good[10:]}); err == nil {
		t.Error("bundle with a missing chunk was accepted")
	}
	if st, _ := w.bundleStatus(b); st == "ready" || st == "failed" {
		t.Errorf("a gap must leave the bundle open, got %s", st)
	}
	// ...and the retry (whole bundle again) completes it, discarding the stray chunk
	if err := a.receiveLogs(ctx, idA, &proto.LogUpload{ID: b, Index: 0, Final: true, Data: good}); err != nil {
		t.Fatal(err)
	}
	if st, _ := w.bundleStatus(b); st != "ready" || w.count(`SELECT count(*) FROM node_log_chunks WHERE bundle_id=$1::uuid`, b) != 1 {
		t.Errorf("retry did not complete cleanly: %s", st)
	}

	// total size is capped across chunks
	big := w.newBundle(t, w.node[A])
	for i := 0; ; i++ {
		part := append([]byte("PK\x03\x04"), make([]byte, proto.LogChunkBytes-4)...)
		if i > 0 {
			part = make([]byte, proto.LogChunkBytes)
		}
		a.receiveLogs(ctx, idA, &proto.LogUpload{ID: big, Index: i, Data: part})
		if st, _ := w.bundleStatus(big); st == "failed" {
			break
		}
		if i > maxLogChunks {
			t.Fatal("size limit never enforced")
		}
	}
	if _, msg := w.bundleStatus(big); !strings.Contains(msg, "size limit") {
		t.Errorf("oversize reason: %q", msg)
	}

	// the node reporting that it could not build the bundle ends the request
	e := w.newBundle(t, w.node[A])
	if err := a.receiveLogs(ctx, idA, &proto.LogUpload{ID: e, Error: "disk full"}); err != nil {
		t.Fatal(err)
	}
	if st, msg := w.bundleStatus(e); st != "failed" || !strings.Contains(msg, "disk full") {
		t.Errorf("node-reported error: %s %q", st, msg)
	}
	if err := a.receiveLogs(ctx, idA, &proto.LogUpload{ID: w.newBundle(t, w.node[A]), Error: strings.Repeat("x", 5000)}); err != nil {
		t.Fatal(err)
	}
	var longest int
	a.St.DB.QueryRow(ctx, `SELECT max(length(error)) FROM node_log_bundles`).Scan(&longest)
	if longest > 400 {
		t.Errorf("a node-supplied error message was stored with %d characters", longest)
	}
}

// ---- housekeeping ----

func TestLogBundleCleanup(t *testing.T) {
	w := newWorld(t)
	a, ctx := w.a, w.ctx
	age := func(bid string, d time.Duration) {
		a.St.DB.Exec(ctx, `UPDATE node_log_bundles SET requested_at=now()-make_interval(secs => $2) WHERE id=$1::uuid`, bid, d.Seconds())
	}
	day := 24 * time.Hour

	stale := w.newBundle(t, w.node["Alpha"])
	age(stale, 8*day) // never answered
	waiting := w.newBundle(t, w.node["Alpha"])
	age(waiting, 2*day) // still within the allowance
	expired := w.newBundle(t, w.node["Alpha"])
	a.St.DB.Exec(ctx, `UPDATE node_log_bundles SET status='ready' WHERE id=$1::uuid`, expired)
	age(expired, 15*day)

	a.cleanupLogBundles(ctx)
	if st, e := w.bundleStatus(stale); st != "failed" || e == "" {
		t.Errorf("unanswered request after 8 days: %s %q", st, e)
	}
	if st, _ := w.bundleStatus(waiting); st != "requested" {
		t.Errorf("a recent request was expired: %s", st)
	}
	if st, _ := w.bundleStatus(expired); st != "" {
		t.Errorf("a 15-day-old bundle was kept: %s", st)
	}

	// only the newest few are kept per node, and other nodes are unaffected
	for i := 0; i < 8; i++ {
		b := w.newBundle(t, w.node["Bravo"])
		a.St.DB.Exec(ctx, `UPDATE node_log_bundles SET status='ready' WHERE id=$1::uuid`, b)
		age(b, time.Duration(i)*time.Hour)
	}
	a.cleanupLogBundles(ctx)
	if n := w.count(`SELECT count(*) FROM node_log_bundles WHERE node_id=$1::uuid`, w.node["Bravo"]); n != maxLogBundlesPerNode {
		t.Errorf("kept %d bundles for the node, want %d", n, maxLogBundlesPerNode)
	}
	if w.count(`SELECT count(*) FROM node_log_bundles WHERE node_id=$1::uuid AND requested_at < now()-interval '4 hours 30 minutes'`, w.node["Bravo"]) != 0 {
		t.Error("the oldest bundles should be the ones removed")
	}
	if w.count(`SELECT count(*) FROM node_log_bundles WHERE node_id=$1::uuid`, w.node["Alpha"]) != 2 {
		t.Error("cleanup touched another node's bundles")
	}
}
