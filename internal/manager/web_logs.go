package manager

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type eventRow struct {
	ID   int64
	Time time.Time
	Site string
	Node string
	D    map[string]string
}

func (s *server) queryEvents(r *http.Request, tenantID, kind, site, extra string, args []any, limit int) []eventRow {
	q := `SELECT e.id, e.ts, s.name, n.name, e.data FROM events e LEFT JOIN sites s ON s.id=e.site_id LEFT JOIN nodes n ON n.id=e.node_id WHERE e.tenant_id=$1::uuid AND e.kind=$2`
	a := []any{tenantID, kind}
	if site != "" && isUUID(site) {
		a = append(a, site)
		q += ` AND e.site_id=$` + strconv.Itoa(len(a)) + `::uuid`
	}
	q += extra
	a = append(a, args...)
	q += ` ORDER BY e.ts DESC, e.id DESC LIMIT ` + strconv.Itoa(limit)
	rows, err := s.a.St.RO.Query(r.Context(), q, a...)
	if err != nil {
		s.a.Log.Printf("events query: %v", err)
		return nil
	}
	defer rows.Close()
	var out []eventRow
	for rows.Next() {
		var e eventRow
		var site, node *string
		var raw []byte
		rows.Scan(&e.ID, &e.Time, &site, &node, &raw)
		if site != nil {
			e.Site = *site
		}
		if node != nil {
			e.Node = *node
		}
		json.Unmarshal(raw, &e.D)
		out = append(out, e)
	}
	return out
}

func (s *server) queryAuthEvents(r *http.Request, site, result, q string, limit int) []eventRow {
	extra := ""
	var args []any
	n := 2
	if site != "" && isUUID(site) {
		n++
	}
	if result == "accept" || result == "reject" {
		n++
		extra += ` AND e.data->>'result'=$` + strconv.Itoa(n)
		args = append(args, result)
	}
	if q != "" {
		n++
		extra += ` AND e.data::text ILIKE $` + strconv.Itoa(n)
		args = append(args, "%"+q+"%")
	}
	return s.queryEvents(r, tenantFrom(r.Context()), "auth", site, extra, args, limit)
}

func (s *server) sitesOptions(r *http.Request) []selOpt {
	var out []selOpt
	rows, _ := s.a.St.DB.Query(r.Context(), `SELECT id::text, name FROM sites WHERE tenant_id=$1::uuid ORDER BY name`, tenantFrom(r.Context()))
	for rows.Next() {
		var x selOpt
		rows.Scan(&x.ID, &x.Name)
		out = append(out, x)
	}
	rows.Close()
	return out
}

func (s *server) logsAuth(w http.ResponseWriter, r *http.Request, u *User) {
	site, result, q := r.URL.Query().Get("site"), r.URL.Query().Get("result"), r.URL.Query().Get("q")
	s.render(w, r, u, "logs_auth", page{"Title": "Authentication log", "Events": s.queryAuthEvents(r, site, result, q, 200),
		"Sites": s.sitesOptions(r), "FSite": site, "FResult": result, "FQ": q, "Tab": "auth"})
}

func (s *server) logsAcct(w http.ResponseWriter, r *http.Request, u *User) {
	site := r.URL.Query().Get("site")
	s.render(w, r, u, "logs_acct", page{"Title": "Accounting log", "Events": s.queryEvents(r, tenantFrom(r.Context()), "acct", site, "", nil, 200),
		"Sites": s.sitesOptions(r), "FSite": site, "Tab": "acct"})
}

func (s *server) logsAudit(w http.ResponseWriter, r *http.Request, u *User) {
	type row struct {
		Time                  time.Time
		Actor, Action, Detail string
	}
	var out []row
	q, args := `SELECT ts, actor, action, detail FROM audit WHERE tenant_id=$1::uuid ORDER BY id DESC LIMIT 300`, []any{tenantFrom(r.Context())}
	if s.a.Standalone() { // one installation: the audit trail includes system-level actions (settings, sign-ins)
		q, args = `SELECT ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT 300`, nil
	}
	rows, _ := s.a.St.DB.Query(r.Context(), q, args...)
	for rows.Next() {
		var x row
		rows.Scan(&x.Time, &x.Actor, &x.Action, &x.Detail)
		out = append(out, x)
	}
	rows.Close()
	s.render(w, r, u, "logs_audit", page{"Title": "Audit log", "Rows": out, "Tab": "audit"})
}
