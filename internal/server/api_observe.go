package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

func (s *Server) analyticsHostPermitted(w http.ResponseWriter, r *http.Request, host string) bool {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return false
	}
	if cu.Role == models.RoleAdmin {
		return true
	}
	allowed, err := s.scopedHostsForAnalytics(cu, s.analyticsServerScope(r))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	for _, name := range allowed {
		if name == host {
			return true
		}
	}
	writeJSONError(w, http.StatusNotFound, "not found")
	return false
}

func (s *Server) apiV1AnalyticsRequests(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	serverID := s.analyticsServerScope(r)
	filter := models.InsightFilter{
		From:     time.Now().Add(-windowDuration(r.URL.Query().Get("window"))),
		Host:     host,
		Status:   r.URL.Query().Get("status"),
		Path:     r.URL.Query().Get("path"),
		ClientIP: r.URL.Query().Get("client_ip"),
		UASearch: r.URL.Query().Get("agent"),
		ServerID: serverID,
	}
	if raw := r.URL.Query().Get("from"); raw != "" {
		if unix, err := strconv.ParseInt(raw, 10, 64); err == nil {
			filter.From = time.Unix(unix, 0)
		}
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		if unix, err := strconv.ParseInt(raw, 10, 64); err == nil {
			filter.To = time.Unix(unix, 0)
		}
	}
	if cu.Role != models.RoleAdmin {
		allowed, err := s.scopedHostsForAnalytics(cu, serverID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if host != "" {
			ok := false
			for _, name := range allowed {
				if name == host {
					ok = true
					break
				}
			}
			if !ok {
				writeJSONError(w, http.StatusNotFound, "not found")
				return
			}
		}
		filter.Scoped = true
		filter.OnlyHosts = allowed
	}
	rows, err := models.SearchRequests(s.DB, filter, 100)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	total, _ := models.SearchRequestCount(s.DB, filter)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"ts": row.TS.UTC(), "host": row.Host, "path": row.Path, "method": row.Method,
			"status": row.Status, "client_ip": row.ClientIP, "duration_ms": row.DurationMs,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "rows": out})
}

func (s *Server) apiV1AnalyticsHost(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "host")))
	if host == "" {
		writeJSONError(w, http.StatusBadRequest, "host is required")
		return
	}
	if !s.analyticsHostPermitted(w, r, host) {
		return
	}
	since := time.Now().Add(-windowDuration(r.URL.Query().Get("window")))
	serverID := s.analyticsServerScope(r)
	totals, err := models.AccessTotalsBetween(s.DB, since, time.Now(), host, serverID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	paths, _ := models.TopPaths(s.DB, since, host, 12, serverID)
	clients, _ := models.TopClientIPs(s.DB, since, host, 12, serverID)
	status, _ := models.StatusBucketsSince(s.DB, since, host, serverID)
	pathOut := make([]map[string]any, 0, len(paths))
	for _, path := range paths {
		pathOut = append(pathOut, map[string]any{"path": path.Path, "method": path.Method, "views": path.Views})
	}
	clientOut := make([]map[string]any, 0, len(clients))
	for _, client := range clients {
		clientOut = append(clientOut, map[string]any{"client_ip": client.ClientIP, "views": client.Views})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host": host, "views": totals.Views, "visitors": totals.Visitors,
		"status":  map[string]int{"2xx": status.S2xx, "3xx": status.S3xx, "4xx": status.S4xx, "5xx": status.S5xx, "other": status.SOther},
		"paths":   pathOut,
		"clients": clientOut,
	})
}

func (s *Server) apiV1ProxyHealth(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	host, err := models.GetProxyHost(s.DB, id)
	if err != nil || host == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(cu, host.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	checks, err := models.GetProxyHealthHistory(s.DB, id, 50)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	total, okCount := 0, 0
	out := make([]map[string]any, 0, len(checks))
	for _, check := range checks {
		if check.CheckedAt.After(cutoff) {
			total++
			if check.OK {
				okCount++
			}
		}
		out = append(out, map[string]any{
			"checked_at": check.CheckedAt.UTC(), "ok": check.OK, "status_code": check.StatusCode,
			"latency_ms": check.LatencyMs, "error": check.ErrorMsg,
		})
	}
	uptime := 0.0
	if total > 0 {
		uptime = float64(okCount) / float64(total) * 100
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": host.Domains, "uptime": uptime, "checks": out})
}

func (s *Server) apiV1SnapshotDiff(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	snap, err := models.GetSnapshot(s.DB, id)
	if err != nil || snap == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	var snapObj any
	if err := json.Unmarshal([]byte(snap.ConfigJSON), &snapObj); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "snapshot is corrupted")
		return
	}
	snapPretty, _ := json.MarshalIndent(snapObj, "", "  ")
	live := ""
	liveError := ""
	_, raw, fetchErr := s.caddyForRequest(r).FetchConfig()
	if fetchErr != nil || raw == "" || raw == "null" {
		if fetchErr != nil {
			liveError = fetchErr.Error()
		}
	} else if err := json.Unmarshal([]byte(raw), &snapObj); err == nil {
		if pretty, err := json.MarshalIndent(snapObj, "", "  "); err == nil {
			live = string(pretty)
		}
	}
	additions, removals := 0, 0
	var lines []map[string]string
	if live != "" && string(snapPretty) != live {
		for _, line := range diffLines(string(snapPretty), live) {
			if line.Type == "same" {
				continue
			}
			if line.Type == "add" {
				additions++
			}
			if line.Type == "remove" {
				removals++
			}
			if len(lines) < 80 {
				lines = append(lines, map[string]string{"type": line.Type, "content": line.Content})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": snap.ID, "note": snap.Note, "source": snap.Source, "created_at": snap.CreatedAt.UTC(),
		"live_error": liveError, "additions": additions, "removals": removals, "lines": lines,
	})
}

func (s *Server) apiV1CaddyConfigOutline(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireUser(w, r) == nil {
		return
	}
	_, raw, err := s.caddyForRequest(r).FetchConfig()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": err.Error(), "keys": []string{}, "bytes": 0})
		return
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &object); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": "config is not a JSON object", "keys": []string{}, "bytes": len(raw)})
		return
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := map[string]any{"keys": keys, "bytes": len(raw)}
	if cu := s.currentUser(r); cu != nil && cu.Role == models.RoleAdmin {
		config := raw
		var value any
		if json.Unmarshal([]byte(raw), &value) == nil {
			if pretty, err := json.MarshalIndent(value, "", "  "); err == nil {
				config = string(pretty)
			}
		}
		out["config"] = config
	}
	writeJSON(w, http.StatusOK, out)
}
