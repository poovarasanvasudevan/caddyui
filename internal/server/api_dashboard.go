package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/X4Applegate/caddyui/internal/models"
)

func (s *Server) apiV1Dashboard(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	sid := s.currentServerID(r)
	isAdmin := cu.Role == models.RoleAdmin
	peers := s.groupPeerIDs(r)
	hosts, _ := models.ListProxyHosts(s.DB, sid, cu.ID, isAdmin, peers)
	redirs, _ := models.ListRedirectionHosts(s.DB, sid, cu.ID, isAdmin, peers)
	raws, _ := models.ListRawRoutes(s.DB, sid, cu.ID, isAdmin, peers)
	certs, _ := models.ListCertificatesForUser(s.DB, sid, cu.ID, isAdmin, peers)

	var lastSync *time.Time
	var synced time.Time
	if err := s.DB.QueryRow(
		`SELECT created_at FROM activity_log WHERE server_id = ? AND action = 'sync_applied' ORDER BY id DESC LIMIT 1`, sid,
	).Scan(&synced); err == nil {
		lastSync = &synced
	}

	enabled, disabled := 0, 0
	maintenance := 0
	for _, host := range hosts {
		if host.Enabled {
			enabled++
		} else {
			disabled++
		}
		if host.MaintenanceMode {
			maintenance++
		}
	}
	now := time.Now()
	expiring := 0
	for _, cert := range certs {
		if expiry := parsePEMExpiry(cert.CertPEM); expiry != nil && expiry.After(now) && expiry.Sub(now) < 30*24*time.Hour {
			expiring++
		}
	}
	healthy, down, unknown := 0, 0, 0
	if len(hosts) > 0 {
		ids := make([]int64, 0, len(hosts))
		for _, host := range hosts {
			ids = append(ids, host.ID)
		}
		healthMap, _ := models.LatestProxyHealth(s.DB, ids)
		for _, host := range hosts {
			if !host.Enabled {
				continue
			}
			check, ok := healthMap[host.ID]
			if !ok {
				unknown++
			} else if check.OK {
				healthy++
			} else {
				down++
			}
		}
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	views, visitors := 0, 0
	var bandwidth int64
	seen := map[string]struct{}{}
	var names []string
	for _, host := range hosts {
		names = append(names, host.DomainList()...)
	}
	for _, redirect := range redirs {
		names = append(names, redirect.DomainList()...)
	}
	for _, route := range raws {
		names = append(names, rawRouteHosts(route)...)
	}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		if totals, err := models.AccessTotalsSince(s.DB, today, name, sid); err == nil {
			views += totals.Views
			visitors += totals.Visitors
		}
		if bytes, err := models.BandwidthSince(s.DB, today, name, sid); err == nil {
			bandwidth += bytes
		}
	}

	current, _ := models.GetCaddyServer(s.DB, sid)
	var server map[string]any
	if current != nil {
		server = map[string]any{
			"id": current.ID, "name": current.Name, "admin_url": current.AdminURL,
			"status": current.Status, "type": current.Type, "version": current.Version,
			"last_contact": nullTime(current.LastContactAt),
		}
	}
	serverReady := current != nil && current.Status == models.CaddyServerStatusOnline
	globalMaintenance, _ := models.GetSetting(s.DB, settingGlobalMaintenance)

	fleet := []map[string]any{}
	if servers, err := models.ListCaddyServers(s.DB); err == nil && len(servers) > 1 {
		for _, item := range servers {
			var hostCount int
			_ = s.DB.QueryRow(`SELECT COUNT(*) FROM proxy_hosts WHERE server_id=?`, item.ID).Scan(&hostCount)
			fleet = append(fleet, map[string]any{
				"id": item.ID, "name": item.Name, "admin_url": item.AdminURL, "status": item.Status,
				"type": item.Type, "version": item.Version, "host_count": hostCount, "active": item.ID == sid,
				"last_contact": nullTime(item.LastContactAt),
			})
		}
	}

	recent := []map[string]any{}
	if rows, err := models.ListActivity(s.DB, sid, 60); err == nil {
		rows = s.activityVisibleTo(cu, rows)
		for _, row := range rows {
			if !row.Success || !isEditAction(row.Action) {
				continue
			}
			recent = append(recent, map[string]any{
				"actor": row.Actor, "action": row.Action, "target": row.Target, "detail": row.Detail,
				"created_at": row.CreatedAt,
			})
			if len(recent) >= 8 {
				break
			}
		}
	}

	profiles := map[string]bool{}
	for _, profile := range s.loadDNSProfiles() {
		profiles[profile.ID] = true
	}
	snapshots, _ := models.ListSnapshots(s.DB, sid, 1)
	recommendations := buildDashboardRecommendations(dashboardRecommendationInput{
		IsAdmin: isAdmin, ProxyHosts: hosts, RedirectionHosts: redirs, RawRoutes: raws, Certificates: certs,
		Snapshots: snapshots, DNSProfileIDs: profiles, LastSync: lastSync, DownCount: down, MaintenanceCount: maintenance,
		GlobalMaintenance: globalMaintenance == "1", RequireTOTP: s.twoFactorRequired(),
		AdminAllowlistSet: strings.TrimSpace(mustGetSetting(s.DB, settingAdminAllowlist)) != "",
		AutoSnapshots:     s.autoSnapshotsEnabled(), DismissedUnused: mustGetSetting(s.DB, unusedCertificateDismissalKey(sid)),
		DismissedTOTPPolicy: mustGetSetting(s.DB, settingTOTPPolicyDismissed) == "1",
		CertificateExpiry:   s.customCertificateExpiries(certs), Now: time.Now(),
	})
	attention := make([]map[string]string, 0, len(recommendations))
	for _, item := range recommendations {
		attention = append(attention, map[string]string{
			"severity": item.Severity, "title": item.Title, "detail": item.Detail, "url": item.URL, "action": item.Action,
		})
	}

	proxies := make([]map[string]any, 0)
	for _, host := range hosts {
		if len(proxies) >= 8 {
			break
		}
		proxies = append(proxies, map[string]any{
			"id": host.ID, "domains": host.Domains, "forward_scheme": host.ForwardScheme,
			"forward_host": host.ForwardHost, "forward_port": host.ForwardPort, "enabled": host.Enabled,
			"ssl_enabled": host.SSLEnabled,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"role": cu.Role, "server": server, "last_sync": lastSync,
		"proxy_hosts": len(hosts), "enabled_hosts": enabled, "disabled_hosts": disabled,
		"redirections": len(redirs), "raw_routes": len(raws), "certificates": len(certs),
		"expiring_soon": expiring, "healthy": healthy, "down": down, "unchecked": unknown,
		"maintenance_hosts": maintenance, "global_maintenance": globalMaintenance == "1",
		"today_views": views, "today_visitors": visitors, "today_bandwidth": bandwidth,
		"show_readiness":  isAdmin && readinessIncomplete(serverReady, len(hosts) > 0),
		"readiness_steps": requiredReadinessSteps(serverReady, len(hosts) > 0),
		"fleet":           fleet, "recent": recent, "attention": attention, "proxies": proxies,
	})
}

func (s *Server) apiV1SyncCaddy(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireUser(w, r) == nil {
		return
	}
	if err := s.syncCaddy(s.currentServerID(r), true); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiV1SelectServer(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireUser(w, r) == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := models.GetCaddyServer(s.DB, id); err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name: serverCookie, Value: strconv.FormatInt(id, 10), Path: "/",
		MaxAge: 60 * 60 * 24 * 365, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "server_id": id})
}

func (s *Server) apiV1DownloadSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	s.downloadSnapshot(w, r)
}
