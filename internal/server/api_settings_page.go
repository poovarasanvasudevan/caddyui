package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
)

func (s *Server) apiV1SettingsSection(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	section := settingsSectionSlug(chi.URLParam(r, "section"))
	if section == "" {
		section = defaultSettingsSection
	}
	writeJSON(w, http.StatusOK, s.settingsDocument(r, section))
}

func (s *Server) apiV1UpdateSettingsSection(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	section := settingsSectionSlug(chi.URLParam(r, "section"))
	if section == "" {
		writeJSONError(w, http.StatusNotFound, "unknown settings section")
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	form := url.Values{}
	form.Set("settings_section", section)
	if section == "integrations" {
		form.Set("fleet_integrations_present", "1")
	}
	for key, value := range body {
		if key == "settings_section" || key == "fleet_integrations_present" {
			continue
		}
		switch typed := value.(type) {
		case string:
			form.Set(key, typed)
		case bool:
			if typed {
				form.Set(key, "1")
			} else {
				form.Set(key, "0")
			}
		case float64:
			form.Set(key, strconv.FormatFloat(typed, 'f', -1, 64))
		case []any:
			for _, item := range typed {
				form.Add(key, fmt.Sprint(item))
			}
		default:
			if value != nil {
				form.Set(key, fmt.Sprint(value))
			}
		}
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", r.Header.Get("Cookie"))
	rec := httptest.NewRecorder()
	s.postSettings(rec, req)
	if rec.Code >= 400 {
		writeJSONError(w, rec.Code, strings.TrimSpace(rec.Body.String()))
		return
	}
	writeJSON(w, http.StatusOK, s.settingsDocument(r, section))
}

func (s *Server) settingsDocument(r *http.Request, section string) map[string]any {
	get := func(key string) string {
		value, _ := models.GetSetting(s.DB, key)
		return value
	}
	flag := func(key string) string {
		if get(key) == "1" {
			return "1"
		}
		return "0"
	}
	nav := make([]map[string]string, 0, len(settingsSections))
	for _, item := range settingsSections {
		nav = append(nav, map[string]string{"slug": item.Slug, "label": item.Label, "blurb": item.Blurb})
	}
	servers, _ := models.ListCaddyServers(s.DB)
	access := loadFleetAccessLogConfig(s.DB)
	crowd := loadCrowdSecConfig(s.DB)
	metrics := loadPrometheusMetricsConfig(s.DB)
	accessSelected := integrationServerSelection(servers, access.ServerIDs)
	crowdSelected := integrationServerSelection(servers, crowd.ServerIDs)
	metricsSelected := integrationServerSelection(servers, metrics.ServerIDs)
	serverRows := make([]map[string]any, 0, len(servers))
	for _, server := range servers {
		serverRows = append(serverRows, map[string]any{
			"id": server.ID, "name": server.Name, "admin_url": server.AdminURL, "type": server.Type,
			"status": server.Status, "public_ip": server.PublicIP,
			"access_log": accessSelected[server.ID], "crowdsec": crowdSelected[server.ID], "metrics": metricsSelected[server.ID],
			"scrape": prometheusScrapeTarget(server.AdminURL),
		})
	}
	analyticsCfg := loadAnalyticsConfig(s.DB)
	storage := s.analyticsStorageView()
	var ingest map[string]any
	if s.analyticsIngest != nil {
		snap := s.analyticsIngest.Stats()
		ingest = map[string]any{
			"connections": snap.Connections, "events": snap.Events, "excluded": snap.Excluded, "errors": snap.Errors,
			"healthy": snap.Events > 0,
		}
	}
	locales := make([]map[string]string, 0)
	for _, locale := range translations().Locales() {
		locales = append(locales, map[string]string{"code": locale.Code, "name": locale.Name})
	}
	providers := make([]map[string]any, 0)
	serverIP := s.serverIP()
	hasIP := strings.TrimSpace(serverIP) != ""
	for _, server := range servers {
		if strings.TrimSpace(server.PublicIP) != "" {
			hasIP = true
			break
		}
	}
	cfProxied := get(settingCFProxied) == "1"
	for _, descriptor := range dns.Descriptors() {
		credentials := make([]map[string]any, 0, len(descriptor.Credentials))
		configured := true
		for _, field := range descriptor.Credentials {
			value := get(field.Key)
			set := strings.TrimSpace(value) != ""
			if !set && !field.Optional {
				configured = false
			}
			row := map[string]any{
				"key": field.Key, "label": field.Label, "help": field.Help, "placeholder": field.Placeholder,
				"secret": field.Secret, "optional": field.Optional, "set": set,
			}
			if !field.Secret {
				row["value"] = value
			}
			credentials = append(credentials, row)
		}
		providers = append(providers, map[string]any{
			"id": descriptor.ID, "name": descriptor.DisplayName, "configured": configured, "enabled": configured && hasIP,
			"proxied": descriptor.ID == dns.Cloudflare && cfProxied, "zone_allowlist": strings.Join(s.zoneAllowlist(descriptor.ID), "\n"),
			"zone_key": zoneAllowlistKey(descriptor.ID), "credentials": credentials,
		})
	}
	profiles := make([]map[string]any, 0)
	for _, profile := range s.dnsProfileViews() {
		profiles = append(profiles, map[string]any{
			"id": profile.ID, "name": profile.Name, "token_set": profile.TokenSet, "proxied": profile.Proxied,
			"zone_allowlist": profile.ZoneAllowlistRaw,
		})
	}
	clientIP, viaProxy := s.resolvedClientIP(r)
	aiProvider := get(settingAIProvider)
	if aiProvider == "" {
		aiProvider = "ollama"
	}
	values := map[string]string{
		"site_title": get(settingSiteTitle), "favicon_url": get(settingFaviconURL), "default_locale": get(settingDefaultLocale),
		"fallback_status_code": strconv.Itoa(s.fallbackStatusCode()), "catch_all_404_html": get(settingCatchAll404HTML),
		"global_maintenance": flag(settingGlobalMaintenance), "auto_sync_hours": zeroDefault(get(settingAutoSyncHours)),
		"activity_log_days": get(settingActivityLogDays), "global_strip_response_headers": get(settingGlobalStripResponseHeaders),
		"expectations_auto_rollback": boolText(expectationsAutoRollbackEnabled(s)), "timezone": get(settingTimezone),
		"smtp_host": get(settingSMTPHost), "smtp_port": defaultString(get(settingSMTPPort), "587"),
		"smtp_security": defaultString(get(settingSMTPSecurity), "starttls"), "smtp_username": get(settingSMTPUsername),
		"smtp_from": get(settingSMTPFrom), "smtp_to": get(settingSMTPTo), "smtp_skip_verify": flag(settingSMTPSkipVerify),
		"days_before": defaultString(get(settingNotifyDaysBefore), strconv.Itoa(defaultNotifyDaysBefore)),
		"webhook_url": get(settingNotifyWebhookURL), "webhook_secret": get(settingNotifyWebhookSecret),
		"notify_ntfy_url": get(settingNotifyNtfyURL),
		"server_ip":       serverIP, "dns_verify_resolver": get(settingDNSVerifyResolver), "acme_dns_resolvers": get(settingACMEDNSResolvers),
		"cf_proxied":         boolText(cfProxied),
		"captcha_provider":   normalizeCaptchaProvider(get(settingCaptchaProvider)),
		"turnstile_site_key": get(settingTurnstileSiteKey), "recaptcha_site_key": get(settingRecaptchaSiteKey),
		"recaptcha_min_score": defaultString(get(settingRecaptchaMinScore), "0.5"),
		"trusted_proxies":     get(settingTrustedProxies), "client_ip_headers": get(settingClientIPHeaders),
		"certificate_read_roots": get(settingCertificateReadRoots), "disable_http3": flag(settingDisableHTTP3),
		"admin_allowlist": get(settingAdminAllowlist), "global_ip_blocklist": get(settingGlobalIPBlocklist),
		"oidc_enabled": flag(settingOIDCEnabled), "oidc_issuer": get(settingOIDCIssuer), "oidc_redirect_url": get(settingOIDCRedirectURL),
		"oidc_client_id": get(settingOIDCClientID), "oidc_button_label": get(settingOIDCButtonLabel),
		"oidc_auto_create": flag(settingOIDCAutoCreate), "oidc_allowed_domains": get(settingOIDCAllowedDomains),
		"oidc_default_role": get(settingOIDCDefaultRole), "oidc_groups_claim": get(settingOIDCGroupsClaim),
		"oidc_role_mappings": get(settingOIDCRoleMappings), "session_duration_days": get(settingSessionDays),
		"max_login_attempts": get(settingMaxLoginAttempts), "require_totp": boolText(s.twoFactorRequired()),
		"analytics_enabled": boolText(analyticsCfg.Enabled), "analytics_ingest_target": analyticsCfg.TargetRaw,
		"analytics_soft_start": boolText(analyticsCfg.SoftStart), "analytics_dial_timeout_sec": strconv.Itoa(int(analyticsCfg.DialTimeout.Seconds())),
		"analytics_exclude_ips": analyticsCfg.ExcludeRaw, "analytics_retention_days": strconv.Itoa(analyticsRetentionDays(s)),
		"fleet_access_log_enabled": boolText(access.Enabled), "fleet_access_log_path": access.Path,
		"fleet_access_log_scope": access.Scope, "fleet_access_log_format": access.Format,
		"fleet_access_log_roll_size_mb": strconv.Itoa(access.RollSizeMB), "fleet_access_log_roll_keep": strconv.Itoa(access.RollKeep),
		"fleet_access_log_roll_keep_days": strconv.Itoa(access.RollKeepDays),
		"prometheus_metrics_enabled":      boolText(metrics.Enabled), "prometheus_metrics_per_host": boolText(metrics.PerHost),
		"prometheus_metrics_observe_catchall_hosts": boolText(metrics.ObserveCatchAllHost),
		"crowdsec_enabled":                          boolText(crowd.Enabled), "crowdsec_api_url": crowd.APIURL, "crowdsec_ticker_interval": crowd.Ticker,
		"crowdsec_streaming": boolText(crowd.Streaming), "crowdsec_hard_fails": boolText(crowd.HardFails),
		"crowdsec_excluded_hosts": get(settingCrowdSecExcludeHost), "crowdsec_excluded_paths": get(settingCrowdSecExcludePath),
		"ai_enabled": flag(settingAIEnabled), "ai_provider": aiProvider,
		"ai_ollama_url":         defaultString(get(settingAIOllamaURL), "http://ollama:11434"),
		"ai_ollama_model":       defaultString(get(settingAIOllamaModel), "llama3.2:latest"),
		"ai_ollama_cloud_model": defaultString(get(settingAIOllamaCloudModel), "qwen3-coder:480b-cloud"),
		"ai_anthropic_model":    defaultString(get(settingAIAnthropicModel), "claude-haiku-4-5-20251001"),
		"ai_openai_base_url":    defaultString(get(settingAIOpenAIBaseURL), "https://api.openai.com/v1"),
		"ai_openai_model":       defaultString(get(settingAIOpenAIModel), "gpt-4o-mini"),
		"ai_system_prompt":      get(settingAISystemPrompt), "ai_request_timeout_sec": defaultString(get(settingAIRequestTimeoutSec), strconv.Itoa(defaultAIRequestTimeoutSec)),
		"backup_schedule_enabled": flag(settingBackupScheduleEnabled), "backup_schedule_dir": get(settingBackupScheduleDir),
		"backup_schedule_interval_hours": get(settingBackupScheduleInterval), "backup_schedule_keep": get(settingBackupScheduleKeep),
	}
	label := settingsSectionLabel(section)
	blurb := ""
	for _, item := range settingsSections {
		if item.Slug == section {
			blurb = item.Blurb
		}
	}
	return map[string]any{
		"section": section, "label": label, "blurb": blurb, "nav": nav, "values": values,
		"secrets": map[string]bool{
			"smtp_password": get(settingSMTPPassword) != "", "notify_ntfy_token": strings.TrimSpace(get(settingNotifyNtfyToken)) != "",
			"turnstile_secret_key":    strings.TrimSpace(get(settingTurnstileSecretKey)) != "",
			"recaptcha_secret_key":    strings.TrimSpace(get(settingRecaptchaSecretKey)) != "",
			"oidc_client_secret":      strings.TrimSpace(get(settingOIDCClientSecret)) != "",
			"crowdsec_api_key":        strings.TrimSpace(crowd.APIKey) != "",
			"ai_ollama_cloud_api_key": strings.TrimSpace(get(settingAIOllamaCloudAPIKey)) != "",
			"ai_anthropic_api_key":    strings.TrimSpace(get(settingAIAnthropicAPIKey)) != "",
			"ai_openai_api_key":       strings.TrimSpace(get(settingAIOpenAIAPIKey)) != "",
		},
		"options": map[string]any{
			"timezones": commonTimezones, "timezone_active": activeLocation().String(), "locales": locales,
			"servers": serverRows, "providers": providers, "profiles": profiles,
			"database": string(appdb.BackendOf(s.DB)), "client_ip": clientIP, "client_ip_via_proxy": viaProxy,
			"allowlist_from_env": s.adminAllowlistFromEnv(), "certificate_roots": strings.Join(s.certificateReadRoots(), ", "),
			"oidc_callback": s.publicBaseURL(r) + "/auth/oidc/callback", "analytics_placeholder": defaultAnalyticsIngestTarget,
			"ingest": ingest, "storage": map[string]any{
				"sqlite": storage.SQLite, "db_bytes": storage.DBBytes, "free_bytes": storage.FreePageBytes,
				"prune_running": storage.PruneRunning, "vacuum_possible": storage.VacuumPossible, "vacuum_blocked": storage.VacuumBlockedBy,
			},
		},
	}
}

func boolText(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func zeroDefault(value string) string {
	if strings.TrimSpace(value) == "" {
		return "0"
	}
	return value
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (s *Server) apiRelay(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiUIRequireAdmin(w, r) == nil {
			return
		}
		s.finishRelay(next, w, r)
	}
}

func (s *Server) apiRelayAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiUIRequireUser(w, r) == nil {
			return
		}
		s.finishRelay(next, w, r)
	}
}

func (s *Server) finishRelay(next http.HandlerFunc, w http.ResponseWriter, r *http.Request) {
	rec := httptest.NewRecorder()
	next(rec, r)
	if strings.Contains(rec.Header().Get("Content-Type"), "json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}
	if rec.Code >= 400 {
		writeJSONError(w, rec.Code, strings.TrimSpace(rec.Body.String()))
		return
	}
	if location := rec.Header().Get("Location"); location != "" {
		if parsed, err := url.Parse(location); err == nil {
			if message := parsed.Query().Get("error"); message != "" {
				writeJSONError(w, http.StatusBadRequest, message)
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "location": rec.Header().Get("Location")})
}

func (s *Server) apiTestCrowdSec(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	var body struct {
		ServerID string `json:"server_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	form := url.Values{"server_id": {body.ServerID}}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "/settings/test-crowdsec", strings.NewReader(form.Encode()))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.apiRelay(s.postTestCrowdSec).ServeHTTP(w, req)
}
