package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

func (s *Server) apiUIRequireUser(w http.ResponseWriter, r *http.Request) *models.User {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
	}
	return cu
}

func (s *Server) apiUIRequireAdmin(w http.ResponseWriter, r *http.Request) *models.User {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return nil
	}
	if cu.Role != models.RoleAdmin {
		writeJSONError(w, http.StatusForbidden, "admin access required")
		return nil
	}
	return cu
}

func nullTime(v sql.NullTime) any {
	if !v.Valid {
		return nil
	}
	return v.Time.UTC()
}

func (s *Server) apiV1Me(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	out := userPublic(cu)
	out["csrf_token"] = s.csrfTokenForRequest(r)
	locales := make([]map[string]string, 0)
	for _, locale := range translations().Locales() {
		locales = append(locales, map[string]string{"code": locale.Code, "name": locale.Name})
	}
	out["locales"] = locales
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiV1UpdateMe(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	var body struct {
		Name            *string `json:"name"`
		Locale          *string `json:"locale"`
		CurrentPassword string  `json:"current_password"`
		NewPassword     string  `json:"new_password"`
		ConfirmPassword string  `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Name != nil {
		name := strings.TrimSpace(*body.Name)
		if name == "" {
			writeJSONError(w, http.StatusBadRequest, "Name cannot be empty")
			return
		}
		if _, err := s.DB.Exec(`UPDATE users SET name = ? WHERE id = ?`, name, cu.ID); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		cu.Name = name
	}
	if body.Locale != nil {
		locale := strings.TrimSpace(*body.Locale)
		if locale != "" && !translations().Has(locale) {
			writeJSONError(w, http.StatusBadRequest, "Unknown language")
			return
		}
		if err := models.UpdateUserLocale(s.DB, cu.ID, locale); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		cu.Locale = locale
	}
	if body.NewPassword != "" || body.CurrentPassword != "" || body.ConfirmPassword != "" {
		if body.NewPassword != body.ConfirmPassword {
			writeJSONError(w, http.StatusBadRequest, "The new passwords do not match")
			return
		}
		if len(body.NewPassword) < 8 {
			writeJSONError(w, http.StatusBadRequest, "Use at least 8 characters")
			return
		}
		user, err := models.GetUserByEmail(s.DB, cu.Email)
		if err != nil || !auth.CheckPassword(user.PasswordHash, body.CurrentPassword) {
			writeJSONError(w, http.StatusBadRequest, "The current password is wrong")
			return
		}
		hash, err := auth.HashPassword(body.NewPassword)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if _, err := s.DB.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, cu.ID); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, userPublic(cu))
}

func userPublic(u *models.User) map[string]any {
	return map[string]any{
		"id":           u.ID,
		"email":        u.Email,
		"name":         u.Name,
		"role":         u.Role,
		"totp_enabled": u.TOTPEnabled,
		"locale":       u.Locale,
	}
}

func (s *Server) apiV1Users(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	users, err := models.ListUsers(s.DB)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(users))
	for i := range users {
		out = append(out, userPublic(&users[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiV1Groups(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	groups, err := models.ListGroups(s.DB)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		out = append(out, map[string]any{
			"id": g.ID, "name": g.Name, "description": g.Description, "member_count": g.MemberCount,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiV1Activity(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireUser(w, r) == nil {
		return
	}
	cu := s.currentUser(r)
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	rows, err := models.ListActivitySearch(s.DB, s.currentServerID(r), 500, search)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows = s.activityVisibleTo(cu, rows)
	if action != "" {
		filtered := rows[:0]
		for _, row := range rows {
			if strings.Contains(row.Action, action) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id": row.ID, "actor": row.Actor, "action": row.Action, "target": row.Target,
			"detail": row.Detail, "success": row.Success, "created_at": row.CreatedAt.UTC(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiV1Sessions(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	var rows *sql.Rows
	var err error
	if cu.Role == models.RoleAdmin {
		rows, err = s.DB.Query(`SELECT s.token, u.email, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.expires_at > ? ORDER BY s.expires_at DESC`, time.Now().UTC())
	} else {
		rows, err = s.DB.Query(`SELECT token, ?, expires_at FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY expires_at DESC`, cu.Email, cu.ID, time.Now().UTC())
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var token, email string
		var expires time.Time
		if err := rows.Scan(&token, &email, &expires); err != nil {
			continue
		}
		out = append(out, map[string]any{"id": token, "email": email, "expires_at": expires.UTC()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiV1RevokeSession(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	token := chi.URLParam(r, "token")
	var err error
	if cu.Role == models.RoleAdmin {
		_, err = s.DB.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	} else {
		_, err = s.DB.Exec(`DELETE FROM sessions WHERE token = ? AND user_id = ?`, token, cu.ID)
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiV1APITokens(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	tokens, err := models.ListAPITokens(s.DB, cu.ID, cu.Role == models.RoleAdmin)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(tokens))
	for _, token := range tokens {
		out = append(out, map[string]any{
			"id": token.ID, "name": token.Name, "scopes": token.Scopes, "email": token.UserEmail,
			"last_used_at": nullTime(token.LastUsedAt), "expires_at": nullTime(token.ExpiresAt),
			"created_at": token.CreatedAt.UTC(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiV1CreateAPIToken(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	var body struct {
		Name      string `json:"name"`
		Scopes    string `json:"scopes"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "My token"
	}
	scopes := body.Scopes
	switch scopes {
	case models.TokenScopeReadOnly, models.TokenScopeProxyWrite:
	default:
		scopes = models.TokenScopeFull
	}
	var expiresAt *time.Time
	if exp := strings.TrimSpace(body.ExpiresAt); exp != "" {
		parsed, err := time.ParseInLocation("2006-01-02", exp, time.UTC)
		if err == nil {
			expiresAt = &parsed
		}
	}
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not generate token")
		return
	}
	rawToken := "cadu_" + base64.RawURLEncoding.EncodeToString(rawBytes)
	sum := sha256.Sum256([]byte(rawToken))
	if _, err := models.CreateAPIToken(s.DB, cu.ID, name, fmt.Sprintf("%x", sum), scopes, expiresAt); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "api_token_create", "token", name, true)
	writeJSON(w, http.StatusCreated, map[string]string{"token": rawToken, "name": name, "scopes": scopes})
}

func (s *Server) apiV1Snapshots(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	rows, err := models.ListSnapshots(s.DB, s.currentServerID(r), 50)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id": row.ID, "note": row.Note, "source": row.Source, "size_kb": row.SizeKB(), "created_at": row.CreatedAt.UTC(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"auto": s.autoSnapshotsEnabled(), "rows": out})
}

func (s *Server) apiV1Layer4(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	rows, err := models.ListLayer4Proxies(s.DB, s.currentServerID(r))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id": row.ID, "name": row.Name, "protocol": row.Protocol, "listen_port": row.ListenPort,
			"upstream_host": row.UpstreamHost, "upstream_port": row.UpstreamPort, "enabled": row.Enabled,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiV1Middleware(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	rows, err := models.ListMiddlewareProfiles(s.DB)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id": row.ID, "name": row.Name, "description": row.Description, "host_count": row.HostCount,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiV1SettingsGeneral(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	keys := []string{settingSiteTitle, settingFaviconURL, settingTimezone, settingFallbackStatus, settingGlobalMaintenance, settingAutoSyncHours, settingActivityLogDays}
	out := map[string]string{}
	for _, key := range keys {
		value, _ := models.GetSetting(s.DB, key)
		out[key] = value
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiV1UpdateSettingsGeneral(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	allowed := map[string]bool{
		settingSiteTitle: true, settingFaviconURL: true, settingTimezone: true, settingFallbackStatus: true,
		settingGlobalMaintenance: true, settingAutoSyncHours: true, settingActivityLogDays: true,
	}
	for key, value := range body {
		if !allowed[key] {
			continue
		}
		if err := models.SetSetting(s.DB, key, strings.TrimSpace(value)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.apiV1SettingsGeneral(w, r)
}

func (s *Server) apiV1AnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	writeJSON(w, http.StatusOK, s.analyticsDashboard(r, cu))
}
