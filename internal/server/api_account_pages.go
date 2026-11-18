package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/X4Applegate/caddyui/internal/porkbun"
	totplib "github.com/pquerna/otp/totp"
)

type caddyfileJSONContextKey struct{}

func (s *Server) renderCaddyfileImport(w http.ResponseWriter, r *http.Request, data map[string]any) {
	if r.Context().Value(caddyfileJSONContextKey{}) == nil {
		s.render(w, r, "caddyfile_import.html", data)
		return
	}
	if msg, _ := data["Error"].(string); msg != "" {
		if hint, _ := data["Hint"].(string); hint != "" {
			msg += " " + hint
		}
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	rows := []map[string]string{}
	if results, ok := data["Results"].([]caddyfileImportResult); ok {
		rows = make([]map[string]string, 0, len(results))
		for _, item := range results {
			rows = append(rows, map[string]string{"head": item.Head, "status": item.Status, "kind": item.Kind, "message": item.Message})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"created": data["Created"], "proxies": data["CreatedProxy"], "redirects": data["CreatedRedir"], "raw": data["CreatedRaw"], "results": rows,
	})
}

func (s *Server) applyImportResult(r *http.Request, result *caddy.ImportResult) (int, int, int) {
	taken := map[string]struct{}{}
	if existing, err := models.ListProxyHosts(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
		for _, host := range existing {
			for _, domain := range host.DomainList() {
				taken[strings.ToLower(domain)] = struct{}{}
			}
		}
	}
	if existing, err := models.ListRedirectionHosts(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
		for _, host := range existing {
			for _, domain := range host.DomainList() {
				taken[strings.ToLower(domain)] = struct{}{}
			}
		}
	}
	if existing, err := models.ListRawRoutes(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
		for _, route := range existing {
			for _, domain := range rawRouteHosts(route) {
				taken[strings.ToLower(domain)] = struct{}{}
			}
		}
	}
	claim := func(domains []string) bool {
		for _, domain := range domains {
			if _, ok := taken[strings.ToLower(domain)]; ok {
				return false
			}
		}
		for _, domain := range domains {
			taken[strings.ToLower(domain)] = struct{}{}
		}
		return true
	}
	cu := s.currentUser(r)
	nProxy, nRedir, nRaw := 0, 0, 0
	for i := range result.Proxies {
		proxy := result.Proxies[i]
		if !claim(proxy.DomainList()) {
			continue
		}
		if msg := s.validateProxyUpstreamsForUser(cu, &proxy); msg != "" {
			log.Printf("import: skipped proxy host %q: refused by the non-admin upstream guard", proxy.Domains)
			continue
		}
		if _, err := models.CreateProxyHost(s.DB, s.currentServerID(r), 0, &proxy); err == nil {
			nProxy++
		}
	}
	for i := range result.Redirect {
		redirect := result.Redirect[i]
		if !claim(redirect.DomainList()) {
			continue
		}
		if _, err := models.CreateRedirectionHost(s.DB, s.currentServerID(r), 0, &redirect); err == nil {
			nRedir++
		}
	}
	for i := range result.Passthrough {
		route := result.Passthrough[i]
		if !claim(rawRouteHosts(route)) {
			continue
		}
		if _, err := models.CreateRawRoute(s.DB, s.currentServerID(r), 0, &route); err == nil {
			nRaw++
		}
	}
	return nProxy, nRedir, nRaw
}

func (s *Server) apiV1ImportPreview(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireUser(w, r) == nil {
		return
	}
	result, err := s.caddyForRequest(r).Import()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": err.Error(), "proxies": []string{}, "redirects": []string{}, "routes": []string{}})
		return
	}
	proxies := make([]map[string]any, 0, len(result.Proxies))
	for _, proxy := range result.Proxies {
		proxies = append(proxies, map[string]any{
			"domains": proxy.Domains, "destination": fmt.Sprintf("%s://%s:%d", proxy.ForwardScheme, proxy.ForwardHost, proxy.ForwardPort),
		})
	}
	redirects := make([]map[string]any, 0, len(result.Redirect))
	for _, redirect := range result.Redirect {
		redirects = append(redirects, map[string]any{
			"domains": redirect.Domains, "destination": fmt.Sprintf("%s://%s", redirect.ForwardScheme, redirect.ForwardDomain), "code": redirect.ForwardHTTPCode,
		})
	}
	routes := make([]map[string]string, 0, len(result.Passthrough))
	for _, route := range result.Passthrough {
		routes = append(routes, map[string]string{"label": route.Label})
	}
	skipped := result.Skipped
	if skipped == nil {
		skipped = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"proxies": proxies, "redirects": redirects, "routes": routes, "skipped": skipped,
	})
}

func (s *Server) apiV1Import(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	result, err := s.caddyForRequest(r).Import()
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	nProxy, nRedir, nRaw := s.applyImportResult(r, result)
	detail := fmt.Sprintf("proxies=%d redirects=%d passthrough=%d", nProxy, nRedir, nRaw)
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "import", "", detail, true)
	writeJSON(w, http.StatusOK, map[string]any{"proxies": nProxy, "redirects": nRedir, "routes": nRaw})
}

func (s *Server) apiV1CaddyfileImport(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireUser(w, r) == nil {
		return
	}
	var body struct {
		Caddyfile    string `json:"caddyfile"`
		AutoClassify *bool  `json:"auto_classify"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	form := url.Values{"caddyfile": {body.Caddyfile}}
	if body.AutoClassify != nil && !*body.AutoClassify {
		form.Set("auto_classify", "off")
	}
	cloned := r.Clone(context.WithValue(r.Context(), caddyfileJSONContextKey{}, true))
	cloned.Form = form
	cloned.PostForm = form
	s.postCaddyfileImport(w, cloned)
}

func (s *Server) apiV1PorkbunDomains(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireUser(w, r) == nil {
		return
	}
	apiKey, _ := models.GetSetting(s.DB, settingPBAPIKey)
	secretKey, _ := models.GetSetting(s.DB, settingPBSecretKey)
	if apiKey == "" || secretKey == "" {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false, "domains": []string{}, "error": "Porkbun API credentials are not configured."})
		return
	}
	domains, err := porkbun.New(apiKey, secretKey).ListDomains()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": true, "domains": []string{}, "error": err.Error()})
		return
	}
	names := make([]string, 0, len(domains))
	for _, domain := range domains {
		names = append(names, domain.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "domains": names})
}

func (s *Server) apiV1PorkbunImport(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	domain := strings.TrimSpace(body.Domain)
	if domain == "" {
		writeJSONError(w, http.StatusBadRequest, "domain is required")
		return
	}
	apiKey, _ := models.GetSetting(s.DB, settingPBAPIKey)
	secretKey, _ := models.GetSetting(s.DB, settingPBSecretKey)
	if apiKey == "" || secretKey == "" {
		writeJSONError(w, http.StatusBadRequest, "Porkbun credentials are not configured")
		return
	}
	bundle, err := porkbun.New(apiKey, secretKey).RetrieveSSL(domain)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	ownerID := int64(0)
	if cu.Role != models.RoleAdmin {
		ownerID = cu.ID
	}
	id, err := models.CreateCertificate(s.DB, s.currentServerID(r), ownerID, &models.Certificate{
		Name: domain, Domains: domain, Source: models.CertSourcePEM, CertPEM: bundle.CertificateChain, KeyPEM: bundle.PrivateKey,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "cert_create", fmt.Sprintf("cert:%d", id), domain+" (Porkbun import)", true)
	s.trySyncCaddy(s.currentServerID(r), true)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "domain": domain})
}

func (s *Server) apiV1TOTP(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	out := map[string]any{"enabled": cu.TOTPEnabled, "backup_codes": backupCodeCount(cu)}
	if !cu.TOTPEnabled {
		key, err := totplib.Generate(totplib.GenerateOpts{Issuer: "CaddyUI", AccountName: cu.Email})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out["secret"] = key.Secret()
		out["otpauth"] = key.URL()
	}
	writeJSON(w, http.StatusOK, out)
}

func backupCodeCount(u *models.User) int {
	if u == nil || u.BackupCodes == "" {
		return 0
	}
	var hashes []string
	if json.Unmarshal([]byte(u.BackupCodes), &hashes) != nil {
		return 0
	}
	return len(hashes)
}

func (s *Server) apiV1TOTPUpdate(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireUser(w, r)
	if cu == nil {
		return
	}
	var body struct {
		Action   string `json:"action"`
		Secret   string `json:"secret"`
		Code     string `json:"code"`
		Password string `json:"current_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Action == "disable" {
		if !s.reauthenticated(cu, body.Password) {
			writeJSONError(w, http.StatusBadRequest, "Enter your current password to change two-factor settings.")
			return
		}
		if err := models.SetUserTOTP(s.DB, cu.ID, "", false); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	if !totplib.Validate(strings.TrimSpace(body.Code), body.Secret) {
		writeJSONError(w, http.StatusBadRequest, "Invalid code — try again.")
		return
	}
	if err := models.SetUserTOTP(s.DB, cu.ID, body.Secret, true); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	codes, err := models.GenerateBackupCodes(10)
	if err == nil {
		_ = models.SaveBackupCodes(s.DB, cu.ID, codes)
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "backup_codes": codes})
}

func (s *Server) apiV1Meta(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireUser(w, r) == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"database": string(appdb.BackendOf(s.DB))})
}

func (s *Server) apiSetupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := models.CountUsers(s.DB)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needs_setup": n == 0})
}

func (s *Server) apiSetup(w http.ResponseWriter, r *http.Request) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	n, err := models.CountUsers(s.DB)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n > 0 {
		writeJSONError(w, http.StatusConflict, "An administrator already exists")
		return
	}
	var body struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
		Confirm  string `json:"password_confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	email := strings.TrimSpace(body.Email)
	if email == "" || body.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "Email and password required")
		return
	}
	if body.Password != body.Confirm {
		writeJSONError(w, http.StatusBadRequest, "Passwords do not match")
		return
	}
	if len(body.Password) < 8 {
		writeJSONError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, err := models.CreateUser(s.DB, email, hash, strings.TrimSpace(body.Name), models.RoleAdmin)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	token, exp, err := auth.CreateSessionWithTTL(s.DB, id, s.sessionTTL())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auth.SetSessionCookie(w, r, token, exp)
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (s *Server) apiForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	email := strings.TrimSpace(strings.ToLower(body.Email))
	if email == "" {
		writeJSONError(w, http.StatusBadRequest, "Enter your email address")
		return
	}
	user, _ := models.GetUserByEmail(s.DB, email)
	if user != nil {
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		token := hex.EncodeToString(raw)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
		expires := time.Now().Add(time.Hour).Unix()
		_ = models.SetSetting(s.DB, "pw_reset_"+hash, fmt.Sprintf("%d:%d", user.ID, expires))
		resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.publicBaseURL(r), token)
		message := fmt.Sprintf("Hello %s,\n\nA password reset was requested for your CaddyUI account.\n\n%s\n", user.Name, resetURL)
		if err := sendEmailTo(s.DB, email, "CaddyUI password reset", message); err != nil {
			log.Printf("forgot-password: sendEmail to %s: %v", sanitizeForLog(email), err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}

func (s *Server) apiResetPasswordStatus(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	writeJSON(w, http.StatusOK, map[string]bool{"valid": s.resetTokenValid(token)})
}

func (s *Server) resetTokenValid(token string) bool {
	if token == "" {
		return false
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	val, _ := models.GetSetting(s.DB, "pw_reset_"+hash)
	return val != "" && validResetToken(val)
}

func (s *Server) apiResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		Confirm  string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	token := strings.TrimSpace(body.Token)
	if !s.resetTokenValid(token) {
		writeJSONError(w, http.StatusBadRequest, "Invalid reset link")
		return
	}
	if len(body.Password) < 8 {
		writeJSONError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}
	if body.Password != body.Confirm {
		writeJSONError(w, http.StatusBadRequest, "Passwords do not match")
		return
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	val, _ := models.GetSetting(s.DB, "pw_reset_"+hash)
	parts := strings.SplitN(val, ":", 2)
	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid reset link")
		return
	}
	pwHash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := models.UpdateUserPassword(s.DB, userID, pwHash); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to update password")
		return
	}
	_ = models.SetSetting(s.DB, "pw_reset_"+hash, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) inviteTokenValid(token string) bool {
	if token == "" {
		return false
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	val, _ := models.GetSetting(s.DB, "invite_"+hash)
	return val != "" && validResetToken(val)
}

func (s *Server) apiAcceptInviteStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"valid": s.inviteTokenValid(r.URL.Query().Get("token"))})
}

func (s *Server) apiAcceptInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		Confirm  string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	token := strings.TrimSpace(body.Token)
	if !s.inviteTokenValid(token) {
		writeJSONError(w, http.StatusBadRequest, "Invalid invitation")
		return
	}
	if len(body.Password) < 8 {
		writeJSONError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}
	if body.Password != body.Confirm {
		writeJSONError(w, http.StatusBadRequest, "Passwords do not match")
		return
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	val, _ := models.GetSetting(s.DB, "invite_"+hash)
	parts := strings.SplitN(val, ":", 2)
	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid invitation")
		return
	}
	pwHash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := models.UpdateUserPassword(s.DB, userID, pwHash); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.SetSetting(s.DB, "invite_"+hash, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiLoginOptions(w http.ResponseWriter, r *http.Request) {
	oc := s.oidcConfig()
	writeJSON(w, http.StatusOK, map[string]any{"oidc": oc.ready(), "oidc_label": oc.ButtonLabel})
}

func (s *Server) apiLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	tok := strings.TrimSpace(body.Token)
	code := strings.TrimSpace(body.Code)
	if ok, err := verifyCaptcha(loadCaptchaConfig(s.DB), r); err != nil || !ok {
		writeJSONError(w, http.StatusBadRequest, "Security check failed. Please try again.")
		return
	}
	val, ok := s.pendingTOTP.Load(tok)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "Session expired. Please log in again.")
		return
	}
	s.pendingTOTP.Delete(tok)
	userID := val.(int64)
	user, err := models.GetUserByID(s.DB, userID)
	if err != nil || user == nil {
		writeJSONError(w, http.StatusBadRequest, "Session expired. Please log in again.")
		return
	}
	if s.totpLockedOut(user.Email) {
		s.pendingTOTPAttempts.Delete(tok)
		writeJSONError(w, http.StatusBadRequest, "Too many failed verification attempts for this account. Please wait 15 minutes and sign in again.")
		return
	}
	valid := totplib.Validate(code, user.TOTPSecret)
	if !valid {
		if ok, _ := models.ConsumeBackupCode(s.DB, userID, user.BackupCodes, code); ok {
			valid = true
		}
	}
	if !valid {
		attemptsAny, _ := s.pendingTOTPAttempts.LoadOrStore(tok, new(int32))
		attempts := atomic.AddInt32(attemptsAny.(*int32), 1)
		_ = models.LogActivity(s.DB, 0, user.Email, "login_totp_fail", "ip:"+clientIPFromRequest(r), "invalid TOTP code", false)
		if attempts >= maxTOTPAttemptsPerToken {
			s.pendingTOTPAttempts.Delete(tok)
			writeJSONError(w, http.StatusBadRequest, "Too many incorrect codes. Please sign in again.")
			return
		}
		s.pendingTOTP.Store(tok, userID)
		writeJSONError(w, http.StatusBadRequest, "Invalid code. Try again.")
		return
	}
	sessionTok, exp, err := auth.CreateSessionWithTTL(s.DB, userID, s.sessionTTL())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auth.SetSessionCookie(w, r, sessionTok, exp)
	_ = models.LogActivity(s.DB, 0, user.Email, "login_totp_success", "ip:"+clientIPFromRequest(r), r.UserAgent(), true)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
