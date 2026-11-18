package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

func parseMemberIDs(raw string) []int64 {
	var ids []int64
	for _, part := range strings.Split(raw, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err == nil && id > 0 {
			ids = append(ids, id)
		}
	}
	return ids
}

func joinMemberIDs(users []models.User) string {
	parts := make([]string, 0, len(users))
	for _, user := range users {
		parts = append(parts, strconv.FormatInt(user.ID, 10))
	}
	return strings.Join(parts, ",")
}

func (s *Server) apiV1GetUser(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	user, err := models.GetUserByID(s.DB, id)
	if err != nil || user == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, userPublic(user))
}

func (s *Server) apiV1CreateUser(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	var body struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	email := strings.TrimSpace(body.Email)
	if email == "" || body.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "Email and password are required")
		return
	}
	if body.Role == "" {
		body.Role = models.RoleView
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
	id, err := models.CreateUser(s.DB, email, hash, strings.TrimSpace(body.Name), body.Role)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "user_create", email, body.Role, true)
	created, _ := models.GetUserByID(s.DB, id)
	writeJSON(w, http.StatusCreated, userPublic(created))
}

func (s *Server) apiV1UpdateUser(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	user, err := models.GetUserByID(s.DB, id)
	if err != nil || user == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	var body struct {
		Name     string `json:"name"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if user.Role == models.RoleAdmin && body.Role != models.RoleAdmin {
		n, _ := models.CountAdmins(s.DB)
		if n <= 1 {
			writeJSONError(w, http.StatusBadRequest, "Can't demote the last admin")
			return
		}
	}
	if err := models.UpdateUser(s.DB, id, strings.TrimSpace(body.Name), body.Role); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Password != "" {
		if len(body.Password) < 8 {
			writeJSONError(w, http.StatusBadRequest, "Password must be at least 8 characters")
			return
		}
		hash, err := auth.HashPassword(body.Password)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := models.UpdateUserPassword(s.DB, id, hash); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "user_update", user.Email, body.Role, true)
	updated, _ := models.GetUserByID(s.DB, id)
	writeJSON(w, http.StatusOK, userPublic(updated))
}

func (s *Server) apiV1GetGroup(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	group, err := models.GetGroup(s.DB, id)
	if err != nil || group == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	members, _ := models.ListGroupMembers(s.DB, id)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": group.ID, "name": group.Name, "description": group.Description, "member_ids": joinMemberIDs(members),
	})
}

func (s *Server) apiV1CreateGroup(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		MemberIDs   string `json:"member_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "Name is required")
		return
	}
	id, err := models.CreateGroup(s.DB, name, strings.TrimSpace(body.Description))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := models.SetGroupMembers(s.DB, id, parseMemberIDs(body.MemberIDs)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "group_create", name, "", true)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": name})
}

func (s *Server) apiV1UpdateGroup(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	group, err := models.GetGroup(s.DB, id)
	if err != nil || group == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		MemberIDs   string `json:"member_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "Name is required")
		return
	}
	if err := models.UpdateGroup(s.DB, id, name, strings.TrimSpace(body.Description)); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := models.SetGroupMembers(s.DB, id, parseMemberIDs(body.MemberIDs)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "group_update", name, "", true)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": name})
}

func layer4Public(p *models.Layer4Proxy) map[string]any {
	return map[string]any{
		"id": p.ID, "name": p.Name, "protocol": p.Protocol, "listen_port": p.ListenPort,
		"upstream_host": p.UpstreamHost, "upstream_port": p.UpstreamPort, "enabled": p.Enabled,
	}
}

func (s *Server) apiV1GetLayer4(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	proxy, err := models.GetLayer4Proxy(s.DB, id)
	if err != nil || proxy == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, layer4Public(proxy))
}

func layer4FromBody(body struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	ListenPort   int    `json:"listen_port"`
	UpstreamHost string `json:"upstream_host"`
	UpstreamPort int    `json:"upstream_port"`
	Enabled      bool   `json:"enabled"`
}) (*models.Layer4Proxy, string) {
	if strings.TrimSpace(body.Name) == "" || strings.TrimSpace(body.UpstreamHost) == "" || body.ListenPort <= 0 || body.UpstreamPort <= 0 {
		return nil, "Name, listen port, upstream host, and upstream port are required"
	}
	return &models.Layer4Proxy{
		Name: body.Name, Protocol: body.Protocol, ListenPort: body.ListenPort,
		UpstreamHost: body.UpstreamHost, UpstreamPort: body.UpstreamPort, Enabled: body.Enabled,
	}, ""
}

func (s *Server) apiV1CreateLayer4(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	var body struct {
		Name         string `json:"name"`
		Protocol     string `json:"protocol"`
		ListenPort   int    `json:"listen_port"`
		UpstreamHost string `json:"upstream_host"`
		UpstreamPort int    `json:"upstream_port"`
		Enabled      bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	proxy, msg := layer4FromBody(body)
	if msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	id, err := models.CreateLayer4Proxy(s.DB, s.currentServerID(r), proxy)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "layer4_create", proxy.Name, "", true)
	proxy.ID = id
	writeJSON(w, http.StatusCreated, layer4Public(proxy))
}

func (s *Server) apiV1UpdateLayer4(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetLayer4Proxy(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	var body struct {
		Name         string `json:"name"`
		Protocol     string `json:"protocol"`
		ListenPort   int    `json:"listen_port"`
		UpstreamHost string `json:"upstream_host"`
		UpstreamPort int    `json:"upstream_port"`
		Enabled      bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	next, msg := layer4FromBody(body)
	if msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	existing.Name = next.Name
	existing.Protocol = next.Protocol
	existing.ListenPort = next.ListenPort
	existing.UpstreamHost = next.UpstreamHost
	existing.UpstreamPort = next.UpstreamPort
	existing.Enabled = next.Enabled
	if err := models.UpdateLayer4Proxy(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "layer4_update", existing.Name, "", true)
	writeJSON(w, http.StatusOK, layer4Public(existing))
}

func middlewarePublic(p *models.MiddlewareProfile) map[string]any {
	return map[string]any{
		"id": p.ID, "name": p.Name, "description": p.Description,
		"security_headers": p.SecurityHeaders, "forward_auth_url": p.ForwardAuthURL, "host_count": p.HostCount,
	}
}

func (s *Server) apiV1GetMiddleware(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	profile, err := models.GetMiddlewareProfile(s.DB, id)
	if err != nil || profile == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, middlewarePublic(profile))
}

func (s *Server) apiV1CreateMiddleware(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	var body struct {
		Name            string `json:"name"`
		Description     string `json:"description"`
		SecurityHeaders bool   `json:"security_headers"`
		ForwardAuthURL  string `json:"forward_auth_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeJSONError(w, http.StatusBadRequest, "Name is required")
		return
	}
	profile := &models.MiddlewareProfile{
		Name: body.Name, Description: body.Description, SecurityHeaders: body.SecurityHeaders, ForwardAuthURL: body.ForwardAuthURL,
	}
	id, err := models.CreateMiddlewareProfile(s.DB, profile)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "middleware_create", profile.Name, "", true)
	profile.ID = id
	writeJSON(w, http.StatusCreated, middlewarePublic(profile))
}

func (s *Server) apiV1UpdateMiddleware(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	profile, err := models.GetMiddlewareProfile(s.DB, id)
	if err != nil || profile == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	var body struct {
		Name            string `json:"name"`
		Description     string `json:"description"`
		SecurityHeaders bool   `json:"security_headers"`
		ForwardAuthURL  string `json:"forward_auth_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeJSONError(w, http.StatusBadRequest, "Name is required")
		return
	}
	profile.Name = body.Name
	profile.Description = body.Description
	profile.SecurityHeaders = body.SecurityHeaders
	profile.ForwardAuthURL = body.ForwardAuthURL
	if err := models.UpdateMiddlewareProfile(s.DB, profile); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "middleware_update", profile.Name, "", true)
	writeJSON(w, http.StatusOK, middlewarePublic(profile))
}

func serverPublic(c *models.CaddyServer) map[string]any {
	return map[string]any{
		"id": c.ID, "name": c.Name, "admin_url": c.AdminURL, "type": c.Type, "tags": c.Tags,
		"admin_username": c.AdminUsername, "has_admin_password": c.AdminPassword != "", "status": c.Status, "version": c.Version,
	}
}

func (s *Server) apiV1GetServer(w http.ResponseWriter, r *http.Request) {
	if s.apiUIRequireAdmin(w, r) == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	server, err := models.GetCaddyServer(s.DB, id)
	if err != nil || server == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, serverPublic(server))
}

func (s *Server) apiV1CreateServer(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	var body struct {
		Name          string `json:"name"`
		AdminURL      string `json:"admin_url"`
		Type          string `json:"type"`
		Tags          string `json:"tags"`
		AdminUsername string `json:"admin_username"`
		AdminPassword string `json:"admin_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	server := &models.CaddyServer{
		Name: body.Name, AdminURL: body.AdminURL, Type: body.Type, Tags: body.Tags,
		AdminUsername: body.AdminUsername, AdminPassword: body.AdminPassword,
	}
	if strings.TrimSpace(server.Name) == "" || strings.TrimSpace(server.AdminURL) == "" {
		writeJSONError(w, http.StatusBadRequest, "Name and admin URL are required")
		return
	}
	if !isValidAdminURL(strings.TrimSpace(server.AdminURL)) {
		writeJSONError(w, http.StatusBadRequest, "Admin URL must start with http://, https://, or unix://")
		return
	}
	id, err := models.CreateCaddyServer(s.DB, server)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "server_create", server.Name, "", true)
	created, _ := models.GetCaddyServer(s.DB, id)
	writeJSON(w, http.StatusCreated, serverPublic(created))
}

func (s *Server) apiV1UpdateServer(w http.ResponseWriter, r *http.Request) {
	cu := s.apiUIRequireAdmin(w, r)
	if cu == nil {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	server, err := models.GetCaddyServer(s.DB, id)
	if err != nil || server == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	var body struct {
		Name          string `json:"name"`
		AdminURL      string `json:"admin_url"`
		Type          string `json:"type"`
		Tags          string `json:"tags"`
		AdminUsername string `json:"admin_username"`
		AdminPassword string `json:"admin_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if strings.TrimSpace(body.Name) == "" || strings.TrimSpace(body.AdminURL) == "" {
		writeJSONError(w, http.StatusBadRequest, "Name and admin URL are required")
		return
	}
	if !isValidAdminURL(strings.TrimSpace(body.AdminURL)) {
		writeJSONError(w, http.StatusBadRequest, "Admin URL must start with http://, https://, or unix://")
		return
	}
	server.Name = body.Name
	server.AdminURL = body.AdminURL
	server.Type = body.Type
	server.Tags = body.Tags
	server.AdminUsername = body.AdminUsername
	if body.AdminPassword != "" {
		server.AdminPassword = body.AdminPassword
	}
	if err := models.UpdateCaddyServer(s.DB, server); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "server_update", server.Name, "", true)
	writeJSON(w, http.StatusOK, serverPublic(server))
}
