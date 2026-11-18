// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// ─── REST JSON API v1 ─────────────────────────────────────────────────────────
//
// All endpoints are under /api/v1/ and live inside the requireAuth middleware
// group, so both session cookies and Bearer API tokens are accepted.
// Write endpoints (POST/PUT/DELETE) additionally require a write-scoped token
// or an admin/write role — the requireWrite middleware enforces that at the
// chi group level.

// GET /api/v1/servers
func (s *Server) apiV1ListServers(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(servers))
	for _, srv := range servers {
		var lastContactAt any
		if srv.LastContactAt.Valid {
			lastContactAt = srv.LastContactAt.Time.UTC()
		}
		entry := map[string]any{
			"id":              srv.ID,
			"name":            srv.Name,
			"type":            srv.Type,
			"status":          srv.Status,
			"version":         srv.Version,
			"tags":            srv.TagList(),
			"last_contact_at": lastContactAt,
		}
		// v2.57.1: a node's admin URL is the address of its admin API. Handing
		// every node's to any account gave a tenant the exact targets for an
		// upstream-guard bypass attempt (and SECURITY.md says it is not exposed).
		if isAdminUser(cu) {
			entry["admin_url"] = srv.AdminURL
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, out)
}

// apiProxyHostInput is the JSON request body for create / update.
type apiProxyHostInput struct {
	Domains                string `json:"domains"`
	ForwardScheme          string `json:"forward_scheme"`
	ForwardHost            string `json:"forward_host"`
	ForwardPort            int    `json:"forward_port"`
	WebsocketSupport       bool   `json:"websocket_support"`
	BlockCommonExploits    bool   `json:"block_common_exploits"`
	SSLEnabled             bool   `json:"ssl_enabled"`
	SSLForced              bool   `json:"ssl_forced"`
	HTTP2Support           bool   `json:"http2_support"`
	Enabled                bool   `json:"enabled"`
	CertificateID          int64  `json:"certificate_id"`
	BasicAuthEnabled       bool   `json:"basicauth_enabled"`
	AccessList             string `json:"access_list"`
	IPBlocklist            string `json:"ip_blocklist"`
	ExtraUpstreams         string `json:"extra_upstreams"`
	CompressionEnabled     bool   `json:"compression_enabled"`
	SecurityHeadersEnabled bool   `json:"security_headers_enabled"`
	TLSMinVersion          string `json:"tls_min_version"`
	// v2.64.0 (discussion #137): client certificate authentication (mTLS).
	// On PATCH, "off" clears the mode — an empty string leaves it unchanged
	// like every other field in this struct.
	ClientAuthMode                    string  `json:"client_auth_mode"`
	ClientAuthCAFiles                 string  `json:"client_auth_ca_files"`
	MaintenanceMode                   bool    `json:"maintenance_mode"`
	MaintenanceMsg                    string  `json:"maintenance_msg"`
	MaxRequestBodyMB                  int     `json:"max_request_body_mb"`
	StickySessions                    bool    `json:"sticky_sessions"`
	LBPolicy                          string  `json:"lb_policy"`
	UpstreamTimeoutSec                int     `json:"upstream_timeout_sec"`
	CORSEnabled                       bool    `json:"cors_enabled"`
	CORSOrigins                       string  `json:"cors_origins"`
	HealthCheckURI                    string  `json:"health_check_uri"`
	HealthCheckIntervalSec            int     `json:"health_check_interval_sec"`
	HealthCheckMethod                 string  `json:"health_check_method"`
	KeepaliveConns                    int     `json:"keepalive_conns"`
	Tags                              string  `json:"tags"`
	Notes                             string  `json:"notes"`
	DisableAccessLog                  bool    `json:"disable_access_log"`
	AddRequestID                      bool    `json:"add_request_id"`
	StripRespHeaders                  string  `json:"strip_resp_headers"`
	BlockedAgents                     string  `json:"blocked_agents"`
	UpstreamSNI                       string  `json:"upstream_sni"`
	HSTSPreload                       bool    `json:"hsts_preload"`
	MaxConnsPerHost                   int     `json:"max_conns_per_host"`
	UpstreamRetries                   int     `json:"upstream_retries"`
	ForceHTTP1                        bool    `json:"force_http1"`
	ProxyProtocol                     string  `json:"proxy_protocol"`
	WWWRedirect                       string  `json:"www_redirect"`
	TrailingSlashRedirect             string  `json:"trailing_slash_redirect"`
	DNSProvider                       string  `json:"dns_provider"`
	DNSProfileID                      string  `json:"dns_profile_id"`
	DNSZoneID                         string  `json:"dns_zone_id"`
	DNSZoneName                       string  `json:"dns_zone_name"`
	DNSSkipRecord                     bool    `json:"dns_skip_record"`
	MiddlewareProfileID               int64   `json:"middleware_profile_id"`
	HSTSIncludeSubdomains             bool    `json:"hsts_include_subdomains"`
	HSTSMaxAgeSec                     int     `json:"hsts_max_age_sec"`
	CSPHeader                         string  `json:"csp_header"`
	CSPReportOnly                     string  `json:"csp_report_only"`
	PermissionsPolicy                 string  `json:"permissions_policy"`
	XFrameOptions                     string  `json:"x_frame_options"`
	ReferrerPolicy                    string  `json:"referrer_policy"`
	CustomReqHeaders                  string  `json:"custom_req_headers"`
	CustomRespHeaders                 string  `json:"custom_resp_headers"`
	MaintenanceStatusCode             int     `json:"maintenance_status_code"`
	MaintenanceRetryAfterSec          int     `json:"maintenance_retry_after_sec"`
	MaintenanceWindowStart            string  `json:"maintenance_window_start"`
	MaintenanceWindowEnd              string  `json:"maintenance_window_end"`
	MaintenanceWindowDays             string  `json:"maintenance_window_days"`
	MaintenanceWindowTimezone         string  `json:"maintenance_window_timezone"`
	MaintenanceAllowedIPs             string  `json:"maintenance_allowed_ips"`
	MaintenanceRedirectURL            string  `json:"maintenance_redirect_url"`
	Expectations                      *string `json:"expectations"`
	InternalTLS                       bool    `json:"internal_tls"`
	BasicAuthUsers                    string  `json:"basicauth_users"`
	PathMatcher                       *string `json:"path_matcher"`
	PathMatcherType                   *string `json:"path_matcher_type"`
	StripPathPrefix                   bool    `json:"strip_path_prefix"`
	StripPathSuffix                   *string `json:"strip_path_suffix"`
	UpstreamPathPrefix                *string `json:"upstream_path_prefix"`
	ForwardAuthURL                    *string `json:"forward_auth_url"`
	ForwardAuthMethod                 *string `json:"forward_auth_method"`
	ForwardAuthCopyHeaders            *string `json:"forward_auth_copy_headers"`
	ForwardAuthHeadersPrefix          *string `json:"forward_auth_headers_prefix"`
	SSLVerifyUpstream                 bool    `json:"ssl_verify_upstream"`
	UpstreamTLSMinVersion             *string `json:"upstream_tls_min_version"`
	UpstreamTLSMaxVersion             *string `json:"upstream_tls_max_version"`
	UpstreamTLSCAPEMFile              *string `json:"upstream_tls_ca_pem_file"`
	UpstreamTLSClientCertFile         *string `json:"upstream_tls_client_cert_file"`
	UpstreamTLSClientKeyFile          *string `json:"upstream_tls_client_key_file"`
	UpstreamTLSRenegotiation          *string `json:"upstream_tls_renegotiation"`
	AdvancedConfig                    *string `json:"advanced_config"`
	FlushImmediate                    bool    `json:"flush_immediate"`
	H2CEnabled                        bool    `json:"h2c_enabled"`
	GRPCWebEnabled                    bool    `json:"grpc_web_enabled"`
	ErrorPageHTML                     *string `json:"error_page_html"`
	ErrorRedirectURL                  *string `json:"error_redirect_url"`
	RobotsTxt                         *string `json:"robots_txt"`
	StripReqHeaders                   *string `json:"strip_req_headers"`
	TrustedProxies                    *string `json:"trusted_proxies"`
	UpstreamHostOverride              *string `json:"upstream_host_override"`
	APIKeyHeader                      *string `json:"api_key_header"`
	APIKeyValue                       string  `json:"api_key_value"`
	BlockEmptyUserAgent               bool    `json:"block_empty_user_agent"`
	CORSAllowCredentials              bool    `json:"cors_allow_credentials"`
	CORSAllowMethods                  *string `json:"cors_allow_methods"`
	CORSAllowHeaders                  *string `json:"cors_allow_headers"`
	CORSExposeHeaders                 *string `json:"cors_expose_headers"`
	CORSMaxAgeSec                     int     `json:"cors_max_age_sec"`
	CompressionMinSizeKB              int     `json:"compression_min_size_kb"`
	CompressionLevel                  int     `json:"compression_level"`
	CompressionPreferGzip             bool    `json:"compression_prefer_gzip"`
	EnableBrotli                      bool    `json:"enable_brotli"`
	HealthCheckTimeoutSec             int     `json:"health_check_timeout_sec"`
	HealthCheckExpectStatus           int     `json:"health_check_expect_status"`
	HealthCheckExpectBody             *string `json:"health_check_expect_body"`
	HealthCheckPort                   int     `json:"health_check_port"`
	StickyCookieName                  *string `json:"sticky_cookie_name"`
	DialTimeoutSec                    int     `json:"dial_timeout_sec"`
	ReadTimeoutSec                    int     `json:"read_timeout_sec"`
	BufferResponses                   bool    `json:"buffer_responses"`
	RequestBuffersKB                  int     `json:"request_buffers_kb"`
	ResponseBuffersKB                 int     `json:"response_buffers_kb"`
	UpstreamReadBufferSizeKB          int     `json:"upstream_read_buffer_size_kb"`
	UpstreamWriteBufferSizeKB         int     `json:"upstream_write_buffer_size_kb"`
	KeepaliveIdleTimeoutSec           int     `json:"keepalive_idle_timeout_sec"`
	KeepaliveDisabled                 bool    `json:"keepalive_disabled"`
	WriteTimeoutSec                   int     `json:"write_timeout_sec"`
	RequestBodyReadTimeoutSec         int     `json:"request_body_read_timeout_sec"`
	ResponseHeaderTimeoutSec          int     `json:"response_header_timeout_sec"`
	MaxConnDurationSec                int     `json:"max_conn_duration_sec"`
	DialFallbackDelayMS               int     `json:"dial_fallback_delay_ms"`
	ForwardProxyURL                   *string `json:"forward_proxy_url"`
	UpstreamNetwork                   *string `json:"upstream_network"`
	DNSResolver                       *string `json:"dns_resolver"`
	ReqHeaderReplace                  *string `json:"req_header_replace"`
	RespHeaderReplace                 *string `json:"resp_header_replace"`
	ResponseCacheControl              *string `json:"response_cache_control"`
	StripServerHeader                 bool    `json:"strip_server_header"`
	StripETag                         bool    `json:"strip_etag"`
	AddContentTypeNosniff             bool    `json:"add_content_type_nosniff"`
	VaryHeader                        *string `json:"vary_header"`
	ServerHeaderValue                 *string `json:"server_header_value"`
	DenyDotfiles                      bool    `json:"deny_dotfiles"`
	BlockedMethods                    *string `json:"blocked_methods"`
	AllowedMethods                    *string `json:"allowed_methods"`
	ForwardClientIP                   bool    `json:"forward_client_ip"`
	StripQueryString                  bool    `json:"strip_query_string"`
	DeleteQueryParams                 *string `json:"delete_query_params"`
	HealthCheckFollowRedirects        bool    `json:"health_check_follow_redirects"`
	HealthCheckHeaders                string  `json:"health_check_headers"`
	BasicAuthRealm                    *string `json:"basicauth_realm"`
	Color                             *string `json:"color"`
	PassiveFailDurationSec            int     `json:"passive_fail_duration_sec"`
	PassiveMaxFails                   int     `json:"passive_max_fails"`
	LBTryDurationSec                  int     `json:"lb_try_duration_sec"`
	LBTryIntervalMS                   int     `json:"lb_try_interval_ms"`
	MaxBufferSizeKB                   int     `json:"max_buffer_size_kb"`
	UpstreamKeepaliveProbes           int     `json:"upstream_keepalive_probes"`
	UpstreamFlushIntervalMS           int     `json:"upstream_flush_interval_ms"`
	PassiveUnhealthyCount             int     `json:"passive_unhealthy_count"`
	LBCookieMaxAgeSec                 int     `json:"lb_cookie_max_age_sec"`
	LBRandomChooseCount               int     `json:"lb_random_choose_count"`
	ResponseCacheTTLSec               int     `json:"response_cache_ttl_sec"`
	UpstreamKeepaliveMaxLifetimeSec   int     `json:"upstream_keepalive_max_lifetime_sec"`
	MonitorMode                       *string `json:"monitor_mode"`
	MonitorMethod                     *string `json:"monitor_method"`
	MonitorExpectStatus               int     `json:"monitor_expect_status"`
	MonitorIntervalSec                int     `json:"monitor_interval_sec"`
	MonitorTimeoutSec                 int     `json:"monitor_timeout_sec"`
	RateLimitEvents                   int     `json:"rate_limit_events"`
	RateLimitWindowSec                int     `json:"rate_limit_window_sec"`
	ProxyRedirectRules                *string `json:"proxy_redirect_rules"`
	AdditionalUpstreamRules           *string `json:"additional_upstream_rules"`
	RetryStatusCodes                  *string `json:"retry_status_codes"`
	DecompressResponse                bool    `json:"decompress_response"`
	RequestIDHeaderName               *string `json:"request_id_header_name"`
	LBCookiePath                      *string `json:"lb_cookie_path"`
	AddReqQueryParams                 *string `json:"add_req_query_params"`
	ErrorPageCodes                    *string `json:"error_page_codes"`
	CORSAllowPrivateNetwork           bool    `json:"cors_allow_private_network"`
	RobotsTxtDisallowAll              bool    `json:"robots_txt_disallow_all"`
	UpstreamHTTPVersions              *string `json:"upstream_http_versions"`
	HealthCheckBody                   *string `json:"health_check_body"`
	AddCanonicalLinkHeader            bool    `json:"add_canonical_link_header"`
	HTTPBasicAuthUpstream             string  `json:"http_basic_auth_upstream"`
	BlockUARegexp                     *string `json:"block_ua_regexp"`
	SecurityTxtBody                   *string `json:"security_txt_body"`
	XRobotsTag                        *string `json:"x_robots_tag"`
	AddForwardedHeader                bool    `json:"add_forwarded_header"`
	LBCookieSecret                    string  `json:"lb_cookie_secret"`
	PassiveUnhealthyStatusCodes       *string `json:"passive_unhealthy_status_codes"`
	HealthCheckContentType            *string `json:"health_check_content_type"`
	BlockPrivateIPs                   bool    `json:"block_private_ips"`
	HTTP2PushPaths                    *string `json:"http2_push_paths"`
	DenyContentTypes                  *string `json:"deny_content_types"`
	UpstreamLocalAddr                 *string `json:"upstream_local_addr"`
	UpstreamTLSCurves                 *string `json:"upstream_tls_curves"`
	UpstreamTLSPins                   *string `json:"upstream_tls_pins"`
	LBHeaderField                     *string `json:"lb_header_field"`
	MaintenanceCustomHeaders          *string `json:"maintenance_custom_headers"`
	DenyExtensions                    *string `json:"deny_extensions"`
	InjectRequestTimestamp            bool    `json:"inject_request_timestamp"`
	AddRespCookies                    *string `json:"add_resp_cookies"`
	StripAcceptEncoding               bool    `json:"strip_accept_encoding"`
	AddUpstreamTimingHeader           bool    `json:"add_upstream_timing_header"`
	BlockRefererRegexp                *string `json:"block_referer_regexp"`
	StripAuthorizationHeader          bool    `json:"strip_authorization_header"`
	RealIPFromHeader                  *string `json:"real_ip_from_header"`
	HealthCheckHostOverride           *string `json:"health_check_host_override"`
	AddXForwardedPort                 bool    `json:"add_x_forwarded_port"`
	LBRetryOn                         *string `json:"lb_retry_on"`
	AddXForwardedHost                 bool    `json:"add_x_forwarded_host"`
	UpstreamTLSCipherSuites           *string `json:"upstream_tls_cipher_suites"`
	AddCacheControlNoStore            bool    `json:"add_cache_control_no_store"`
	DenyRefererEmpty                  bool    `json:"deny_referer_empty"`
	LBCookieHTTPOnly                  bool    `json:"lb_cookie_httponly"`
	LBCookieSecure                    bool    `json:"lb_cookie_secure"`
	LBCookieSameSite                  *string `json:"lb_cookie_same_site"`
	UpstreamTLSEarlyData              bool    `json:"upstream_tls_early_data"`
	AddViaHeader                      bool    `json:"add_via_header"`
	ReqHeaderRename                   *string `json:"req_header_rename"`
	AddExpectCTHeader                 bool    `json:"add_expect_ct_header"`
	ForceUpstreamEncoding             *string `json:"force_upstream_encoding"`
	StripXPoweredBy                   bool    `json:"strip_x_powered_by"`
	AddTimingAllowOrigin              *string `json:"add_timing_allow_origin"`
	CrossOriginOpenerPolicy           *string `json:"cross_origin_opener_policy"`
	CrossOriginResourcePolicy         *string `json:"cross_origin_resource_policy"`
	CrossOriginEmbedderPolicy         *string `json:"cross_origin_embedder_policy"`
	DenyRequestContentType            *string `json:"deny_request_content_type"`
	CompressionExcludeRegexp          *string `json:"compression_exclude_regexp"`
	AddCacheControlPublic             bool    `json:"add_cache_control_public"`
	AddXRequestStart                  bool    `json:"add_x_request_start"`
	AddXForwardedScheme               bool    `json:"add_x_forwarded_scheme"`
	AddLinkPreload                    *string `json:"add_link_preload"`
	DenyPathRegexp                    *string `json:"deny_path_regexp"`
	AddRequestIDToResponse            bool    `json:"add_request_id_to_response"`
	HealthCheckTLSServerName          *string `json:"health_check_tls_server_name"`
	AddXRealIP                        bool    `json:"add_x_real_ip"`
	StripIncomingXForwardedFor        bool    `json:"strip_incoming_x_forwarded_for"`
	HealthCheckTLSInsecureSkipVerify  bool    `json:"health_check_tls_insecure_skip_verify"`
	AddCORSVaryHeader                 bool    `json:"add_cors_vary_header"`
	UpstreamTLSALPN                   *string `json:"upstream_tls_alpn"`
	AddXPoweredBy                     *string `json:"add_x_powered_by"`
	BlockQueryParams                  *string `json:"block_query_params"`
	AddDocumentPolicy                 *string `json:"add_document_policy"`
	AddOriginHeader                   *string `json:"add_origin_header"`
	UpstreamTLSCAPEMInline            *string `json:"upstream_tls_ca_pem_inline"`
	AddServerTimingHeader             bool    `json:"add_server_timing_header"`
	AddClearSiteData                  *string `json:"add_clear_site_data"`
	AddXDNSPrefetchControl            bool    `json:"add_x_dns_prefetch_control"`
	AddAcceptRanges                   bool    `json:"add_accept_ranges"`
	AddContentDisposition             *string `json:"add_content_disposition"`
	UpstreamTLSServerNameFromHost     bool    `json:"upstream_tls_server_name_from_host"`
	AddXPermittedCrossDomainPolicies  *string `json:"add_x_permitted_cross_domain_policies"`
	AddReportTo                       *string `json:"add_report_to"`
	AddNELHeader                      *string `json:"add_nel_header"`
	BlockHTTPMethods                  *string `json:"block_http_methods"`
	AddServiceWorkerAllowed           *string `json:"add_service_worker_allowed"`
	AddAcceptCH                       *string `json:"add_accept_ch"`
	AddAltSvc                         *string `json:"add_alt_svc"`
	AddContentLanguage                *string `json:"add_content_language"`
	AddCriticalCH                     *string `json:"add_critical_ch"`
	AddXDownloadOptions               bool    `json:"add_x_download_options"`
	DenyUserAgentRegexp               *string `json:"deny_user_agent_regexp"`
	AddPragmaNoCache                  bool    `json:"add_pragma_no_cache"`
	HealthCheckUserAgent              *string `json:"health_check_user_agent"`
	AddXRequestPath                   bool    `json:"add_x_request_path"`
	AddXClacksOverhead                *string `json:"add_x_clacks_overhead"`
	AddXUACompatible                  *string `json:"add_x_ua_compatible"`
	ForwardAuthSkipPaths              *string `json:"forward_auth_skip_paths"`
	AddAgeZero                        bool    `json:"add_age_zero"`
	AddSurrogateControl               *string `json:"add_surrogate_control"`
	AddWarningHeader                  *string `json:"add_warning_header"`
	AddXRequestMethod                 bool    `json:"add_x_request_method"`
	AddXRequestQuery                  bool    `json:"add_x_request_query"`
	AddXForwardedUser                 *string `json:"add_x_forwarded_user"`
	AddXRealScheme                    bool    `json:"add_x_real_scheme"`
	AddOriginAgentCluster             bool    `json:"add_origin_agent_cluster"`
	AddXForwardedGroups               *string `json:"add_x_forwarded_groups"`
	AddXForwardedEmail                *string `json:"add_x_forwarded_email"`
	AddXForwardedRoles                *string `json:"add_x_forwarded_roles"`
	BlockQueryParamRegexp             *string `json:"block_query_param_regexp"`
	AddXRequestReferer                bool    `json:"add_x_request_referer"`
	AddXRequestOrigin                 bool    `json:"add_x_request_origin"`
	AddXForwardedURI                  bool    `json:"add_x_forwarded_uri"`
	AddXNoArchive                     bool    `json:"add_x_no_archive"`
	AddXRequestHostname               bool    `json:"add_x_request_hostname"`
	AddXXSSProtectionDisabled         bool    `json:"add_x_xss_protection_disabled"`
	AddXRequestRemotePort             bool    `json:"add_x_request_remote_port"`
	AddXRequestProtocol               bool    `json:"add_x_request_protocol"`
	AddSaveDataVary                   bool    `json:"add_save_data_vary"`
	AddXEnvironment                   *string `json:"add_x_environment"`
	AddXTraceID                       bool    `json:"add_x_trace_id"`
	HealthCheckQueryParams            *string `json:"health_check_query_params"`
	AddXSessionID                     bool    `json:"add_x_session_id"`
	AddXResponseTraceID               bool    `json:"add_x_response_trace_id"`
	AddXRequestLocalAddr              bool    `json:"add_x_request_local_addr"`
	AddXRequestLocalPort              bool    `json:"add_x_request_local_port"`
	AddXRequestPathInfo               bool    `json:"add_x_request_path_info"`
	AddXAuthenticatedUser             *string `json:"add_x_authenticated_user"`
	BlockPathExtensions               *string `json:"block_path_extensions"`
	AddLinkModulePreload              *string `json:"add_link_modulepreload"`
	AddXRemoteUser                    *string `json:"add_x_remote_user"`
	AddXForwardedPath                 bool    `json:"add_x_forwarded_path"`
	AddXGeoCountryCode                *string `json:"add_x_geo_country_code"`
	AddXRequestPriority               *string `json:"add_x_request_priority"`
	HealthCheckBasicAuth              string  `json:"health_check_basic_auth"`
	AddXRealSSLProtocol               bool    `json:"add_x_real_ssl_protocol"`
	AddXRealSSLCipher                 bool    `json:"add_x_real_ssl_cipher"`
	AddXCacheStatus                   *string `json:"add_x_cache_status"`
	DenyRefererRegexp                 *string `json:"deny_referer_regexp"`
	AddXRequestUserAgent              bool    `json:"add_x_request_user_agent"`
	AddReportingEndpoints             *string `json:"add_reporting_endpoints"`
	AddXRequestByteCount              bool    `json:"add_x_request_byte_count"`
	AddXRequestReceivedAt             bool    `json:"add_x_request_received_at"`
	AddXForwardedMethod               bool    `json:"add_x_forwarded_method"`
	AddXRequestOriginalHost           bool    `json:"add_x_request_original_host"`
	AddXRequestDNT                    bool    `json:"add_x_request_dnt"`
	AddXGeoRegion                     *string `json:"add_x_geo_region"`
	AddXRequestSecure                 bool    `json:"add_x_request_secure"`
	AddXRequestQueryCount             bool    `json:"add_x_request_query_count"`
	AddXRequestIDHeaderResponse       bool    `json:"add_x_request_id_header_response"`
	ForceCanonicalHost                *string `json:"force_canonical_host"`
	AddXRobotsNoindexQuick            bool    `json:"add_x_robots_noindex_quick"`
	BlockBotUserAgents                bool    `json:"block_bot_user_agents"`
	BlockAdminPaths                   bool    `json:"block_admin_paths"`
	AddLinkDNSPrefetch                *string `json:"add_link_dns_prefetch"`
	AddLinkPreconnect                 *string `json:"add_link_preconnect"`
	AddXCSPDisabled                   bool    `json:"add_x_csp_disabled"`
	AddXRequestMethodOverride         bool    `json:"add_x_request_method_override"`
	DisableUpstreamCompression        bool    `json:"disable_upstream_compression"`
	MonitorPath                       *string `json:"monitor_path"`
	NodeLocal                         bool    `json:"node_local"`
	RateLimitEnabled                  bool    `json:"rate_limit_enabled"`
	SortOrder                         int     `json:"sort_order"`
	UpstreamMaxRespHeaderKB           int     `json:"upstream_max_resp_header_kb"`
	PassiveUnhealthyLatencyMS         int     `json:"passive_unhealthy_latency_ms"`
	TLSHandshakeTimeoutSec            int     `json:"tls_handshake_timeout_sec"`
	ExpectContinueTimeoutSec          int     `json:"expect_continue_timeout_sec"`
	UpstreamMaxIdleConns              int     `json:"upstream_max_idle_conns"`
	UpstreamKeepAliveProbeIntervalSec int     `json:"upstream_keep_alive_probe_sec"`
	HealthCheckMaxSizeKB              int     `json:"health_check_max_size_kb"`
	UpstreamResolveTimeoutSec         int     `json:"upstream_resolve_timeout_sec"`
}

// proxyHostToAPIMap converts a ProxyHost to a JSON-serialisable map.
func (s *Server) proxyHostToAPIMap(p *models.ProxyHost) map[string]any {
	return map[string]any{
		"id":                                    p.ID,
		"server_id":                             p.ServerID,
		"domains":                               p.Domains,
		"forward_scheme":                        p.ForwardScheme,
		"forward_host":                          p.ForwardHost,
		"forward_port":                          p.ForwardPort,
		"websocket_support":                     p.WebsocketSupport,
		"block_common_exploits":                 p.BlockCommonExploits,
		"ssl_enabled":                           p.SSLEnabled,
		"ssl_forced":                            p.SSLForced,
		"http2_support":                         p.HTTP2Support,
		"enabled":                               p.Enabled,
		"certificate_id":                        p.CertificateID,
		"basicauth_enabled":                     p.BasicAuthEnabled,
		"access_list":                           p.AccessList,
		"ip_blocklist":                          p.IPBlocklist,
		"extra_upstreams":                       p.ExtraUpstreams,
		"compression_enabled":                   p.CompressionEnabled,
		"security_headers_enabled":              p.SecurityHeadersEnabled,
		"tls_min_version":                       p.TLSMinVersion,
		"client_auth_mode":                      p.ClientAuthMode,
		"client_auth_ca_files":                  p.ClientAuthCAFiles,
		"maintenance_mode":                      p.MaintenanceMode,
		"maintenance_msg":                       p.MaintenanceMsg,
		"max_request_body_mb":                   p.MaxRequestBodyMB,
		"sticky_sessions":                       p.StickySessions,
		"lb_policy":                             p.LBPolicy,
		"upstream_timeout_sec":                  p.UpstreamTimeoutSec,
		"cors_enabled":                          p.CORSEnabled,
		"cors_origins":                          p.CORSOrigins,
		"health_check_uri":                      p.HealthCheckURI,
		"health_check_interval_sec":             p.HealthCheckIntervalSec,
		"health_check_method":                   p.HealthCheckMethod,
		"keepalive_conns":                       p.KeepaliveConns,
		"tags":                                  p.Tags,
		"notes":                                 p.Notes,
		"disable_access_log":                    p.DisableAccessLog,
		"add_request_id":                        p.AddRequestID,
		"strip_resp_headers":                    p.StripRespHeaders,
		"blocked_agents":                        p.BlockedAgents,
		"upstream_sni":                          p.UpstreamSNI,
		"hsts_preload":                          p.HSTSPreload,
		"max_conns_per_host":                    p.MaxConnsPerHost,
		"upstream_retries":                      p.UpstreamRetries,
		"force_http1":                           p.ForceHTTP1,
		"proxy_protocol":                        p.ProxyProtocol,
		"www_redirect":                          wwwRedirectValue(p.WWWRedirect),
		"trailing_slash_redirect":               trailingSlashValue(p.TrailingSlashRedirect),
		"dns_provider":                          p.DNSProvider,
		"dns_profile_id":                        p.DNSProfileID,
		"dns_zone_id":                           p.DNSZoneID,
		"dns_zone_name":                         p.DNSZoneName,
		"dns_skip_record":                       p.DNSSkipRecord,
		"middleware_profile_id":                 models.ProxyHostProfileID(s.DB, p.ID),
		"hsts_include_subdomains":               p.HSTSIncludeSubdomains,
		"hsts_max_age_sec":                      p.HSTSMaxAgeSec,
		"csp_header":                            p.CSPHeader,
		"csp_report_only":                       p.CSPReportOnly,
		"permissions_policy":                    p.PermissionsPolicy,
		"x_frame_options":                       p.XFrameOptions,
		"referrer_policy":                       p.ReferrerPolicy,
		"custom_req_headers":                    p.CustomReqHeaders,
		"custom_resp_headers":                   p.CustomRespHeaders,
		"maintenance_status_code":               p.MaintenanceStatusCode,
		"maintenance_retry_after_sec":           p.MaintenanceRetryAfterSec,
		"maintenance_window_start":              p.MaintenanceWindowStart,
		"maintenance_window_end":                p.MaintenanceWindowEnd,
		"maintenance_window_days":               p.MaintenanceWindowDays,
		"maintenance_window_timezone":           p.MaintenanceWindowTimezone,
		"maintenance_allowed_ips":               p.MaintenanceAllowedIPs,
		"maintenance_redirect_url":              p.MaintenanceRedirectURL,
		"expectations":                          p.Expectations,
		"internal_tls":                          p.InternalTLS,
		"path_matcher":                          p.PathMatcher,
		"path_matcher_type":                     p.PathMatcherType,
		"strip_path_prefix":                     p.StripPathPrefix,
		"strip_path_suffix":                     p.StripPathSuffix,
		"upstream_path_prefix":                  p.UpstreamPathPrefix,
		"forward_auth_url":                      p.ForwardAuthURL,
		"forward_auth_method":                   p.ForwardAuthMethod,
		"forward_auth_copy_headers":             p.ForwardAuthCopyHeaders,
		"forward_auth_headers_prefix":           p.ForwardAuthHeadersPrefix,
		"ssl_verify_upstream":                   p.SSLVerifyUpstream,
		"upstream_tls_min_version":              p.UpstreamTLSMinVersion,
		"upstream_tls_max_version":              p.UpstreamTLSMaxVersion,
		"upstream_tls_ca_pem_file":              p.UpstreamTLSCAPEMFile,
		"upstream_tls_client_cert_file":         p.UpstreamTLSClientCertFile,
		"upstream_tls_client_key_file":          p.UpstreamTLSClientKeyFile,
		"upstream_tls_renegotiation":            p.UpstreamTLSRenegotiation,
		"advanced_config":                       p.AdvancedConfig,
		"flush_immediate":                       p.FlushImmediate,
		"h2c_enabled":                           p.H2CEnabled,
		"grpc_web_enabled":                      p.GRPCWebEnabled,
		"error_page_html":                       p.ErrorPageHTML,
		"error_redirect_url":                    p.ErrorRedirectURL,
		"robots_txt":                            p.RobotsTxt,
		"strip_req_headers":                     p.StripReqHeaders,
		"trusted_proxies":                       p.TrustedProxies,
		"upstream_host_override":                p.UpstreamHostOverride,
		"api_key_header":                        p.APIKeyHeader,
		"block_empty_user_agent":                p.BlockEmptyUserAgent,
		"cors_allow_credentials":                p.CORSAllowCredentials,
		"cors_allow_methods":                    p.CORSAllowMethods,
		"cors_allow_headers":                    p.CORSAllowHeaders,
		"cors_expose_headers":                   p.CORSExposeHeaders,
		"cors_max_age_sec":                      p.CORSMaxAgeSec,
		"compression_min_size_kb":               p.CompressionMinSizeKB,
		"compression_level":                     p.CompressionLevel,
		"compression_prefer_gzip":               p.CompressionPreferGzip,
		"enable_brotli":                         p.EnableBrotli,
		"health_check_timeout_sec":              p.HealthCheckTimeoutSec,
		"health_check_expect_status":            p.HealthCheckExpectStatus,
		"health_check_expect_body":              p.HealthCheckExpectBody,
		"health_check_port":                     p.HealthCheckPort,
		"sticky_cookie_name":                    p.StickyCookieName,
		"dial_timeout_sec":                      p.DialTimeoutSec,
		"read_timeout_sec":                      p.ReadTimeoutSec,
		"buffer_responses":                      p.BufferResponses,
		"request_buffers_kb":                    p.RequestBuffersKB,
		"response_buffers_kb":                   p.ResponseBuffersKB,
		"upstream_read_buffer_size_kb":          p.UpstreamReadBufferSizeKB,
		"upstream_write_buffer_size_kb":         p.UpstreamWriteBufferSizeKB,
		"keepalive_idle_timeout_sec":            p.KeepaliveIdleTimeoutSec,
		"keepalive_disabled":                    p.KeepaliveDisabled,
		"write_timeout_sec":                     p.WriteTimeoutSec,
		"request_body_read_timeout_sec":         p.RequestBodyReadTimeoutSec,
		"response_header_timeout_sec":           p.ResponseHeaderTimeoutSec,
		"max_conn_duration_sec":                 p.MaxConnDurationSec,
		"dial_fallback_delay_ms":                p.DialFallbackDelayMS,
		"forward_proxy_url":                     p.ForwardProxyURL,
		"upstream_network":                      p.UpstreamNetwork,
		"dns_resolver":                          p.DNSResolver,
		"req_header_replace":                    p.ReqHeaderReplace,
		"resp_header_replace":                   p.RespHeaderReplace,
		"response_cache_control":                p.ResponseCacheControl,
		"strip_server_header":                   p.StripServerHeader,
		"strip_etag":                            p.StripETag,
		"add_content_type_nosniff":              p.AddContentTypeNosniff,
		"vary_header":                           p.VaryHeader,
		"server_header_value":                   p.ServerHeaderValue,
		"deny_dotfiles":                         p.DenyDotfiles,
		"blocked_methods":                       p.BlockedMethods,
		"allowed_methods":                       p.AllowedMethods,
		"forward_client_ip":                     p.ForwardClientIP,
		"strip_query_string":                    p.StripQueryString,
		"delete_query_params":                   p.DeleteQueryParams,
		"health_check_follow_redirects":         p.HealthCheckFollowRedirects,
		"health_check_headers":                  p.HealthCheckHeaders,
		"basicauth_realm":                       p.BasicAuthRealm,
		"color":                                 p.Color,
		"passive_fail_duration_sec":             p.PassiveFailDurationSec,
		"passive_max_fails":                     p.PassiveMaxFails,
		"lb_try_duration_sec":                   p.LBTryDurationSec,
		"lb_try_interval_ms":                    p.LBTryIntervalMS,
		"max_buffer_size_kb":                    p.MaxBufferSizeKB,
		"upstream_keepalive_probes":             p.UpstreamKeepaliveProbes,
		"upstream_flush_interval_ms":            p.UpstreamFlushIntervalMS,
		"passive_unhealthy_count":               p.PassiveUnhealthyCount,
		"lb_cookie_max_age_sec":                 p.LBCookieMaxAgeSec,
		"lb_random_choose_count":                p.LBRandomChooseCount,
		"response_cache_ttl_sec":                p.ResponseCacheTTLSec,
		"upstream_keepalive_max_lifetime_sec":   p.UpstreamKeepaliveMaxLifetimeSec,
		"monitor_mode":                          p.MonitorMode,
		"monitor_method":                        p.MonitorMethod,
		"monitor_expect_status":                 p.MonitorExpectStatus,
		"monitor_interval_sec":                  p.MonitorIntervalSec,
		"monitor_timeout_sec":                   p.MonitorTimeoutSec,
		"rate_limit_events":                     p.RateLimitEvents,
		"rate_limit_window_sec":                 p.RateLimitWindowSec,
		"proxy_redirect_rules":                  p.ProxyRedirectRules,
		"additional_upstream_rules":             p.AdditionalUpstreamRules,
		"retry_status_codes":                    p.RetryStatusCodes,
		"decompress_response":                   p.DecompressResponse,
		"request_id_header_name":                p.RequestIDHeaderName,
		"lb_cookie_path":                        p.LBCookiePath,
		"add_req_query_params":                  p.AddReqQueryParams,
		"error_page_codes":                      p.ErrorPageCodes,
		"cors_allow_private_network":            p.CORSAllowPrivateNetwork,
		"robots_txt_disallow_all":               p.RobotsTxtDisallowAll,
		"upstream_http_versions":                p.UpstreamHTTPVersions,
		"health_check_body":                     p.HealthCheckBody,
		"add_canonical_link_header":             p.AddCanonicalLinkHeader,
		"block_ua_regexp":                       p.BlockUARegexp,
		"security_txt_body":                     p.SecurityTxtBody,
		"x_robots_tag":                          p.XRobotsTag,
		"add_forwarded_header":                  p.AddForwardedHeader,
		"passive_unhealthy_status_codes":        p.PassiveUnhealthyStatusCodes,
		"health_check_content_type":             p.HealthCheckContentType,
		"block_private_ips":                     p.BlockPrivateIPs,
		"http2_push_paths":                      p.HTTP2PushPaths,
		"deny_content_types":                    p.DenyContentTypes,
		"upstream_local_addr":                   p.UpstreamLocalAddr,
		"upstream_tls_curves":                   p.UpstreamTLSCurves,
		"upstream_tls_pins":                     p.UpstreamTLSPins,
		"lb_header_field":                       p.LBHeaderField,
		"maintenance_custom_headers":            p.MaintenanceCustomHeaders,
		"deny_extensions":                       p.DenyExtensions,
		"inject_request_timestamp":              p.InjectRequestTimestamp,
		"add_resp_cookies":                      p.AddRespCookies,
		"strip_accept_encoding":                 p.StripAcceptEncoding,
		"add_upstream_timing_header":            p.AddUpstreamTimingHeader,
		"block_referer_regexp":                  p.BlockRefererRegexp,
		"strip_authorization_header":            p.StripAuthorizationHeader,
		"real_ip_from_header":                   p.RealIPFromHeader,
		"health_check_host_override":            p.HealthCheckHostOverride,
		"add_x_forwarded_port":                  p.AddXForwardedPort,
		"lb_retry_on":                           p.LBRetryOn,
		"add_x_forwarded_host":                  p.AddXForwardedHost,
		"upstream_tls_cipher_suites":            p.UpstreamTLSCipherSuites,
		"add_cache_control_no_store":            p.AddCacheControlNoStore,
		"deny_referer_empty":                    p.DenyRefererEmpty,
		"lb_cookie_httponly":                    p.LBCookieHTTPOnly,
		"lb_cookie_secure":                      p.LBCookieSecure,
		"lb_cookie_same_site":                   p.LBCookieSameSite,
		"upstream_tls_early_data":               p.UpstreamTLSEarlyData,
		"add_via_header":                        p.AddViaHeader,
		"req_header_rename":                     p.ReqHeaderRename,
		"add_expect_ct_header":                  p.AddExpectCTHeader,
		"force_upstream_encoding":               p.ForceUpstreamEncoding,
		"strip_x_powered_by":                    p.StripXPoweredBy,
		"add_timing_allow_origin":               p.AddTimingAllowOrigin,
		"cross_origin_opener_policy":            p.CrossOriginOpenerPolicy,
		"cross_origin_resource_policy":          p.CrossOriginResourcePolicy,
		"cross_origin_embedder_policy":          p.CrossOriginEmbedderPolicy,
		"deny_request_content_type":             p.DenyRequestContentType,
		"compression_exclude_regexp":            p.CompressionExcludeRegexp,
		"add_cache_control_public":              p.AddCacheControlPublic,
		"add_x_request_start":                   p.AddXRequestStart,
		"add_x_forwarded_scheme":                p.AddXForwardedScheme,
		"add_link_preload":                      p.AddLinkPreload,
		"deny_path_regexp":                      p.DenyPathRegexp,
		"add_request_id_to_response":            p.AddRequestIDToResponse,
		"health_check_tls_server_name":          p.HealthCheckTLSServerName,
		"add_x_real_ip":                         p.AddXRealIP,
		"strip_incoming_x_forwarded_for":        p.StripIncomingXForwardedFor,
		"health_check_tls_insecure_skip_verify": p.HealthCheckTLSInsecureSkipVerify,
		"add_cors_vary_header":                  p.AddCORSVaryHeader,
		"upstream_tls_alpn":                     p.UpstreamTLSALPN,
		"add_x_powered_by":                      p.AddXPoweredBy,
		"block_query_params":                    p.BlockQueryParams,
		"add_document_policy":                   p.AddDocumentPolicy,
		"add_origin_header":                     p.AddOriginHeader,
		"upstream_tls_ca_pem_inline":            p.UpstreamTLSCAPEMInline,
		"add_server_timing_header":              p.AddServerTimingHeader,
		"add_clear_site_data":                   p.AddClearSiteData,
		"add_x_dns_prefetch_control":            p.AddXDNSPrefetchControl,
		"add_accept_ranges":                     p.AddAcceptRanges,
		"add_content_disposition":               p.AddContentDisposition,
		"upstream_tls_server_name_from_host":    p.UpstreamTLSServerNameFromHost,
		"add_x_permitted_cross_domain_policies": p.AddXPermittedCrossDomainPolicies,
		"add_report_to":                         p.AddReportTo,
		"add_nel_header":                        p.AddNELHeader,
		"block_http_methods":                    p.BlockHTTPMethods,
		"add_service_worker_allowed":            p.AddServiceWorkerAllowed,
		"add_accept_ch":                         p.AddAcceptCH,
		"add_alt_svc":                           p.AddAltSvc,
		"add_content_language":                  p.AddContentLanguage,
		"add_critical_ch":                       p.AddCriticalCH,
		"add_x_download_options":                p.AddXDownloadOptions,
		"deny_user_agent_regexp":                p.DenyUserAgentRegexp,
		"add_pragma_no_cache":                   p.AddPragmaNoCache,
		"health_check_user_agent":               p.HealthCheckUserAgent,
		"add_x_request_path":                    p.AddXRequestPath,
		"add_x_clacks_overhead":                 p.AddXClacksOverhead,
		"add_x_ua_compatible":                   p.AddXUACompatible,
		"forward_auth_skip_paths":               p.ForwardAuthSkipPaths,
		"add_age_zero":                          p.AddAgeZero,
		"add_surrogate_control":                 p.AddSurrogateControl,
		"add_warning_header":                    p.AddWarningHeader,
		"add_x_request_method":                  p.AddXRequestMethod,
		"add_x_request_query":                   p.AddXRequestQuery,
		"add_x_forwarded_user":                  p.AddXForwardedUser,
		"add_x_real_scheme":                     p.AddXRealScheme,
		"add_origin_agent_cluster":              p.AddOriginAgentCluster,
		"add_x_forwarded_groups":                p.AddXForwardedGroups,
		"add_x_forwarded_email":                 p.AddXForwardedEmail,
		"add_x_forwarded_roles":                 p.AddXForwardedRoles,
		"block_query_param_regexp":              p.BlockQueryParamRegexp,
		"add_x_request_referer":                 p.AddXRequestReferer,
		"add_x_request_origin":                  p.AddXRequestOrigin,
		"add_x_forwarded_uri":                   p.AddXForwardedURI,
		"add_x_no_archive":                      p.AddXNoArchive,
		"add_x_request_hostname":                p.AddXRequestHostname,
		"add_x_xss_protection_disabled":         p.AddXXSSProtectionDisabled,
		"add_x_request_remote_port":             p.AddXRequestRemotePort,
		"add_x_request_protocol":                p.AddXRequestProtocol,
		"add_save_data_vary":                    p.AddSaveDataVary,
		"add_x_environment":                     p.AddXEnvironment,
		"add_x_trace_id":                        p.AddXTraceID,
		"health_check_query_params":             p.HealthCheckQueryParams,
		"add_x_session_id":                      p.AddXSessionID,
		"add_x_response_trace_id":               p.AddXResponseTraceID,
		"add_x_request_local_addr":              p.AddXRequestLocalAddr,
		"add_x_request_local_port":              p.AddXRequestLocalPort,
		"add_x_request_path_info":               p.AddXRequestPathInfo,
		"add_x_authenticated_user":              p.AddXAuthenticatedUser,
		"block_path_extensions":                 p.BlockPathExtensions,
		"add_link_modulepreload":                p.AddLinkModulePreload,
		"add_x_remote_user":                     p.AddXRemoteUser,
		"add_x_forwarded_path":                  p.AddXForwardedPath,
		"add_x_geo_country_code":                p.AddXGeoCountryCode,
		"add_x_request_priority":                p.AddXRequestPriority,
		"add_x_real_ssl_protocol":               p.AddXRealSSLProtocol,
		"add_x_real_ssl_cipher":                 p.AddXRealSSLCipher,
		"add_x_cache_status":                    p.AddXCacheStatus,
		"deny_referer_regexp":                   p.DenyRefererRegexp,
		"add_x_request_user_agent":              p.AddXRequestUserAgent,
		"add_reporting_endpoints":               p.AddReportingEndpoints,
		"add_x_request_byte_count":              p.AddXRequestByteCount,
		"add_x_request_received_at":             p.AddXRequestReceivedAt,
		"add_x_forwarded_method":                p.AddXForwardedMethod,
		"add_x_request_original_host":           p.AddXRequestOriginalHost,
		"add_x_request_dnt":                     p.AddXRequestDNT,
		"add_x_geo_region":                      p.AddXGeoRegion,
		"add_x_request_secure":                  p.AddXRequestSecure,
		"add_x_request_query_count":             p.AddXRequestQueryCount,
		"add_x_request_id_header_response":      p.AddXRequestIDHeaderResponse,
		"force_canonical_host":                  p.ForceCanonicalHost,
		"add_x_robots_noindex_quick":            p.AddXRobotsNoindexQuick,
		"block_bot_user_agents":                 p.BlockBotUserAgents,
		"block_admin_paths":                     p.BlockAdminPaths,
		"add_link_dns_prefetch":                 p.AddLinkDNSPrefetch,
		"add_link_preconnect":                   p.AddLinkPreconnect,
		"add_x_csp_disabled":                    p.AddXCSPDisabled,
		"add_x_request_method_override":         p.AddXRequestMethodOverride,
		"disable_upstream_compression":          p.DisableUpstreamCompression,
		"monitor_path":                          p.MonitorPath,
		"node_local":                            p.NodeLocal,
		"rate_limit_enabled":                    p.RateLimitEnabled,
		"sort_order":                            p.SortOrder,
		"upstream_max_resp_header_kb":           p.UpstreamMaxRespHeaderKB,
		"passive_unhealthy_latency_ms":          p.PassiveUnhealthyLatencyMS,
		"tls_handshake_timeout_sec":             p.TLSHandshakeTimeoutSec,
		"expect_continue_timeout_sec":           p.ExpectContinueTimeoutSec,
		"upstream_max_idle_conns":               p.UpstreamMaxIdleConns,
		"upstream_keep_alive_probe_sec":         p.UpstreamKeepAliveProbeIntervalSec,
		"health_check_max_size_kb":              p.HealthCheckMaxSizeKB,
		"upstream_resolve_timeout_sec":          p.UpstreamResolveTimeoutSec,
		"owner_email":                           p.OwnerEmail,
		"created_at":                            p.CreatedAt,
		"updated_at":                            p.UpdatedAt,
	}
}

func wwwRedirectValue(value string) string {
	if value == "" {
		return "off"
	}
	return value
}

func trailingSlashValue(value string) string {
	if value == "" {
		return "off"
	}
	return value
}

func normalizeWWWRedirect(value string) string {
	switch value {
	case "to_www", "to_bare":
		return value
	default:
		return ""
	}
}

func normalizeTrailingSlash(value string) string {
	switch value {
	case "add", "remove":
		return value
	default:
		return ""
	}
}

// writeJSON is a convenience wrapper that sets Content-Type and encodes v as JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// validateClientAuthInput rejects a client-certificate (mTLS) configuration
// that Caddy would accept but that could not admit anyone: an unknown mode,
// or a verifying mode with no trusted CA to verify against.
//
// v2.64.0 (discussion #137).
func validateClientAuthInput(mode, caFiles string) error {
	if !models.ValidClientAuthMode(mode) {
		return fmt.Errorf("client_auth_mode %q is not valid: use request, require, verify_if_given, require_and_verify, or off", mode)
	}
	if models.ClientAuthModeVerifies(mode) && strings.TrimSpace(caFiles) == "" {
		return fmt.Errorf("client_auth_mode %q verifies the client certificate, so client_auth_ca_files must list at least one trusted CA certificate file", mode)
	}
	return nil
}

func applyProxyDNS(p *models.ProxyHost, inp apiProxyHostInput) error {
	provider := strings.ToLower(strings.TrimSpace(inp.DNSProvider))
	if provider == "" {
		return nil
	}
	if provider == "off" {
		p.DNSProvider, p.DNSProfileID, p.DNSZoneID, p.DNSZoneName = "", "", "", ""
		p.DNSSkipRecord = false
		return nil
	}
	if _, ok := dns.Lookup(provider); !ok {
		return fmt.Errorf("unknown DNS provider %q", provider)
	}
	zoneID := strings.TrimSpace(inp.DNSZoneID)
	if zoneID == "" {
		return fmt.Errorf("DNS zone ID is required when a provider is set")
	}
	zoneName := strings.TrimSpace(inp.DNSZoneName)
	if zoneName == "" {
		zoneName = zoneID
	}
	p.DNSProvider = provider
	p.DNSProfileID = strings.TrimSpace(inp.DNSProfileID)
	p.DNSZoneID = zoneID
	p.DNSZoneName = zoneName
	p.DNSSkipRecord = inp.DNSSkipRecord
	return nil
}

func headerJSON(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return "{}", nil
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		return "", fmt.Errorf("custom headers must be a JSON object of strings")
	}
	encoded, err := json.Marshal(headers)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func basicAuthUsersFromLines(raw string) (string, error) {
	var users []models.BasicAuthUser
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		username, password, ok := strings.Cut(line, ":")
		username = strings.TrimSpace(username)
		if !ok || username == "" || password == "" {
			return "", fmt.Errorf("basic auth lines must look like username:password")
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return "", fmt.Errorf("could not hash the password for %q", username)
		}
		users = append(users, models.BasicAuthUser{Username: username, BcryptHash: hash})
	}
	if len(users) == 0 {
		return "[]", nil
	}
	encoded, err := json.Marshal(users)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func applyProxyHostDetails(p *models.ProxyHost, inp apiProxyHostInput) error {
	if err := applyProxyDNS(p, inp); err != nil {
		return err
	}
	p.HSTSIncludeSubdomains = inp.HSTSIncludeSubdomains
	p.InternalTLS = inp.InternalTLS
	if inp.HSTSMaxAgeSec != 0 {
		p.HSTSMaxAgeSec = inp.HSTSMaxAgeSec
	}
	if inp.CSPHeader != "" {
		p.CSPHeader = inp.CSPHeader
	}
	if inp.CSPReportOnly != "" {
		p.CSPReportOnly = inp.CSPReportOnly
	}
	if inp.PermissionsPolicy != "" {
		p.PermissionsPolicy = inp.PermissionsPolicy
	}
	if inp.XFrameOptions != "" {
		p.XFrameOptions = inp.XFrameOptions
	}
	if inp.ReferrerPolicy != "" {
		p.ReferrerPolicy = inp.ReferrerPolicy
	}
	if strings.TrimSpace(inp.CustomReqHeaders) != "" {
		headers, err := headerJSON(inp.CustomReqHeaders)
		if err != nil {
			return err
		}
		p.CustomReqHeaders = headers
	}
	if strings.TrimSpace(inp.CustomRespHeaders) != "" {
		headers, err := headerJSON(inp.CustomRespHeaders)
		if err != nil {
			return err
		}
		p.CustomRespHeaders = headers
	}
	if inp.MaintenanceStatusCode != 0 {
		p.MaintenanceStatusCode = inp.MaintenanceStatusCode
	}
	if inp.MaintenanceRetryAfterSec != 0 {
		p.MaintenanceRetryAfterSec = inp.MaintenanceRetryAfterSec
	}
	if inp.MaintenanceWindowStart != "" {
		p.MaintenanceWindowStart = inp.MaintenanceWindowStart
	}
	if inp.MaintenanceWindowEnd != "" {
		p.MaintenanceWindowEnd = inp.MaintenanceWindowEnd
	}
	if inp.MaintenanceWindowDays != "" {
		p.MaintenanceWindowDays = inp.MaintenanceWindowDays
	}
	if inp.MaintenanceWindowTimezone != "" {
		p.MaintenanceWindowTimezone = inp.MaintenanceWindowTimezone
	}
	if inp.MaintenanceAllowedIPs != "" {
		p.MaintenanceAllowedIPs = inp.MaintenanceAllowedIPs
	}
	if inp.MaintenanceRedirectURL != "" {
		p.MaintenanceRedirectURL = inp.MaintenanceRedirectURL
	}
	if inp.Expectations != nil {
		p.Expectations = models.NormalizeHostExpectationsJSON(*inp.Expectations)
	}
	if strings.TrimSpace(inp.BasicAuthUsers) != "" {
		users, err := basicAuthUsersFromLines(inp.BasicAuthUsers)
		if err != nil {
			return err
		}
		p.BasicAuthUsers = users
		p.BasicAuthEnabled = true
	}
	setString(&p.PathMatcher, inp.PathMatcher)
	setString(&p.PathMatcherType, inp.PathMatcherType)
	p.StripPathPrefix = inp.StripPathPrefix
	setString(&p.StripPathSuffix, inp.StripPathSuffix)
	setString(&p.UpstreamPathPrefix, inp.UpstreamPathPrefix)
	setString(&p.ForwardAuthURL, inp.ForwardAuthURL)
	setString(&p.ForwardAuthMethod, inp.ForwardAuthMethod)
	setString(&p.ForwardAuthCopyHeaders, inp.ForwardAuthCopyHeaders)
	setString(&p.ForwardAuthHeadersPrefix, inp.ForwardAuthHeadersPrefix)
	p.SSLVerifyUpstream = inp.SSLVerifyUpstream
	setString(&p.UpstreamTLSMinVersion, inp.UpstreamTLSMinVersion)
	setString(&p.UpstreamTLSMaxVersion, inp.UpstreamTLSMaxVersion)
	setString(&p.UpstreamTLSCAPEMFile, inp.UpstreamTLSCAPEMFile)
	setString(&p.UpstreamTLSClientCertFile, inp.UpstreamTLSClientCertFile)
	setString(&p.UpstreamTLSClientKeyFile, inp.UpstreamTLSClientKeyFile)
	setString(&p.UpstreamTLSRenegotiation, inp.UpstreamTLSRenegotiation)
	if inp.AdvancedConfig != nil {
		p.AdvancedConfig = normalizeProxyAdvancedConfig(*inp.AdvancedConfig)
	}
	p.FlushImmediate = inp.FlushImmediate
	p.H2CEnabled = inp.H2CEnabled
	p.GRPCWebEnabled = inp.GRPCWebEnabled
	setString(&p.ErrorPageHTML, inp.ErrorPageHTML)
	setString(&p.ErrorRedirectURL, inp.ErrorRedirectURL)
	setString(&p.RobotsTxt, inp.RobotsTxt)
	setString(&p.StripReqHeaders, inp.StripReqHeaders)
	setString(&p.TrustedProxies, inp.TrustedProxies)
	setString(&p.UpstreamHostOverride, inp.UpstreamHostOverride)
	setString(&p.APIKeyHeader, inp.APIKeyHeader)
	if strings.TrimSpace(inp.APIKeyValue) != "" {
		p.APIKeyValue = strings.TrimSpace(inp.APIKeyValue)
	}
	p.BlockEmptyUserAgent = inp.BlockEmptyUserAgent
	p.CORSAllowCredentials = inp.CORSAllowCredentials
	setString(&p.CORSAllowMethods, inp.CORSAllowMethods)
	setString(&p.CORSAllowHeaders, inp.CORSAllowHeaders)
	setString(&p.CORSExposeHeaders, inp.CORSExposeHeaders)
	if inp.CORSMaxAgeSec != 0 {
		p.CORSMaxAgeSec = inp.CORSMaxAgeSec
	}
	if inp.CompressionMinSizeKB != 0 {
		p.CompressionMinSizeKB = inp.CompressionMinSizeKB
	}
	if inp.CompressionLevel != 0 {
		p.CompressionLevel = inp.CompressionLevel
	}
	p.CompressionPreferGzip = inp.CompressionPreferGzip
	p.EnableBrotli = inp.EnableBrotli
	if inp.HealthCheckTimeoutSec != 0 {
		p.HealthCheckTimeoutSec = inp.HealthCheckTimeoutSec
	}
	if inp.HealthCheckExpectStatus != 0 {
		p.HealthCheckExpectStatus = inp.HealthCheckExpectStatus
	}
	setString(&p.HealthCheckExpectBody, inp.HealthCheckExpectBody)
	if inp.HealthCheckPort != 0 {
		p.HealthCheckPort = inp.HealthCheckPort
	}
	setString(&p.StickyCookieName, inp.StickyCookieName)
	if inp.DialTimeoutSec != 0 {
		p.DialTimeoutSec = inp.DialTimeoutSec
	}
	if inp.ReadTimeoutSec != 0 {
		p.ReadTimeoutSec = inp.ReadTimeoutSec
	}
	p.BufferResponses = inp.BufferResponses
	if inp.RequestBuffersKB != 0 {
		p.RequestBuffersKB = inp.RequestBuffersKB
	}
	if inp.ResponseBuffersKB != 0 {
		p.ResponseBuffersKB = inp.ResponseBuffersKB
	}
	if inp.UpstreamReadBufferSizeKB != 0 {
		p.UpstreamReadBufferSizeKB = inp.UpstreamReadBufferSizeKB
	}
	if inp.UpstreamWriteBufferSizeKB != 0 {
		p.UpstreamWriteBufferSizeKB = inp.UpstreamWriteBufferSizeKB
	}
	if inp.KeepaliveIdleTimeoutSec != 0 {
		p.KeepaliveIdleTimeoutSec = inp.KeepaliveIdleTimeoutSec
	}
	p.KeepaliveDisabled = inp.KeepaliveDisabled
	if inp.WriteTimeoutSec != 0 {
		p.WriteTimeoutSec = inp.WriteTimeoutSec
	}
	if inp.RequestBodyReadTimeoutSec != 0 {
		p.RequestBodyReadTimeoutSec = inp.RequestBodyReadTimeoutSec
	}
	if inp.ResponseHeaderTimeoutSec != 0 {
		p.ResponseHeaderTimeoutSec = inp.ResponseHeaderTimeoutSec
	}
	if inp.MaxConnDurationSec != 0 {
		p.MaxConnDurationSec = inp.MaxConnDurationSec
	}
	if inp.DialFallbackDelayMS != 0 {
		p.DialFallbackDelayMS = inp.DialFallbackDelayMS
	}
	setString(&p.ForwardProxyURL, inp.ForwardProxyURL)
	setString(&p.UpstreamNetwork, inp.UpstreamNetwork)
	setString(&p.DNSResolver, inp.DNSResolver)
	setString(&p.ReqHeaderReplace, inp.ReqHeaderReplace)
	setString(&p.RespHeaderReplace, inp.RespHeaderReplace)
	setString(&p.ResponseCacheControl, inp.ResponseCacheControl)
	p.StripServerHeader = inp.StripServerHeader
	p.StripETag = inp.StripETag
	p.AddContentTypeNosniff = inp.AddContentTypeNosniff
	setString(&p.VaryHeader, inp.VaryHeader)
	setString(&p.ServerHeaderValue, inp.ServerHeaderValue)
	p.DenyDotfiles = inp.DenyDotfiles
	setString(&p.BlockedMethods, inp.BlockedMethods)
	setString(&p.AllowedMethods, inp.AllowedMethods)
	p.ForwardClientIP = inp.ForwardClientIP
	p.StripQueryString = inp.StripQueryString
	setString(&p.DeleteQueryParams, inp.DeleteQueryParams)
	p.HealthCheckFollowRedirects = inp.HealthCheckFollowRedirects
	if strings.TrimSpace(inp.HealthCheckHeaders) != "" {
		headers, err := headerJSON(inp.HealthCheckHeaders)
		if err != nil {
			return err
		}
		p.HealthCheckHeaders = headers
	}
	setString(&p.BasicAuthRealm, inp.BasicAuthRealm)
	setString(&p.Color, inp.Color)
	switch p.Color {
	case "", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink", "gray":
	default:
		return fmt.Errorf("color must be one of red, orange, yellow, green, teal, blue, purple, pink, or gray")
	}
	switch p.UpstreamNetwork {
	case "", "tcp4", "tcp6":
	default:
		return fmt.Errorf("upstream network must be tcp4 or tcp6")
	}
	if inp.PassiveFailDurationSec != 0 {
		p.PassiveFailDurationSec = inp.PassiveFailDurationSec
	}
	if inp.PassiveMaxFails != 0 {
		p.PassiveMaxFails = inp.PassiveMaxFails
	}
	if inp.LBTryDurationSec != 0 {
		p.LBTryDurationSec = inp.LBTryDurationSec
	}
	if inp.LBTryIntervalMS != 0 {
		p.LBTryIntervalMS = inp.LBTryIntervalMS
	}
	if inp.MaxBufferSizeKB != 0 {
		p.MaxBufferSizeKB = inp.MaxBufferSizeKB
	}
	if inp.UpstreamKeepaliveProbes != 0 {
		p.UpstreamKeepaliveProbes = inp.UpstreamKeepaliveProbes
	}
	if inp.UpstreamFlushIntervalMS != 0 {
		p.UpstreamFlushIntervalMS = inp.UpstreamFlushIntervalMS
	}
	if inp.PassiveUnhealthyCount != 0 {
		p.PassiveUnhealthyCount = inp.PassiveUnhealthyCount
	}
	if inp.LBCookieMaxAgeSec != 0 {
		p.LBCookieMaxAgeSec = inp.LBCookieMaxAgeSec
	}
	if inp.LBRandomChooseCount != 0 {
		p.LBRandomChooseCount = inp.LBRandomChooseCount
	}
	if inp.ResponseCacheTTLSec != 0 {
		p.ResponseCacheTTLSec = inp.ResponseCacheTTLSec
	}
	if inp.UpstreamKeepaliveMaxLifetimeSec != 0 {
		p.UpstreamKeepaliveMaxLifetimeSec = inp.UpstreamKeepaliveMaxLifetimeSec
	}
	setString(&p.MonitorMode, inp.MonitorMode)
	setString(&p.MonitorMethod, inp.MonitorMethod)
	if inp.MonitorExpectStatus != 0 {
		p.MonitorExpectStatus = inp.MonitorExpectStatus
	}
	if inp.MonitorIntervalSec != 0 {
		p.MonitorIntervalSec = inp.MonitorIntervalSec
	}
	if inp.MonitorTimeoutSec != 0 {
		p.MonitorTimeoutSec = inp.MonitorTimeoutSec
	}
	if inp.RateLimitEvents != 0 {
		p.RateLimitEvents = inp.RateLimitEvents
	}
	if inp.RateLimitWindowSec != 0 {
		p.RateLimitWindowSec = inp.RateLimitWindowSec
	}
	setString(&p.ProxyRedirectRules, inp.ProxyRedirectRules)
	setString(&p.AdditionalUpstreamRules, inp.AdditionalUpstreamRules)
	setString(&p.RetryStatusCodes, inp.RetryStatusCodes)
	p.DecompressResponse = inp.DecompressResponse
	setString(&p.RequestIDHeaderName, inp.RequestIDHeaderName)
	setString(&p.LBCookiePath, inp.LBCookiePath)
	setString(&p.AddReqQueryParams, inp.AddReqQueryParams)
	setString(&p.ErrorPageCodes, inp.ErrorPageCodes)
	p.CORSAllowPrivateNetwork = inp.CORSAllowPrivateNetwork
	p.RobotsTxtDisallowAll = inp.RobotsTxtDisallowAll
	setString(&p.UpstreamHTTPVersions, inp.UpstreamHTTPVersions)
	setString(&p.HealthCheckBody, inp.HealthCheckBody)
	p.AddCanonicalLinkHeader = inp.AddCanonicalLinkHeader
	if strings.TrimSpace(inp.HTTPBasicAuthUpstream) != "" {
		p.HTTPBasicAuthUpstream = strings.TrimSpace(inp.HTTPBasicAuthUpstream)
	}
	setString(&p.BlockUARegexp, inp.BlockUARegexp)
	setString(&p.SecurityTxtBody, inp.SecurityTxtBody)
	setString(&p.XRobotsTag, inp.XRobotsTag)
	p.AddForwardedHeader = inp.AddForwardedHeader
	if strings.TrimSpace(inp.LBCookieSecret) != "" {
		p.LBCookieSecret = strings.TrimSpace(inp.LBCookieSecret)
	}
	setString(&p.PassiveUnhealthyStatusCodes, inp.PassiveUnhealthyStatusCodes)
	setString(&p.HealthCheckContentType, inp.HealthCheckContentType)
	p.BlockPrivateIPs = inp.BlockPrivateIPs
	setString(&p.HTTP2PushPaths, inp.HTTP2PushPaths)
	setString(&p.DenyContentTypes, inp.DenyContentTypes)
	setString(&p.UpstreamLocalAddr, inp.UpstreamLocalAddr)
	setString(&p.UpstreamTLSCurves, inp.UpstreamTLSCurves)
	setString(&p.UpstreamTLSPins, inp.UpstreamTLSPins)
	setString(&p.LBHeaderField, inp.LBHeaderField)
	setString(&p.MaintenanceCustomHeaders, inp.MaintenanceCustomHeaders)
	setString(&p.DenyExtensions, inp.DenyExtensions)
	p.InjectRequestTimestamp = inp.InjectRequestTimestamp
	setString(&p.AddRespCookies, inp.AddRespCookies)
	p.StripAcceptEncoding = inp.StripAcceptEncoding
	p.AddUpstreamTimingHeader = inp.AddUpstreamTimingHeader
	setString(&p.BlockRefererRegexp, inp.BlockRefererRegexp)
	p.StripAuthorizationHeader = inp.StripAuthorizationHeader
	setString(&p.RealIPFromHeader, inp.RealIPFromHeader)
	setString(&p.HealthCheckHostOverride, inp.HealthCheckHostOverride)
	p.AddXForwardedPort = inp.AddXForwardedPort
	setString(&p.LBRetryOn, inp.LBRetryOn)
	p.AddXForwardedHost = inp.AddXForwardedHost
	setString(&p.UpstreamTLSCipherSuites, inp.UpstreamTLSCipherSuites)
	p.AddCacheControlNoStore = inp.AddCacheControlNoStore
	p.DenyRefererEmpty = inp.DenyRefererEmpty
	p.LBCookieHTTPOnly = inp.LBCookieHTTPOnly
	p.LBCookieSecure = inp.LBCookieSecure
	setString(&p.LBCookieSameSite, inp.LBCookieSameSite)
	p.UpstreamTLSEarlyData = inp.UpstreamTLSEarlyData
	p.AddViaHeader = inp.AddViaHeader
	setString(&p.ReqHeaderRename, inp.ReqHeaderRename)
	p.AddExpectCTHeader = inp.AddExpectCTHeader
	setString(&p.ForceUpstreamEncoding, inp.ForceUpstreamEncoding)
	p.StripXPoweredBy = inp.StripXPoweredBy
	setString(&p.AddTimingAllowOrigin, inp.AddTimingAllowOrigin)
	setString(&p.CrossOriginOpenerPolicy, inp.CrossOriginOpenerPolicy)
	setString(&p.CrossOriginResourcePolicy, inp.CrossOriginResourcePolicy)
	setString(&p.CrossOriginEmbedderPolicy, inp.CrossOriginEmbedderPolicy)
	setString(&p.DenyRequestContentType, inp.DenyRequestContentType)
	setString(&p.CompressionExcludeRegexp, inp.CompressionExcludeRegexp)
	p.AddCacheControlPublic = inp.AddCacheControlPublic
	p.AddXRequestStart = inp.AddXRequestStart
	p.AddXForwardedScheme = inp.AddXForwardedScheme
	setString(&p.AddLinkPreload, inp.AddLinkPreload)
	setString(&p.DenyPathRegexp, inp.DenyPathRegexp)
	p.AddRequestIDToResponse = inp.AddRequestIDToResponse
	setString(&p.HealthCheckTLSServerName, inp.HealthCheckTLSServerName)
	p.AddXRealIP = inp.AddXRealIP
	p.StripIncomingXForwardedFor = inp.StripIncomingXForwardedFor
	p.HealthCheckTLSInsecureSkipVerify = inp.HealthCheckTLSInsecureSkipVerify
	p.AddCORSVaryHeader = inp.AddCORSVaryHeader
	setString(&p.UpstreamTLSALPN, inp.UpstreamTLSALPN)
	setString(&p.AddXPoweredBy, inp.AddXPoweredBy)
	setString(&p.BlockQueryParams, inp.BlockQueryParams)
	setString(&p.AddDocumentPolicy, inp.AddDocumentPolicy)
	setString(&p.AddOriginHeader, inp.AddOriginHeader)
	setString(&p.UpstreamTLSCAPEMInline, inp.UpstreamTLSCAPEMInline)
	p.AddServerTimingHeader = inp.AddServerTimingHeader
	setString(&p.AddClearSiteData, inp.AddClearSiteData)
	p.AddXDNSPrefetchControl = inp.AddXDNSPrefetchControl
	p.AddAcceptRanges = inp.AddAcceptRanges
	setString(&p.AddContentDisposition, inp.AddContentDisposition)
	p.UpstreamTLSServerNameFromHost = inp.UpstreamTLSServerNameFromHost
	setString(&p.AddXPermittedCrossDomainPolicies, inp.AddXPermittedCrossDomainPolicies)
	setString(&p.AddReportTo, inp.AddReportTo)
	setString(&p.AddNELHeader, inp.AddNELHeader)
	setString(&p.BlockHTTPMethods, inp.BlockHTTPMethods)
	setString(&p.AddServiceWorkerAllowed, inp.AddServiceWorkerAllowed)
	setString(&p.AddAcceptCH, inp.AddAcceptCH)
	setString(&p.AddAltSvc, inp.AddAltSvc)
	setString(&p.AddContentLanguage, inp.AddContentLanguage)
	setString(&p.AddCriticalCH, inp.AddCriticalCH)
	p.AddXDownloadOptions = inp.AddXDownloadOptions
	setString(&p.DenyUserAgentRegexp, inp.DenyUserAgentRegexp)
	p.AddPragmaNoCache = inp.AddPragmaNoCache
	setString(&p.HealthCheckUserAgent, inp.HealthCheckUserAgent)
	p.AddXRequestPath = inp.AddXRequestPath
	setString(&p.AddXClacksOverhead, inp.AddXClacksOverhead)
	setString(&p.AddXUACompatible, inp.AddXUACompatible)
	setString(&p.ForwardAuthSkipPaths, inp.ForwardAuthSkipPaths)
	p.AddAgeZero = inp.AddAgeZero
	setString(&p.AddSurrogateControl, inp.AddSurrogateControl)
	setString(&p.AddWarningHeader, inp.AddWarningHeader)
	p.AddXRequestMethod = inp.AddXRequestMethod
	p.AddXRequestQuery = inp.AddXRequestQuery
	setString(&p.AddXForwardedUser, inp.AddXForwardedUser)
	p.AddXRealScheme = inp.AddXRealScheme
	p.AddOriginAgentCluster = inp.AddOriginAgentCluster
	setString(&p.AddXForwardedGroups, inp.AddXForwardedGroups)
	setString(&p.AddXForwardedEmail, inp.AddXForwardedEmail)
	setString(&p.AddXForwardedRoles, inp.AddXForwardedRoles)
	setString(&p.BlockQueryParamRegexp, inp.BlockQueryParamRegexp)
	p.AddXRequestReferer = inp.AddXRequestReferer
	p.AddXRequestOrigin = inp.AddXRequestOrigin
	p.AddXForwardedURI = inp.AddXForwardedURI
	p.AddXNoArchive = inp.AddXNoArchive
	p.AddXRequestHostname = inp.AddXRequestHostname
	p.AddXXSSProtectionDisabled = inp.AddXXSSProtectionDisabled
	p.AddXRequestRemotePort = inp.AddXRequestRemotePort
	p.AddXRequestProtocol = inp.AddXRequestProtocol
	p.AddSaveDataVary = inp.AddSaveDataVary
	setString(&p.AddXEnvironment, inp.AddXEnvironment)
	p.AddXTraceID = inp.AddXTraceID
	setString(&p.HealthCheckQueryParams, inp.HealthCheckQueryParams)
	p.AddXSessionID = inp.AddXSessionID
	p.AddXResponseTraceID = inp.AddXResponseTraceID
	p.AddXRequestLocalAddr = inp.AddXRequestLocalAddr
	p.AddXRequestLocalPort = inp.AddXRequestLocalPort
	p.AddXRequestPathInfo = inp.AddXRequestPathInfo
	setString(&p.AddXAuthenticatedUser, inp.AddXAuthenticatedUser)
	setString(&p.BlockPathExtensions, inp.BlockPathExtensions)
	setString(&p.AddLinkModulePreload, inp.AddLinkModulePreload)
	setString(&p.AddXRemoteUser, inp.AddXRemoteUser)
	p.AddXForwardedPath = inp.AddXForwardedPath
	setString(&p.AddXGeoCountryCode, inp.AddXGeoCountryCode)
	setString(&p.AddXRequestPriority, inp.AddXRequestPriority)
	if strings.TrimSpace(inp.HealthCheckBasicAuth) != "" {
		p.HealthCheckBasicAuth = strings.TrimSpace(inp.HealthCheckBasicAuth)
	}
	p.AddXRealSSLProtocol = inp.AddXRealSSLProtocol
	p.AddXRealSSLCipher = inp.AddXRealSSLCipher
	setString(&p.AddXCacheStatus, inp.AddXCacheStatus)
	setString(&p.DenyRefererRegexp, inp.DenyRefererRegexp)
	p.AddXRequestUserAgent = inp.AddXRequestUserAgent
	setString(&p.AddReportingEndpoints, inp.AddReportingEndpoints)
	p.AddXRequestByteCount = inp.AddXRequestByteCount
	p.AddXRequestReceivedAt = inp.AddXRequestReceivedAt
	p.AddXForwardedMethod = inp.AddXForwardedMethod
	p.AddXRequestOriginalHost = inp.AddXRequestOriginalHost
	p.AddXRequestDNT = inp.AddXRequestDNT
	setString(&p.AddXGeoRegion, inp.AddXGeoRegion)
	p.AddXRequestSecure = inp.AddXRequestSecure
	p.AddXRequestQueryCount = inp.AddXRequestQueryCount
	p.AddXRequestIDHeaderResponse = inp.AddXRequestIDHeaderResponse
	setString(&p.ForceCanonicalHost, inp.ForceCanonicalHost)
	p.AddXRobotsNoindexQuick = inp.AddXRobotsNoindexQuick
	p.BlockBotUserAgents = inp.BlockBotUserAgents
	p.BlockAdminPaths = inp.BlockAdminPaths
	setString(&p.AddLinkDNSPrefetch, inp.AddLinkDNSPrefetch)
	setString(&p.AddLinkPreconnect, inp.AddLinkPreconnect)
	p.AddXCSPDisabled = inp.AddXCSPDisabled
	p.AddXRequestMethodOverride = inp.AddXRequestMethodOverride
	p.DisableUpstreamCompression = inp.DisableUpstreamCompression
	setString(&p.MonitorPath, inp.MonitorPath)
	p.NodeLocal = inp.NodeLocal
	p.RateLimitEnabled = inp.RateLimitEnabled
	if inp.SortOrder != 0 {
		p.SortOrder = inp.SortOrder
	}
	if inp.UpstreamMaxRespHeaderKB != 0 {
		p.UpstreamMaxRespHeaderKB = inp.UpstreamMaxRespHeaderKB
	}
	if inp.PassiveUnhealthyLatencyMS != 0 {
		p.PassiveUnhealthyLatencyMS = inp.PassiveUnhealthyLatencyMS
	}
	if inp.TLSHandshakeTimeoutSec != 0 {
		p.TLSHandshakeTimeoutSec = inp.TLSHandshakeTimeoutSec
	}
	if inp.ExpectContinueTimeoutSec != 0 {
		p.ExpectContinueTimeoutSec = inp.ExpectContinueTimeoutSec
	}
	if inp.UpstreamMaxIdleConns != 0 {
		p.UpstreamMaxIdleConns = inp.UpstreamMaxIdleConns
	}
	if inp.UpstreamKeepAliveProbeIntervalSec != 0 {
		p.UpstreamKeepAliveProbeIntervalSec = inp.UpstreamKeepAliveProbeIntervalSec
	}
	if inp.HealthCheckMaxSizeKB != 0 {
		p.HealthCheckMaxSizeKB = inp.HealthCheckMaxSizeKB
	}
	if inp.UpstreamResolveTimeoutSec != 0 {
		p.UpstreamResolveTimeoutSec = inp.UpstreamResolveTimeoutSec
	}
	switch p.PathMatcherType {
	case "", "exact", "regexp":
	default:
		p.PathMatcherType = ""
	}
	switch strings.ToUpper(p.ForwardAuthMethod) {
	case "", "GET", "POST", "HEAD":
		p.ForwardAuthMethod = strings.ToUpper(p.ForwardAuthMethod)
	default:
		return fmt.Errorf("forward auth method must be GET, POST, or HEAD")
	}
	switch p.UpstreamTLSMinVersion {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("upstream TLS minimum must be 1.2 or 1.3")
	}
	switch p.UpstreamTLSMaxVersion {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("upstream TLS maximum must be 1.2 or 1.3")
	}
	switch p.UpstreamTLSRenegotiation {
	case "", "once", "freely":
	default:
		return fmt.Errorf("upstream TLS renegotiation must be once or freely")
	}
	if msg := validateForwardAuthURL(p.ForwardAuthURL); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	if msg := validateSSLFlags(p.SSLEnabled, p.SSLForced, p.CertificateID); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func setString(dst *string, src *string) {
	if src == nil {
		return
	}
	*dst = strings.TrimSpace(*src)
}

// GET /api/v1/proxy-hosts
func (s *Server) apiV1ListProxyHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	serverID := s.currentServerID(r)
	hosts, err := models.ListProxyHosts(s.DB, serverID, cu.ID, cu.IsAdmin, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(hosts))
	for i := range hosts {
		out = append(out, s.proxyHostToAPIMap(&hosts[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/proxy-hosts/{id}
func (s *Server) apiV1GetProxyHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(cu, ph.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, s.proxyHostToAPIMap(ph))
}

// POST /api/v1/proxy-hosts
func (s *Server) apiV1CreateProxyHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var inp apiProxyHostInput
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Domains == "" || inp.ForwardHost == "" || inp.ForwardPort == 0 {
		writeJSONError(w, http.StatusBadRequest, "domains, forward_host, and forward_port are required")
		return
	}
	if inp.ForwardScheme == "" {
		inp.ForwardScheme = "http"
	}
	if inp.HealthCheckMethod == "" {
		inp.HealthCheckMethod = "GET"
	}
	if err := validateClientAuthInput(inp.ClientAuthMode, inp.ClientAuthCAFiles); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ph := &models.ProxyHost{
		Domains: inp.Domains, ForwardScheme: inp.ForwardScheme,
		ForwardHost: inp.ForwardHost, ForwardPort: inp.ForwardPort,
		WebsocketSupport: inp.WebsocketSupport, BlockCommonExploits: inp.BlockCommonExploits,
		SSLEnabled: inp.SSLEnabled, SSLForced: inp.SSLForced, HTTP2Support: inp.HTTP2Support,
		Enabled: inp.Enabled, CertificateID: inp.CertificateID,
		BasicAuthEnabled: inp.BasicAuthEnabled, BasicAuthUsers: "[]",
		AccessList: inp.AccessList, IPBlocklist: inp.IPBlocklist,
		ExtraUpstreams: func() string {
			if inp.ExtraUpstreams == "" {
				return "[]"
			}
			return inp.ExtraUpstreams
		}(),
		CompressionEnabled: inp.CompressionEnabled, SecurityHeadersEnabled: inp.SecurityHeadersEnabled,
		TLSMinVersion:     inp.TLSMinVersion,
		ClientAuthMode:    inp.ClientAuthMode,
		ClientAuthCAFiles: inp.ClientAuthCAFiles,
		MaintenanceMode:   inp.MaintenanceMode, MaintenanceMsg: inp.MaintenanceMsg,
		MaxRequestBodyMB: inp.MaxRequestBodyMB, StickySessions: inp.StickySessions,
		LBPolicy: inp.LBPolicy, UpstreamTimeoutSec: inp.UpstreamTimeoutSec,
		CORSEnabled: inp.CORSEnabled, CORSOrigins: func() string {
			if inp.CORSOrigins == "" {
				return "*"
			}
			return inp.CORSOrigins
		}(),
		HealthCheckURI: inp.HealthCheckURI, HealthCheckIntervalSec: func() int {
			if inp.HealthCheckIntervalSec <= 0 {
				return 30
			}
			return inp.HealthCheckIntervalSec
		}(),
		HealthCheckMethod: inp.HealthCheckMethod, KeepaliveConns: inp.KeepaliveConns,
		Tags: inp.Tags, Notes: inp.Notes,
		DisableAccessLog: inp.DisableAccessLog, AddRequestID: inp.AddRequestID,
		StripRespHeaders: inp.StripRespHeaders, BlockedAgents: inp.BlockedAgents,
		UpstreamSNI: inp.UpstreamSNI, HSTSPreload: inp.HSTSPreload,
		MaxConnsPerHost: inp.MaxConnsPerHost, UpstreamRetries: inp.UpstreamRetries,
		ForceHTTP1: inp.ForceHTTP1, ProxyProtocol: inp.ProxyProtocol,
		WWWRedirect:           normalizeWWWRedirect(inp.WWWRedirect),
		TrailingSlashRedirect: normalizeTrailingSlash(inp.TrailingSlashRedirect),
		BasicAuthRealm:        "Restricted", CustomReqHeaders: "{}", CustomRespHeaders: "{}",
		URLRewrites: "[]",
	}
	if err := applyProxyHostDetails(ph, inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := s.validateProxyAdvanced(s.caddyForRequest(r), ph); msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	// SSRF guard (GHSA-r4wm-rgc5-q834): non-admins may not point an upstream at
	// loopback/link-local/internal management addresses (e.g. the Caddy admin API).
	if msg := s.validateProxyUpstreamsForUser(cu, ph); msg != "" {
		writeJSONError(w, http.StatusForbidden, msg)
		return
	}
	serverID := s.currentServerID(r)
	ownerID := cu.ID
	if cu.IsAdmin {
		ownerID = 0
	}
	// v2.57.1: the UI refuses a domain another host or redirect already holds
	// on this server; this path did not. Caddy keeps the first matching route
	// and the newest row sorts first, so a duplicate silently hijacked the
	// existing host's traffic.
	if conflict, err := models.DomainsConflict(s.DB, serverID, ph.DomainList(), 0, 0); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not validate domains: "+err.Error())
		return
	} else if conflict != "" {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("domain %q is already in use by another proxy or redirect on this server", conflict))
		return
	}
	newID, err := models.CreateProxyHost(s.DB, serverID, ownerID, ph)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ph.ID = newID
	ph.ServerID = serverID
	if err := models.SetProxyHostProfile(s.DB, newID, inp.MiddlewareProfileID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, serverID, cu.Email, "proxy_create", fmt.Sprintf("proxy:%d", newID), ph.Domains, true)
	s.trySyncCaddy(serverID, false)
	created, _ := models.GetProxyHost(s.DB, newID)
	if created == nil {
		created = ph
	}
	writeJSON(w, http.StatusCreated, s.proxyHostToAPIMap(created))
}

// PUT /api/v1/proxy-hosts/{id}
func (s *Server) apiV1UpdateProxyHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetProxyHost(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(cu, existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	var inp apiProxyHostInput
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	// Merge: any field not supplied keeps the existing value.
	if inp.Domains != "" {
		existing.Domains = inp.Domains
	}
	if inp.ForwardScheme != "" {
		existing.ForwardScheme = inp.ForwardScheme
	}
	if inp.ForwardHost != "" {
		existing.ForwardHost = inp.ForwardHost
	}
	if inp.ForwardPort != 0 {
		existing.ForwardPort = inp.ForwardPort
	}
	if inp.CertificateID != 0 {
		existing.CertificateID = inp.CertificateID
	}
	if inp.TLSMinVersion != "" {
		existing.TLSMinVersion = inp.TLSMinVersion
	}
	// v2.64.0 (discussion #137): client certificate authentication. An
	// omitted field means "leave unchanged" throughout this handler, so
	// mTLS is switched off with the explicit mode "off" rather than "".
	if inp.ClientAuthMode != "" {
		if inp.ClientAuthMode == "off" {
			existing.ClientAuthMode, existing.ClientAuthCAFiles = "", ""
		} else {
			existing.ClientAuthMode = inp.ClientAuthMode
		}
	}
	if inp.ClientAuthCAFiles != "" && existing.ClientAuthMode != "" {
		existing.ClientAuthCAFiles = inp.ClientAuthCAFiles
	}
	if err := validateClientAuthInput(existing.ClientAuthMode, existing.ClientAuthCAFiles); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if inp.MaintenanceMsg != "" {
		existing.MaintenanceMsg = inp.MaintenanceMsg
	}
	if inp.MaxRequestBodyMB != 0 {
		existing.MaxRequestBodyMB = inp.MaxRequestBodyMB
	}
	if inp.UpstreamTimeoutSec != 0 {
		existing.UpstreamTimeoutSec = inp.UpstreamTimeoutSec
	}
	if inp.CORSOrigins != "" {
		existing.CORSOrigins = inp.CORSOrigins
	}
	if inp.HealthCheckURI != "" {
		existing.HealthCheckURI = inp.HealthCheckURI
	}
	if inp.HealthCheckIntervalSec != 0 {
		existing.HealthCheckIntervalSec = inp.HealthCheckIntervalSec
	}
	if inp.HealthCheckMethod != "" {
		existing.HealthCheckMethod = inp.HealthCheckMethod
	}
	if inp.KeepaliveConns != 0 {
		existing.KeepaliveConns = inp.KeepaliveConns
	}
	if inp.StripRespHeaders != "" {
		existing.StripRespHeaders = inp.StripRespHeaders
	}
	if inp.BlockedAgents != "" {
		existing.BlockedAgents = inp.BlockedAgents
	}
	if inp.UpstreamSNI != "" {
		existing.UpstreamSNI = inp.UpstreamSNI
	}
	if inp.MaxConnsPerHost != 0 {
		existing.MaxConnsPerHost = inp.MaxConnsPerHost
	}
	if inp.UpstreamRetries != 0 {
		existing.UpstreamRetries = inp.UpstreamRetries
	}
	if inp.ProxyProtocol != "" {
		existing.ProxyProtocol = inp.ProxyProtocol
	}
	if next := normalizeWWWRedirect(inp.WWWRedirect); inp.WWWRedirect != "" {
		existing.WWWRedirect = next
	}
	if next := normalizeTrailingSlash(inp.TrailingSlashRedirect); inp.TrailingSlashRedirect != "" {
		existing.TrailingSlashRedirect = next
	}
	if inp.ExtraUpstreams != "" {
		existing.ExtraUpstreams = inp.ExtraUpstreams
	}
	existing.WebsocketSupport = inp.WebsocketSupport
	existing.BlockCommonExploits = inp.BlockCommonExploits
	existing.SSLEnabled = inp.SSLEnabled
	existing.SSLForced = inp.SSLForced
	existing.HTTP2Support = inp.HTTP2Support
	existing.Enabled = inp.Enabled
	existing.BasicAuthEnabled = inp.BasicAuthEnabled
	existing.CompressionEnabled = inp.CompressionEnabled
	existing.SecurityHeadersEnabled = inp.SecurityHeadersEnabled
	existing.MaintenanceMode = inp.MaintenanceMode
	existing.StickySessions = inp.StickySessions
	existing.CORSEnabled = inp.CORSEnabled
	existing.DisableAccessLog = inp.DisableAccessLog
	existing.AddRequestID = inp.AddRequestID
	existing.HSTSPreload = inp.HSTSPreload
	existing.ForceHTTP1 = inp.ForceHTTP1
	if inp.Tags != "" {
		existing.Tags = inp.Tags
	}
	if inp.Notes != "" {
		existing.Notes = inp.Notes
	}
	if inp.AccessList != "" {
		existing.AccessList = inp.AccessList
	}
	if inp.IPBlocklist != "" {
		existing.IPBlocklist = inp.IPBlocklist
	}
	if inp.LBPolicy != "" {
		existing.LBPolicy = inp.LBPolicy
	}
	if err := applyProxyHostDetails(existing, inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := s.validateProxyAdvanced(s.caddyForRequest(r), existing); msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	// SSRF guard (GHSA-r4wm-rgc5-q834): re-validate the merged upstreams so a
	// non-admin can't edit an existing host to target an internal address.
	if msg := s.validateProxyUpstreamsForUser(cu, existing); msg != "" {
		writeJSONError(w, http.StatusForbidden, msg)
		return
	}
	if conflict, err := models.DomainsConflict(s.DB, existing.ServerID, existing.DomainList(), existing.ID, 0); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not validate domains: "+err.Error())
		return
	} else if conflict != "" {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("domain %q is already in use by another proxy or redirect on this server", conflict))
		return
	}
	if err := models.UpdateProxyHost(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := models.SetProxyHostProfile(s.DB, existing.ID, inp.MiddlewareProfileID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, existing.ServerID, s.currentUserEmail(r), "proxy_update", fmt.Sprintf("proxy:%d", id), existing.Domains, true)
	s.trySyncCaddy(existing.ServerID, existing.CertificateID != 0)
	updated, _ := models.GetProxyHost(s.DB, id)
	if updated == nil {
		updated = existing
	}
	writeJSON(w, http.StatusOK, s.proxyHostToAPIMap(updated))
}

// DELETE /api/v1/proxy-hosts/{id}
func (s *Server) apiV1DeleteProxyHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(cu, ph.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if ph.DNSRecordID != "" {
		s.dnsDeleteRecord(ph.DNSProvider, ph.DNSProfileID, ph.DNSZoneID, ph.DNSZoneName, ph.DNSRecordID)
	}
	note := s.noteFleetDeletion(models.FleetResourceProxy, id, ph.Domains)
	if err := models.DeleteProxyHost(s.DB, id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, ph.ServerID, s.currentUserEmail(r), "proxy_delete", fmt.Sprintf("proxy:%d", id), ph.Domains, true)
	s.trySyncCaddyAfterDelete(ph.ServerID, false)
	s.propagateNotedDeletion(s.currentUserEmail(r), note) // v2.59.0 (issue #120)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// POST /api/v1/proxy-hosts/{id}/toggle
func (s *Server) apiV1ToggleProxyHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), ph.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	ph.Enabled = !ph.Enabled
	if err := models.UpdateProxyHost(s.DB, ph); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.trySyncCaddy(ph.ServerID, false)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": ph.Enabled})
}

// POST /api/v1/proxy-hosts/{id}/maintenance
func (s *Server) apiV1ToggleMaintenanceProxyHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), ph.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	// Accept optional JSON body {"maintenance": true/false}; default = toggle.
	var body struct {
		Maintenance *bool `json:"maintenance"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Maintenance != nil {
		ph.MaintenanceMode = *body.Maintenance
	} else {
		ph.MaintenanceMode = !ph.MaintenanceMode
	}
	if err := models.UpdateProxyHost(s.DB, ph); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.trySyncCaddy(ph.ServerID, false)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "maintenance_mode": ph.MaintenanceMode})
}

// ─── Redirection Host REST API ────────────────────────────────────────────────

func redirectionHostToAPIMap(r *models.RedirectionHost) map[string]any {
	return map[string]any{
		"id":                r.ID,
		"domains":           r.Domains,
		"forward_scheme":    r.ForwardScheme,
		"forward_domain":    r.ForwardDomain,
		"forward_http_code": r.ForwardHTTPCode,
		"preserve_path":     r.PreservePath,
		"ssl_enabled":       r.SSLEnabled,
		"ssl_forced":        r.SSLForced,
		"enabled":           r.Enabled,
		"certificate_id":    r.CertificateID,
		"tags":              r.Tags,
		"notes":             r.Notes,
		"owner_email":       r.OwnerEmail,
		"created_at":        r.CreatedAt,
		"updated_at":        r.UpdatedAt,
	}
}

// GET /api/v1/redirection-hosts
func (s *Server) apiV1ListRedirectionHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hosts, err := models.ListRedirectionHosts(s.DB, s.currentServerID(r), cu.ID, cu.IsAdmin, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(hosts))
	for i := range hosts {
		out = append(out, redirectionHostToAPIMap(&hosts[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/redirection-hosts/{id}
func (s *Server) apiV1GetRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rh, err := models.GetRedirectionHost(s.DB, id)
	if err != nil || rh == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), rh.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, redirectionHostToAPIMap(rh))
}

// POST /api/v1/redirection-hosts
func (s *Server) apiV1CreateRedirectionHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var inp struct {
		Domains         string `json:"domains"`
		ForwardScheme   string `json:"forward_scheme"`
		ForwardDomain   string `json:"forward_domain"`
		ForwardHTTPCode int    `json:"forward_http_code"`
		PreservePath    bool   `json:"preserve_path"`
		SSLEnabled      bool   `json:"ssl_enabled"`
		SSLForced       bool   `json:"ssl_forced"`
		Enabled         bool   `json:"enabled"`
		CertificateID   int64  `json:"certificate_id"`
		Tags            string `json:"tags"`
		Notes           string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Domains == "" || inp.ForwardDomain == "" {
		writeJSONError(w, http.StatusBadRequest, "domains and forward_domain are required")
		return
	}
	if inp.ForwardScheme == "" {
		inp.ForwardScheme = "auto"
	}
	if inp.ForwardHTTPCode == 0 {
		inp.ForwardHTTPCode = 301
	}
	rh := &models.RedirectionHost{
		Domains: inp.Domains, ForwardScheme: inp.ForwardScheme,
		ForwardDomain: inp.ForwardDomain, ForwardHTTPCode: inp.ForwardHTTPCode,
		PreservePath: inp.PreservePath, SSLEnabled: inp.SSLEnabled, SSLForced: inp.SSLForced,
		Enabled: inp.Enabled, CertificateID: inp.CertificateID,
		Tags: inp.Tags, Notes: inp.Notes,
	}
	serverID := s.currentServerID(r)
	ownerID := int64(0)
	if !cu.IsAdmin {
		ownerID = cu.ID
	}
	if msg := s.validateRedirectionForUser(cu, rh); msg != "" { // v2.57.1
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	if conflict, err := models.DomainsConflict(s.DB, serverID, rh.DomainList(), 0, 0); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not validate domains: "+err.Error())
		return
	} else if conflict != "" {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("domain %q is already in use by another proxy or redirect on this server", conflict))
		return
	}
	newID, err := models.CreateRedirectionHost(s.DB, serverID, ownerID, rh)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, serverID, cu.Email, "redirect_create", fmt.Sprintf("redir:%d", newID), rh.Domains, true)
	s.trySyncCaddy(serverID, false)
	created, _ := models.GetRedirectionHost(s.DB, newID)
	if created == nil {
		created = rh
		created.ID = newID
	}
	writeJSON(w, http.StatusCreated, redirectionHostToAPIMap(created))
}

// PUT /api/v1/redirection-hosts/{id}
func (s *Server) apiV1UpdateRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRedirectionHost(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	var inp struct {
		Domains         string `json:"domains"`
		ForwardScheme   string `json:"forward_scheme"`
		ForwardDomain   string `json:"forward_domain"`
		ForwardHTTPCode int    `json:"forward_http_code"`
		PreservePath    bool   `json:"preserve_path"`
		SSLEnabled      bool   `json:"ssl_enabled"`
		SSLForced       bool   `json:"ssl_forced"`
		Enabled         bool   `json:"enabled"`
		Tags            string `json:"tags"`
		Notes           string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Domains != "" {
		existing.Domains = inp.Domains
	}
	if inp.ForwardScheme != "" {
		existing.ForwardScheme = inp.ForwardScheme
	}
	if inp.ForwardDomain != "" {
		existing.ForwardDomain = inp.ForwardDomain
	}
	if inp.ForwardHTTPCode != 0 {
		existing.ForwardHTTPCode = inp.ForwardHTTPCode
	}
	existing.PreservePath = inp.PreservePath
	existing.SSLEnabled = inp.SSLEnabled
	existing.SSLForced = inp.SSLForced
	existing.Enabled = inp.Enabled
	if inp.Tags != "" {
		existing.Tags = inp.Tags
	}
	if inp.Notes != "" {
		existing.Notes = inp.Notes
	}
	if msg := s.validateRedirectionForUser(s.currentUser(r), existing); msg != "" { // v2.57.1
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	if conflict, err := models.DomainsConflict(s.DB, s.currentServerID(r), existing.DomainList(), 0, existing.ID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not validate domains: "+err.Error())
		return
	} else if conflict != "" {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("domain %q is already in use by another proxy or redirect on this server", conflict))
		return
	}
	if err := models.UpdateRedirectionHost(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_update", fmt.Sprintf("redir:%d", id), existing.Domains, true)
	s.trySyncCaddy(s.currentServerID(r), false)
	updated, _ := models.GetRedirectionHost(s.DB, id)
	if updated == nil {
		updated = existing
	}
	writeJSON(w, http.StatusOK, redirectionHostToAPIMap(updated))
}

// DELETE /api/v1/redirection-hosts/{id}
func (s *Server) apiV1DeleteRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRedirectionHost(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	note := s.noteFleetDeletion(models.FleetResourceRedirect, id, existing.Domains)
	if err := models.DeleteRedirectionHost(s.DB, id); err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_delete", fmt.Sprintf("redir:%d", id), "", true)
	s.trySyncCaddyAfterDelete(s.currentServerID(r), false)
	s.propagateNotedDeletion(s.currentUserEmail(r), note)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// POST /api/v1/redirection-hosts/{id}/toggle
func (s *Server) apiV1ToggleRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRedirectionHost(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	enabled, err := models.ToggleRedirectionHost(s.DB, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not found or error: "+err.Error())
		return
	}
	rh, _ := models.GetRedirectionHost(s.DB, id)
	if rh != nil {
		s.syncCaddy(s.currentServerID(r), false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": enabled})
}

// --- REST JSON API v1: Raw Routes ---

func rawRouteToAPIMap(r *models.RawRoute) map[string]any {
	return map[string]any{
		"id":                    r.ID,
		"label":                 r.Label,
		"listen":                r.ListenDisplay(), // v2.36.1 (issue #64)
		"json_data":             r.JSONData,
		"caddyfile_src":         r.CaddyfileSrc,
		"enabled":               r.Enabled,
		"certificate_id":        r.CertificateID,
		"force_ssl":             r.ForceSSL,
		"block_common_exploits": r.BlockCommonExploits,
		"owner_email":           r.OwnerEmail,
		"created_at":            r.CreatedAt,
		"updated_at":            r.UpdatedAt,
	}
}

// GET /api/v1/raw-routes
func (s *Server) apiV1ListRawRoutes(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	routes, err := models.ListRawRoutes(s.DB, s.currentServerID(r), cu.ID, cu.IsAdmin, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(routes))
	for i := range routes {
		out = append(out, rawRouteToAPIMap(&routes[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/raw-routes/{id}
func (s *Server) apiV1GetRawRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rr, err := models.GetRawRoute(s.DB, id)
	if err != nil || rr == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), rr.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, rawRouteToAPIMap(rr))
}

// POST /api/v1/raw-routes
func (s *Server) apiV1CreateRawRoute(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var inp struct {
		Label               string `json:"label"`
		JSONData            string `json:"json_data"`
		CaddyfileSrc        string `json:"caddyfile_src"`
		Enabled             bool   `json:"enabled"`
		CertificateID       int64  `json:"certificate_id"`
		ForceSSL            bool   `json:"force_ssl"`
		BlockCommonExploits bool   `json:"block_common_exploits"`
		Listen              string `json:"listen"` // v2.36.1 (issue #64): e.g. ":7070" or ":7070, :7071"
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.JSONData == "" {
		writeJSONError(w, http.StatusBadRequest, "json_data is required")
		return
	}
	rr := &models.RawRoute{
		Label: inp.Label, JSONData: inp.JSONData, CaddyfileSrc: inp.CaddyfileSrc,
		Enabled: inp.Enabled, CertificateID: inp.CertificateID,
		ForceSSL: inp.ForceSSL, BlockCommonExploits: inp.BlockCommonExploits,
		Listen: models.NormalizeRawRouteListen(models.ParseRawRouteListenInput(inp.Listen)), // v2.36.1 (issue #64)
	}
	serverID := s.currentServerID(r)
	ownerID := int64(0)
	if !cu.IsAdmin {
		ownerID = cu.ID
	}
	if msg := s.validateRawRouteForUser(cu, rr); msg != "" { // v2.57.1
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	newID, err := models.CreateRawRoute(s.DB, serverID, ownerID, rr)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, serverID, cu.Email, "rawroute_create", fmt.Sprintf("rr:%d", newID), inp.Label, true)
	s.trySyncCaddy(serverID, false)
	created, _ := models.GetRawRoute(s.DB, newID)
	if created == nil {
		created = rr
		created.ID = newID
	}
	writeJSON(w, http.StatusCreated, rawRouteToAPIMap(created))
}

// PUT /api/v1/raw-routes/{id}
func (s *Server) apiV1UpdateRawRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRawRoute(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	var inp struct {
		Label               string `json:"label"`
		JSONData            string `json:"json_data"`
		CaddyfileSrc        string `json:"caddyfile_src"`
		Enabled             bool   `json:"enabled"`
		CertificateID       int64  `json:"certificate_id"`
		ForceSSL            bool   `json:"force_ssl"`
		BlockCommonExploits bool   `json:"block_common_exploits"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Label != "" {
		existing.Label = inp.Label
	}
	if inp.JSONData != "" {
		existing.JSONData = inp.JSONData
	}
	if inp.CaddyfileSrc != "" {
		existing.CaddyfileSrc = inp.CaddyfileSrc
	}
	existing.Enabled = inp.Enabled
	existing.ForceSSL = inp.ForceSSL
	existing.BlockCommonExploits = inp.BlockCommonExploits
	if inp.CertificateID != 0 {
		existing.CertificateID = inp.CertificateID
	}
	if msg := s.validateRawRouteForUser(s.currentUser(r), existing); msg != "" { // v2.57.1
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	if err := models.UpdateRawRoute(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "rawroute_update", fmt.Sprintf("rr:%d", id), existing.Label, true)
	s.trySyncCaddy(s.currentServerID(r), false)
	updated, _ := models.GetRawRoute(s.DB, id)
	if updated == nil {
		updated = existing
	}
	writeJSON(w, http.StatusOK, rawRouteToAPIMap(updated))
}

// DELETE /api/v1/raw-routes/{id}
func (s *Server) apiV1DeleteRawRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRawRoute(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	note := s.noteFleetDeletion(models.FleetResourceRawRoute, id, existing.Label)
	if err := models.DeleteRawRoute(s.DB, id); err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "rawroute_delete", fmt.Sprintf("rr:%d", id), "", true)
	s.trySyncCaddyAfterDelete(s.currentServerID(r), false)
	s.propagateNotedDeletion(s.currentUserEmail(r), note)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// POST /api/v1/raw-routes/{id}/toggle
func (s *Server) apiV1ToggleRawRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRawRoute(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	enabled, err := models.ToggleRawRoute(s.DB, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not found or error: "+err.Error())
		return
	}
	rr, _ := models.GetRawRoute(s.DB, id)
	if rr != nil {
		s.syncCaddy(s.currentServerID(r), false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": enabled})
}

// --- REST JSON API v1: Certificates ---

// apiCallerMaySeeSecrets reports whether this request may be shown stored
// secrets such as certificate private keys: a signed-in browser session or a
// full-scope token. read_only and proxy_write tokens are the kind of credential
// that ends up in dashboards and CI logs, so they never receive key material
// even when the user that owns them could read it.
func apiCallerMaySeeSecrets(r *http.Request) bool {
	switch currentAPITokenScope(r) {
	case "", models.TokenScopeFull:
		return true
	}
	return false
}

func certificateToAPIMap(c *models.Certificate, includeSecrets bool) map[string]any {
	ownerID := int64(0)
	if c.OwnerID.Valid {
		ownerID = c.OwnerID.Int64
	}
	out := map[string]any{
		"id":             c.ID,
		"name":           c.Name,
		"domains":        c.Domains,
		"source":         c.Source,
		"cert_pem":       c.CertPEM,
		"key_pem":        c.KeyPEM,
		"cert_path":      c.CertPath,
		"key_path":       c.KeyPath,
		"dns_provider":   c.DNSProvider,
		"dns_profile_id": c.DNSProfileID,
		"owner_id":       ownerID,
		"owner_email":    c.OwnerEmail,
		"created_at":     c.CreatedAt,
		"updated_at":     c.UpdatedAt,
	}
	// Security (v2.57.1): private keys and file paths are only for callers who
	// may manage the row. The list endpoint used to return key_pem for every
	// admin-owned (global) certificate to any role — including read-only
	// tokens — because the single-row GET checked ownership and the list did not.
	if !includeSecrets {
		delete(out, "key_pem")
		delete(out, "key_path")
		delete(out, "cert_path")
	}
	return out
}

// GET /api/v1/certificates
func (s *Server) apiV1ListCertificates(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	page, err := s.loadCertificatePage(r, "")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(page.Views))
	for i := range page.Views {
		view := &page.Views[i]
		item := certificateToAPIMap(&view.Certificate, s.canManageOwned(cu, view.OwnerID) && apiCallerMaySeeSecrets(r))
		item["can_edit"] = view.CanEdit
		item["is_unused"] = view.IsUnused
		item["days_left"] = view.DaysLeft
		item["expiry_source"] = view.ExpirySource
		item["served_differs"] = view.ServedDiffers
		if view.ExpiresAt != nil {
			item["expires_at"] = view.ExpiresAt.UTC()
		}
		if view.Lifecycle != nil {
			item["lifecycle_phase"] = view.Lifecycle.Phase
			item["lifecycle_message"] = view.Lifecycle.Message
		}
		if view.Probe != nil && view.Probe.Status != "" {
			item["probe_status"] = view.Probe.Status
			if view.Probe.Error != "" {
				item["probe_error"] = view.Probe.Error
			}
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/certificates/{id}
func (s *Server) apiV1GetCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	c, err := models.GetCertificate(s.DB, id)
	if err != nil || c == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), c.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, certificateToAPIMap(c, apiCallerMaySeeSecrets(r))) // canManageOwned passed above
}

// POST /api/v1/certificates
func (s *Server) apiV1CreateCertificate(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var inp struct {
		Name         string `json:"name"`
		Domains      string `json:"domains"`
		Source       string `json:"source"`
		CertPEM      string `json:"cert_pem"`
		KeyPEM       string `json:"key_pem"`
		CertPath     string `json:"cert_path"`
		KeyPath      string `json:"key_path"`
		DNSProvider  string `json:"dns_provider"`
		DNSProfileID string `json:"dns_profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if inp.Source == "" {
		inp.Source = "pem"
	}
	c := &models.Certificate{
		Name: inp.Name, Domains: inp.Domains, Source: inp.Source,
		CertPEM: inp.CertPEM, KeyPEM: inp.KeyPEM,
		CertPath: inp.CertPath, KeyPath: inp.KeyPath,
		DNSProvider: inp.DNSProvider, DNSProfileID: inp.DNSProfileID,
	}
	serverID := s.currentServerID(r)
	ownerID := int64(0)
	if !cu.IsAdmin {
		ownerID = cu.ID
	}
	newID, err := models.CreateCertificate(s.DB, serverID, ownerID, c)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, serverID, cu.Email, "cert_create", fmt.Sprintf("cert:%d", newID), inp.Name, true)
	created, _ := models.GetCertificate(s.DB, newID)
	if created == nil {
		created = c
		created.ID = newID
	}
	writeJSON(w, http.StatusCreated, certificateToAPIMap(created, apiCallerMaySeeSecrets(r)))
}

// PUT /api/v1/certificates/{id}
func (s *Server) apiV1UpdateCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetCertificate(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	var inp struct {
		Name         string `json:"name"`
		Domains      string `json:"domains"`
		Source       string `json:"source"`
		CertPEM      string `json:"cert_pem"`
		KeyPEM       string `json:"key_pem"`
		CertPath     string `json:"cert_path"`
		KeyPath      string `json:"key_path"`
		DNSProvider  string `json:"dns_provider"`
		DNSProfileID string `json:"dns_profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Name != "" {
		existing.Name = inp.Name
	}
	if inp.Domains != "" {
		existing.Domains = inp.Domains
	}
	if inp.Source != "" {
		existing.Source = inp.Source
	}
	if inp.CertPEM != "" {
		existing.CertPEM = inp.CertPEM
	}
	if inp.KeyPEM != "" {
		existing.KeyPEM = inp.KeyPEM
	}
	if inp.CertPath != "" {
		existing.CertPath = inp.CertPath
	}
	if inp.KeyPath != "" {
		existing.KeyPath = inp.KeyPath
	}
	if inp.DNSProvider != "" {
		existing.DNSProvider = inp.DNSProvider
	}
	if inp.DNSProfileID != "" {
		existing.DNSProfileID = inp.DNSProfileID
	}
	if err := models.UpdateCertificate(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_update", fmt.Sprintf("cert:%d", id), existing.Name, true)
	updated, _ := models.GetCertificate(s.DB, id)
	if updated == nil {
		updated = existing
	}
	writeJSON(w, http.StatusOK, certificateToAPIMap(updated, apiCallerMaySeeSecrets(r)))
}

// DELETE /api/v1/certificates/{id}
func (s *Server) apiV1DeleteCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetCertificate(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.canManageOwned(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if inUse, _ := models.CertificateInUse(s.DB, id); inUse > 0 {
		writeJSONError(w, http.StatusConflict, "certificate is in use by one or more hosts; remove references first")
		return
	}
	if err := models.DeleteCertificate(s.DB, id); err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_delete", fmt.Sprintf("cert:%d", id), "", true)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}
