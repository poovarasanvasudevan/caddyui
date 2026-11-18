package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUIServesIndexAndFallsBack(t *testing.T) {
	handler := UI()
	for _, target := range []string{"/web/", "/web/proxy-hosts"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s -> %d", target, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "<html") && !strings.Contains(rec.Body.String(), "<!doctype html") && !strings.Contains(strings.ToLower(rec.Body.String()), "<!doctype html") {
			t.Fatalf("%s body is not the app shell: %s", target, rec.Body.String())
		}
	}
}
