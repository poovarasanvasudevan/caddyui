package web

import (
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// UI serves the embedded React build at /web.
// Client-side routes fall back to index.html. Real files, including hashed
// assets, are served from the embedded ui directory.
func UI() http.Handler {
	sub, err := fs.Sub(FS, "ui")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "ui is not embedded", http.StatusNotFound)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/web")
		name = strings.TrimPrefix(name, "/")
		name = path.Clean("/" + name)
		name = strings.TrimPrefix(name, "/")
		if name == "" || name == "." {
			name = "index.html"
		}
		serveUI(w, r, sub, name, true)
	})
}

func serveUI(w http.ResponseWriter, r *http.Request, sub fs.FS, name string, fallback bool) {
	file, err := sub.Open(name)
	if err != nil {
		if fallback && (path.Ext(name) == "" || path.Ext(name) == ".html") {
			serveUI(w, r, sub, "index.html", false)
			return
		}
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if stat.IsDir() {
		serveUI(w, r, sub, path.Join(name, "index.html"), false)
		return
	}
	seeker, ok := file.(io.ReadSeeker)
	if !ok {
		http.Error(w, "cannot read embedded file", http.StatusInternalServerError)
		return
	}
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}
	http.ServeContent(w, r, path.Base(name), time.Time{}, seeker)
}
