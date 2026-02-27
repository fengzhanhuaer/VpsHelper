package routes

import (
	"database/sql"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"vpshelper-go/internal/config"
	"vpshelper-go/internal/web"
	"vpshelper-go/static"
	"vpshelper-go/templates"
)

func LoadTemplates(cfg config.Config) (*template.Template, error) {
	funcs := template.FuncMap{
		"join": strings.Join,
		"fmtUnix": func(ts int64) string {
			if ts == 0 {
				return ""
			}
			t := time.Unix(ts, 0).Local()
			return t.Format("01-02 15:04")
		},
	}

	// Prefer disk templates when explicitly configured and present (dev-friendly).
	if dir := strings.TrimSpace(cfg.TemplatesDir); dir != "" {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			pattern := filepath.Join(dir, "*.html")
			return template.New("").Funcs(funcs).ParseGlob(pattern)
		}
	}

	// Production: use embedded templates (single binary install).
	return template.New("").Funcs(funcs).ParseFS(templates.FS, "*.html")
}

func Register(router *gin.Engine, cfg config.Config, dbConn *sql.DB) {
	// Serve individual static files from the embedded FS.
	// Using GET handler per-file avoids issues with Gin's StaticFS
	// and http.FS path handling that caused 404s in production.
	staticFiles, _ := fs.ReadDir(static.FS, ".")
	for _, entry := range staticFiles {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		name := entry.Name()
		router.GET("/static/"+name, func(c *gin.Context) {
			data, err := static.FS.ReadFile(name)
			if err != nil {
				c.Status(http.StatusNotFound)
				return
			}
			contentType := "application/octet-stream"
			if strings.HasSuffix(name, ".css") {
				contentType = "text/css; charset=utf-8"
			} else if strings.HasSuffix(name, ".js") {
				contentType = "application/javascript; charset=utf-8"
			} else if strings.HasSuffix(name, ".svg") {
				contentType = "image/svg+xml"
			} else if strings.HasSuffix(name, ".png") {
				contentType = "image/png"
			}
			c.Header("Cache-Control", "public, max-age=86400")
			c.Data(http.StatusOK, contentType, data)
		})
	}

	web.Register(router, cfg, dbConn)
}
