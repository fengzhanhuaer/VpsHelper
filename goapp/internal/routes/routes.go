package routes

import (
	"database/sql"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"vpshelper-go/internal/config"
	"vpshelper-go/internal/web"
	"vpshelper-go/static"
	"vpshelper-go/templates"
)

func LoadTemplates(cfg config.Config) (*template.Template, error) {
	funcs := template.FuncMap{
		"join": strings.Join,
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
	// Serve static assets: prefer disk directory when present (dev mode),
	// fall back to embedded FS for production single-binary deployment.
	staticDir := filepath.Join(cfg.BaseDir, "static")
	if st, err := os.Stat(staticDir); err == nil && st.IsDir() {
		router.Static("/static", staticDir)
	} else {
		router.StaticFS("/static", http.FS(static.FS))
	}

	web.Register(router, cfg, dbConn)
}
