package routes

import (
	"database/sql"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"vpshelper-go/internal/config"
	"vpshelper-go/internal/web"
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
	web.Register(router, cfg, dbConn)
}
