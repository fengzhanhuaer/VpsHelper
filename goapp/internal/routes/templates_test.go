package routes

import (
	"testing"

	"vpshelper-go/internal/config"
)

func TestLoadTemplatesEmbedded(t *testing.T) {
	cfg := config.Config{
		TemplatesDir: "",
	}

	tpls, err := LoadTemplates(cfg)
	if err != nil {
		t.Fatalf("LoadTemplates() error = %v", err)
	}
	if tpls.Lookup("tg_auto_send.html") == nil {
		t.Fatalf("template tg_auto_send.html not found")
	}
}

