package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"vpshelper-go/internal/cloudflare"
	"vpshelper-go/internal/config"
	"vpshelper-go/internal/d1"
	"vpshelper-go/internal/db"
	"vpshelper-go/internal/firewall"
	"vpshelper-go/internal/ns"
	"vpshelper-go/internal/routes"
	appstore "vpshelper-go/internal/store"
	"vpshelper-go/internal/tg"
	"vpshelper-go/internal/tunnel"
	"vpshelper-go/internal/version"
)

func main() {
	cfg := config.Load()

	database, err := db.Open(cfg)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if err := db.Migrate(database); err != nil {
		log.Fatalf("migrate db: %v", err)
	}

	// Open the local tg_data.db (dialogs, messages, send history).
	// This DB is intentionally kept separate and NOT backed up to D1.
	localDB, err := db.OpenLocal(cfg.DataDir)
	if err != nil {
		log.Fatalf("open local db: %v", err)
	}
	defer localDB.Close()
	appstore.SetLocalDB(localDB)
	if err := appstore.MigrateLegacyPeerKeys(); err != nil {
		log.Printf("warn: migrate legacy peer keys: %v", err)
	}

	// Open the probe_data.db (probe status and telemetry history).
	// This DB is strictly for probe data and is NOT backed up to D1.
	probeDB, err := db.OpenProbe(cfg.DataDir)
	if err != nil {
		log.Fatalf("open probe db: %v", err)
	}
	defer probeDB.Close()
	appstore.SetProbeDB(probeDB)

	// =========================================================================
	// 【私有服务端口】(Private Server Port) (默认: 15019)
	// 作用: 仅用于响应探针长链接 WebSocket 握手，下发命令及后续建立代理网络隧道(Yamux)。
	// 它不提供任何网页界面或常规 API 响应。
	// =========================================================================
	if err := tunnel.StartServer(context.Background(), database); err != nil {
		log.Printf("[warn] tunnel server start failed: %v", err)
	}
	tunnel.StartRenewalWatcher(context.Background(), database)
	d1.StartAutoBackup(context.Background(), database)
	tg.StartAutoSend(context.Background(), database)
	tg.StartAutoReply(context.Background(), database)
	cloudflare.StartDDNSWatch(context.Background(), database)
	ns.StartLotteryWatcher(context.Background(), database)
	firewall.StartDomainWatch(context.Background(), database)

	if os.Getenv("VPSHELPER_UPDATE_TEST") == "1" {
		log.Printf("VPSHELPER_UPDATE_TEST is active. Running pre-flight health checks...")
		// Avoid port conflicts with the running parent process
		cfg.ListenAddr = "127.0.0.1:0"
		// If the process survives for 10 seconds without crashing, exit with success.
		go func() {
			time.Sleep(10 * time.Second)
			log.Printf("Pre-flight checks passed successfully.")
			os.Exit(0)
		}()
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	store := cookie.NewStore([]byte(cfg.SessionKey))
	store.Options(sessions.Options{
		Path:     "/",
		HttpOnly: true,
	})
	router.Use(sessions.Sessions("vpshelper", store))

	tmpl, err := routes.LoadTemplates(cfg)
	if err != nil {
		log.Fatalf("load templates: %v", err)
	}
	router.SetHTMLTemplate(tmpl)

	routes.Register(router, cfg, database)
	// =========================================================================
	// 【主控服务端口】(Main Server Port) (默认: 15018)
	// 作用: 承载面向管理员的后台 Web 面板页面，同时响应探针的常规 HTTP 短链请求
	// (例如探针启动寻址 /api/probe/discover，或走代理通道下载最新安装包 /api/probe/latest_binary)。
	// =========================================================================
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
	}

	log.Printf("vpshelper version: %s", version.Version)
	log.Printf("server listening on %s", cfg.ListenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("server stopped: %v", err)
		os.Exit(1)
	}
}
