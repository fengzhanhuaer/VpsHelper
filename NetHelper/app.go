package main

import (
	"context"
	"log"

	"NetHelper/internal/agent"
	"NetHelper/internal/config"
	"NetHelper/internal/conntrack"
	"NetHelper/internal/runlog"
	"NetHelper/internal/version"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx         context.Context
	cfg         *config.Config
	agentCtx    context.Context
	agentCancel context.CancelFunc
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	runlog.SetEmitter(func(line string) {
		wruntime.EventsEmit(a.ctx, "nethelper:runtime:log", line)
	})

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Printf("Failed to load config: %v", err)
		a.cfg = &config.Config{}
	} else {
		a.cfg = cfg
	}
	
	if a.cfg.ServerUrl != "" && a.cfg.SecretKey != "" {
		a.agentCtx, a.agentCancel = context.WithCancel(a.ctx)
		agent.Start(a.agentCtx, a.cfg)
	}
}

// GetConnections 返回当前系统所有活跃网络连接（含进程信息）
// 供前端每 1s 轮询调用
func (a *App) GetConnections() ([]conntrack.Connection, error) {
	return conntrack.Snapshot()
}

// GetSettings 返回当前的系统配置
func (a *App) GetSettings() *config.Config {
	return a.cfg
}

// SaveSettings 保存前端修改的配置
func (a *App) SaveSettings(serverUrl, secretKey string) error {
	a.cfg.ServerUrl = serverUrl
	a.cfg.SecretKey = secretKey
	if err := config.SaveConfig(a.cfg); err != nil {
		return err
	}
	
	if a.agentCancel != nil {
		a.agentCancel()
		a.agentCancel = nil
	}
	
	if a.cfg.ServerUrl != "" && a.cfg.SecretKey != "" {
		a.agentCtx, a.agentCancel = context.WithCancel(a.ctx)
		agent.Start(a.agentCtx, a.cfg)
	}
	
	return nil
}

// CheckUpdate 检查更新
func (a *App) CheckUpdate(useProxy bool) (map[string]interface{}, error) {
	return agent.CheckUpdate(a.ctx, a.cfg, useProxy)
}

// DoUpdate 执行版本更新
func (a *App) DoUpdate(useProxy bool, targetVersion, urlsDict string) error {
	return agent.DoUpdate(a.ctx, a.cfg, useProxy, targetVersion, urlsDict, func(msg string) {
		wruntime.EventsEmit(a.ctx, "nethelper:update:progress", msg)
	})
}

// GetVersion 返回当前版本号
func (a *App) GetVersion() string {
	return version.Version
}

// GetRuntimeLogs 返回运行日志（最近 limit 条）
func (a *App) GetRuntimeLogs(limit int) []string {
	return runlog.Snapshot(limit)
}

// GetProbeNodeInfo 获取探针节点信息，forceRefresh=true 时强制从主控拉取并更新本地缓存
func (a *App) GetProbeNodeInfo(forceRefresh bool) (map[string]interface{}, error) {
	info, err := agent.GetProbeNodeInfo(a.ctx, a.cfg, forceRefresh)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"node_id":         info.NodeID,
		"name":            info.Name,
		"address":         info.Address,
		"ddns_address":    info.DDNSAddress,
		"report_interval": info.ReportInterval,
		"server_url":      info.ServerURL,
		"updated_at":      info.UpdatedAt,
	}, nil
}
