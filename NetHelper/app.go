package main

import (
	"context"

	"NetHelper/internal/conntrack"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// GetConnections 返回当前系统所有活跃网络连接（含进程信息）
// 供前端每 1s 轮询调用
func (a *App) GetConnections() ([]conntrack.Connection, error) {
	return conntrack.Snapshot()
}
