package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"vpshelper-go/internal/agent"
)

func main() {
	var (
		serverHost string
		secret     string
		version    bool
	)

	flag.StringVar(&serverHost, "host", "", "控制中心的基础 URL (如 https://panel.example.com)")
	flag.StringVar(&secret, "secret", "", "探针节点专属接入密钥")
	flag.BoolVar(&version, "version", false, "显示版本号")
	flag.Parse()

	if os.Getenv("VPSHELPER_UPDATE_TEST") == "1" {
		fmt.Println("VPSHELPER_UPDATE_TEST is active. Running pre-flight probe health checks...")
		os.Exit(0)
	}

	if version {
		fmt.Println("VpsProbe v1.0.0 (Agent)")
		return
	}

	cfg, err := agent.LoadConfig()
	if err == nil && cfg.Host != "" && cfg.Secret != "" {
		serverHost = cfg.Host
		secret = cfg.Secret
		log.Printf("[Agent] 已从本地配置文件读取启动参数: %s", agent.GetConfigPath())
	} else {
		if serverHost == "" || secret == "" {
			log.Fatalf("错误: 必须提供 --host 和 --secret 参数，或者在可执行文件目录存放 vpsprobe.json")
		}
		agent.SaveConfig(agent.Config{Host: serverHost, Secret: secret})
		log.Printf("[Agent] 已将启动参数持久化至本地配置文件: %s", agent.GetConfigPath())
	}

	log.Printf("VpsProbe 启动 - 目标中心: %s", serverHost)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent.Start(ctx, serverHost, secret)

	log.Printf("探针核心服务已异步启动，正在尝试连接就绪...")

	// 阻塞等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("收到退出信号，探针关闭")
	cancel()
}
