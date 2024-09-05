package main

import (
	"flag"
	"hosts++/internal/api"
	"hosts++/internal/config"
	"hosts++/internal/proxy"
	"hosts++/pkg/certificate"
	"hosts++/pkg/logger"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var (
	configPath string
	listenAddr string
)

func init() {
	flag.StringVar(&configPath, "config", "configs/config.yaml", "Path to configuration file")
	flag.StringVar(&listenAddr, "listen", ":8080", "Address to listen on")
	flag.Parse()
}

func main() {
	log := logger.GetInstance()

	// 加载配置
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Error("Failed to load config: %v", err)
		os.Exit(1)
	}

	// 设置日志级别
	setLogLevel(log, cfg.LogLevel)

	// 如果命令行指定了监听地址，覆盖配置文件中的地址
	if listenAddr != "" {
		cfg.ListenAddr = listenAddr
	}

	// 生成并保存 CA 证书
	caCertPEM := certificate.GetRootCAPEM()
	if err := os.WriteFile("ca.crt", caCertPEM, 0644); err != nil {
		log.Error("Failed to save CA certificate: %v", err)
		os.Exit(1)
	}
	log.Info("CA certificate saved to ca.crt")

	// 创建代理服务器
	p := proxy.New(cfg)

	// 创建 API 服务
	apiServer := api.New(cfg)

	// 创建 HTTP 服务器
	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)
	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: p.WithAPIHandler(mux),
	}

	// 启动服务器
	go func() {
		log.Info("Starting Hosts++ proxy server on %s", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Server failed: %v", err)
			os.Exit(1)
		}
	}()

	// 等待中断信号以优雅地关闭服务器（设置 5 秒的超时时间）
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("Shutting down server...")

	if err := server.Close(); err != nil {
		log.Error("Server forced to shutdown: %v", err)
	}

	log.Info("Server exiting")
}

func setLogLevel(log *logger.Logger, level string) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		log.SetLevel(logger.LevelDebug)
	case "INFO":
		log.SetLevel(logger.LevelInfo)
	case "WARN":
		log.SetLevel(logger.LevelWarn)
	case "ERROR":
		log.SetLevel(logger.LevelError)
	case "OFF":
		log.SetLevel(logger.LevelOff)
	default:
		log.Warn("Invalid log level '%s', defaulting to INFO", level)
	}
}
