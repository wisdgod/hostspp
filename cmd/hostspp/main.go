/*
Hosts++
Copyright (C) 2024 wisdgod

This program is free software: you can redistribute it and/or modify
it under the terms of the Apache License 2.0.

Disclaimer: This software is for educational purposes only. Use at your own risk.
The authors are not responsible for any misuse or damages.

免责声明：本软件仅供教育目的使用。使用者自担风险。作者不对任何滥用或损害负责。
*/

package main

import (
	"flag"
	"hosts++/internal/api"
	"hosts++/internal/config"
	"hosts++/internal/handler"
	"hosts++/internal/systrust"
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

	// 获取 CA 证书
	caCertPEM := certificate.GetRootCAPEM()

	// 删除旧的系统信任证书（如果存在）
	if err := systrust.RemoveOldSystemCert(); err != nil {
		log.Warn("Failed to remove old system certificate: %v", err)
	}

	// 添加新的系统信任 CA 证书
	if err := systrust.AddNewSystemCert(caCertPEM); err != nil {
		log.Warn("Failed to add new system certificate: %v", err)
	}

	// 创建处理器
	h := handler.New(cfg)

	// 创建 API 服务
	apiServer := api.New(cfg)

	// 创建 HTTP 服务器
	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)

	// 使用 WithAPIHandler 方法来组合 API 处理器和主处理器
	combinedHandler := h.WithAPIHandler(mux)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: combinedHandler,
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
