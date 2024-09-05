package main

import (
	"fmt"
	"hosts++/pkg/logger"
	"hosts++/pkg/proxy/config"
	"hosts++/pkg/proxy/http"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v\nStack trace:\n%s", r, debug.Stack())
		}
	}()

	if err := config.LoadConfig("config.yaml"); err != nil {
		log.Fatalf("配置文件加载失败: %v", err)
	}

	started, err := http.StartProxyServer()
	if err != nil {
		log.Fatalf("启动代理服务器失败: %v", err)
	}

	select {
	case <-started:
		log.Println("代理服务器已成功启动")
	case <-time.After(10 * time.Second):
		log.Fatalf("启动代理服务器超时")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	fmt.Println("\n收到关闭信号，正在关闭 Hosts++ 代理服务器...")

	if err := logger.CloseLogger(); err != nil {
		log.Printf("关闭日志时发生错误: %v\n", err)
	}

	fmt.Println("Hosts++ 代理服务器已关闭")
}
