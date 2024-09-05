package logger

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Logger 接口定义了日志记录器应该实现的方法
type Logger interface {
	Debug(message string)
	Debugf(format string, args ...interface{})
	Info(message string)
	Infof(format string, args ...interface{})
	Warning(message string)
	Warningf(format string, args ...interface{})
	Error(message string)
	Errorf(format string, args ...interface{})
	SetLevel(level int)
	SetFormat(format string)
}

// HostsPPLogger 结构体封装了日志记录器的所有属性
type HostsPPLogger struct {
	logFile     *os.File       // 日志文件指针
	bufWriter   *bufio.Writer  // 缓冲写入器，用于提高写入性能
	logOutput   string         // 日志输出方式
	logLevel    int            // 当前日志级别
	timezone    *time.Location // 日志时间使用的时区
	format      string         // 日志格式模板
	mu          sync.Mutex     // 互斥锁，用于保护并发写入
	asyncQueue  chan string    // 异步写入队列
	archive     bool
	compress    bool
	logFilePath string
}

// 日志等级定义
const (
	DEBUG = iota
	INFO
	WARNING
	ERROR
)

// 输出方式定义
const (
	OutputConsole = "console" // 只输出到控制台
	OutputFile    = "file"    // 只输出到文件
	OutputBoth    = "both"    // 同时输出到控制台和文件
	OutputNone    = "none"    // 不输出
)

// 默认日志记录器实例
var defaultLogger *HostsPPLogger

// InitLogger 初始化日志系统
// level: 日志级别
// output: 输出方式
// logFilePath: 日志文件路径
// tz: 时区
// archive: 是否归档（未实现）
// compress: 是否压缩（未实现）
func InitLogger(level int, output, logFilePath, tz string, archive, compress bool) error {
	logger := &HostsPPLogger{
		logOutput:  output,
		logLevel:   level,
		format:     "%time% %level% %msg%",  // 默认日志格式
		asyncQueue: make(chan string, 1000), // 异步队列，缓冲大小为1000
		archive:    archive,
		compress:   compress,
	}

	// 设置时区
	var err error
	logger.timezone, err = time.LoadLocation(tz)
	if err != nil {
		logger.timezone = time.Local
	}

	// 设置日志文件路径
	logger.logFilePath = processLogFilePath(logFilePath)

	// 如果需要文件输出，打开日志文件
	if output == OutputFile || output == OutputBoth {
		logger.logFile, err = os.OpenFile(logger.logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("无法打开日志文件: %w", err)
		}
		logger.bufWriter = bufio.NewWriter(logger.logFile)
	}

	defaultLogger = logger

	// 启动异步写入goroutine
	go logger.asyncWriter()

	return nil
}

// asyncWriter 异步写入日志的goroutine
func (l *HostsPPLogger) asyncWriter() {
	for msg := range l.asyncQueue {
		l.writeLog(msg)
	}
}

func processLogFilePath(path string) string {
	if path == "" {
		path = "./logs/latest.log"
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	// 如果不是.log文件，添加.log后缀
	if !strings.HasSuffix(base, ".log") {
		base += ".log"
	}

	// 处理文件名，确保以-latest结尾
	re := regexp.MustCompile(`(-latest)?\.log$`)
	base = re.ReplaceAllString(base, "-latest.log")

	return filepath.Join(dir, base)
}

func (l *HostsPPLogger) rotateLog() error {
	if l.logFile == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// 关闭当前日志文件
	l.bufWriter.Flush()
	l.logFile.Close()

	// 生成新的文件名
	now := time.Now().In(l.timezone)
	count := 1
	var newPath string
	for {
		newPath = filepath.Join(filepath.Dir(l.logFilePath), fmt.Sprintf("%s-%d.log", now.Format("2006-01-02"), count))
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			break
		}
		count++
	}

	// 重命名当前日志文件
	err := os.Rename(l.logFilePath, newPath)
	if err != nil {
		return fmt.Errorf("无法重命名日志文件: %w", err)
	}

	// 如果需要压缩，压缩旧日志文件
	if l.compress {
		go l.compressLog(newPath)
	}

	// 创建新的日志文件
	l.logFile, err = os.OpenFile(l.logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("无法创建新日志文件: %w", err)
	}
	l.bufWriter = bufio.NewWriter(l.logFile)

	return nil
}

func (l *HostsPPLogger) compressLog(path string) {
	source, err := os.Open(path)
	if err != nil {
		fmt.Printf("无法打开日志文件进行压缩: %v\n", err)
		return
	}
	defer source.Close()

	target, err := os.Create(path + ".gz")
	if err != nil {
		fmt.Printf("无法创建压缩文件: %v\n", err)
		return
	}
	defer target.Close()

	gzw := gzip.NewWriter(target)
	defer gzw.Close()

	_, err = io.Copy(gzw, source)
	if err != nil {
		fmt.Printf("压缩日志文件时发生错误: %v\n", err)
		return
	}

	// 压缩成功后删除原文件
	if err = os.Remove(path); err != nil {
		Errorf("删除原文件时发生错误: %v\n", err)
	}
}

func (l *HostsPPLogger) writeLog(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 检查是否需要轮转日志
	if l.archive && l.logFile != nil {
		info, err := l.logFile.Stat()
		if err == nil && info.Size() > 10*1024*1024 { // 假设日志文件大小超过10MB时进行轮转
			if err = l.rotateLog(); err != nil {
				Errorf("轮转日志时发生错误: %v\n", err)
			}
		}
	}

	var err error
	retries := 3

	for i := 0; i < retries; i++ {
		switch l.logOutput {
		case OutputConsole:
			_, err = fmt.Print(message)
		case OutputFile:
			_, err = l.bufWriter.WriteString(message)
			if err == nil {
				err = l.bufWriter.Flush()
			}
		case OutputBoth:
			_, err = fmt.Print(message)
			if err == nil {
				_, err = l.bufWriter.WriteString(message)
				if err == nil {
					err = l.bufWriter.Flush()
				}
			}
		}

		if err == nil {
			break
		}

		time.Sleep(time.Millisecond * 100)
	}

	if err != nil {
		fmt.Printf("写入日志失败，重试%d次后: %v\n", retries, err)
	}
}

func (l *HostsPPLogger) formatLog(level int, message string) string {
	timestamp := time.Now().In(l.timezone).Format("2006-01-02 15:04:05")
	levelStr := getLevelString(level)

	var colorCode string
	switch level {
	case DEBUG:
		colorCode = "\033[1;90m"
	case INFO:
		colorCode = "\033[1;37m"
	case WARNING:
		colorCode = "\033[1;33m"
	case ERROR:
		colorCode = "\033[1;31m"
	}

	logMsg := strings.ReplaceAll(l.format, "%time%", timestamp)
	logMsg = strings.ReplaceAll(logMsg, "%level%", levelStr)
	logMsg = strings.ReplaceAll(logMsg, "%msg%", message)

	if l.logOutput == OutputConsole || l.logOutput == OutputBoth {
		return fmt.Sprintf("%s%s\033[0m\n", colorCode, logMsg)
	}

	return logMsg + "\n"
}

// log 内部日志记录方法
func (l *HostsPPLogger) log(level int, message string) {
	if level < l.logLevel {
		return
	}

	logMsg := l.formatLog(level, message)
	l.asyncQueue <- logMsg
}

// Debug 记录调试级别的日志
func (l *HostsPPLogger) Debug(message string) {
	l.log(DEBUG, message)
}

// Debugf 记录格式化的调试级别日志
func (l *HostsPPLogger) Debugf(format string, args ...interface{}) {
	l.log(DEBUG, fmt.Sprintf(format, args...))
}

// Info 记录信息级别的日志
func (l *HostsPPLogger) Info(message string) {
	l.log(INFO, message)
}

// Infof 记录格式化的信息级别日志
func (l *HostsPPLogger) Infof(format string, args ...interface{}) {
	l.log(INFO, fmt.Sprintf(format, args...))
}

// Warning 记录警告级别的日志
func (l *HostsPPLogger) Warning(message string) {
	l.log(WARNING, message)
}

// Warningf 记录格式化的警告级别日志
func (l *HostsPPLogger) Warningf(format string, args ...interface{}) {
	l.log(WARNING, fmt.Sprintf(format, args...))
}

// Error 记录错误级别的日志
func (l *HostsPPLogger) Error(message string) {
	l.log(ERROR, message)
}

// Errorf 记录格式化的错误级别日志
func (l *HostsPPLogger) Errorf(format string, args ...interface{}) {
	l.log(ERROR, fmt.Sprintf(format, args...))
}

// SetLevel 设置日志级别
func (l *HostsPPLogger) SetLevel(level int) {
	l.logLevel = level
}

// SetFormat 设置日志格式
func (l *HostsPPLogger) SetFormat(format string) {
	l.format = format
}

// 辅助函数

// getLevelString 将日志级别转换为字符串
func getLevelString(level int) string {
	switch level {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// GetLevelInt 获取字符串对应的日志等级整数值
func GetLevelInt(levelString string) int {
	switch strings.ToUpper(levelString) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARNING":
		return WARNING
	case "ERROR":
		return ERROR
	default:
		return -1
	}
}

// CloseLogger 关闭日志文件并清理资源
func CloseLogger() error {
	if defaultLogger != nil && defaultLogger.logFile != nil {
		close(defaultLogger.asyncQueue)
		defaultLogger.bufWriter.Flush()
		return defaultLogger.logFile.Close()
	}
	return nil
}

// 全局函数，用于方便调用

// Debug 全局调试日志函数
func Debug(message string) {
	defaultLogger.Debug(message)
}

// Debugf 全局格式化调试日志函数
func Debugf(format string, args ...interface{}) {
	defaultLogger.Debugf(format, args...)
}

// Info 全局信息日志函数
func Info(message string) {
	defaultLogger.Info(message)
}

// Infof 全局格式化信息日志函数
func Infof(format string, args ...interface{}) {
	defaultLogger.Infof(format, args...)
}

// Warning 全局警告日志函数
func Warning(message string) {
	defaultLogger.Warning(message)
}

// Warningf 全局格式化警告日志函数
func Warningf(format string, args ...interface{}) {
	defaultLogger.Warningf(format, args...)
}

// Error 全局错误日志函数
func Error(message string) {
	defaultLogger.Error(message)
}

// Errorf 全局格式化错误日志函数
func Errorf(format string, args ...interface{}) {
	defaultLogger.Errorf(format, args...)
}

// SetLevel 全局设置日志级别函数
func SetLevel(level int) {
	defaultLogger.SetLevel(level)
}

// SetFormat 全局设置日志格式函数
func SetFormat(format string) {
	defaultLogger.SetFormat(format)
}

func SafeErrorf(format string, args ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Errorf(format, args...)
	} else {
		fmt.Printf("\033[1;31mERROR\033[0m "+format+"\n", args...)
	}
}
