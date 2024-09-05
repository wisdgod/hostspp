package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sync"
)

type LogLevel int

const (
	LevelOff LogLevel = iota
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
)

var levelColors = map[LogLevel]string{
	LevelError: "\033[1;31m", // 红色
	LevelWarn:  "\033[1;33m", // 黄色
	LevelInfo:  "\033[1;32m", // 绿色
	LevelDebug: "\033[1;34m", // 蓝色
}

var levelPrefixes = map[LogLevel]string{
	LevelError: "ERROR",
	LevelWarn:  "WARN",
	LevelInfo:  "INFO",
	LevelDebug: "DEBUG",
}

type Logger struct {
	level  LogLevel
	logger *log.Logger
	mu     sync.Mutex
	color  bool
}

var (
	instance *Logger
	once     sync.Once
)

func GetInstance() *Logger {
	once.Do(func() {
		instance = &Logger{
			level:  LevelInfo,
			logger: log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds),
			color:  true,
		}
	})
	return instance
}

func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logger.SetOutput(w)
}

func (l *Logger) SetColor(enable bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.color = enable
}

func (l *Logger) log(level LogLevel, format string, v ...interface{}) {
	if level > l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// 获取调用者的文件名和行号
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "???"
		line = 0
	}

	// 构建日志前缀
	prefix := fmt.Sprintf("%s:%d", file, line)

	// 构建日志消息
	msg := fmt.Sprintf(format, v...)

	// 添加颜色（如果启用）
	levelString := levelPrefixes[level]
	if l.color {
		levelString = fmt.Sprintf("%s%s\033[0m", levelColors[level], levelString)
	}

	// 输出日志
	l.logger.Printf("%s [%s] %s", prefix, levelString, msg)
}

func (l *Logger) Debug(format string, v ...interface{}) {
	l.log(LevelDebug, format, v...)
}

func (l *Logger) Info(format string, v ...interface{}) {
	l.log(LevelInfo, format, v...)
}

func (l *Logger) Warn(format string, v ...interface{}) {
	l.log(LevelWarn, format, v...)
}

func (l *Logger) Error(format string, v ...interface{}) {
	l.log(LevelError, format, v...)
}
