package logger

import (
	"log"
	"os"
	"sync"
)

type Logger struct {
	infoLogger  *log.Logger
	errorLogger *log.Logger
	mu          sync.Mutex
}

var (
	instance *Logger
	once     sync.Once
)

func GetInstance() *Logger {
	once.Do(func() {
		instance = &Logger{
			infoLogger:  log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile),
			errorLogger: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile),
		}
	})
	return instance
}

func (l *Logger) Info(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infoLogger.Printf(format, v...)
}

func (l *Logger) Error(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errorLogger.Printf(format, v...)
}
