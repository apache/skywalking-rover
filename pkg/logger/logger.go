package logger

import (
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	root = initializeDefaultLogger()
	once sync.Once
)

type Config struct {
	Level string
}

type Logger struct {
	*logrus.Entry
	module []string
}

func SetupLogger(config *Config) (err error) {
	once.Do(func() {
		err = updateLogger(root, config)
	})
	if err != nil {
		return err
	}
	return nil
}

// GetLogger from the sub-module name
func GetLogger(modules ...string) *Logger {
	moduleString := ""
	if len(modules) > 0 {
		moduleString = strings.Join(modules, ".")
	}
	return &Logger{Entry: root.WithField("module", moduleString), module: modules}
}
