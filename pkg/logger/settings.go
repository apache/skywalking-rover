package logger

import "github.com/sirupsen/logrus"

const (
	DefaultLoggerLevel = logrus.InfoLevel
)

func updateLogger(log *logrus.Logger, config *Config) error {
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		return err
	}
	log.SetLevel(level)
	return nil
}

func initializeDefaultLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(DefaultLoggerLevel)
	l.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	})
	return l
}
