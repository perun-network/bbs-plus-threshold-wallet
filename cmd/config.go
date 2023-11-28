package cmd

import (
	"os"

	"perun.network/go-perun/log"
	plogrus "perun.network/go-perun/log/logrus"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
)

type logCfg struct {
	Level string
	level logrus.Level
	File  string
}

var logConfig logCfg

func setConfig() {
	lvl, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		log.Fatal(errors.WithMessage(err, "parsing log level"))
	}
	logConfig.level = lvl

	// Set the logging output file
	logger := logrus.New()
	if logConfig.File != "" {
		f, err := os.OpenFile(logConfig.File,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(errors.WithMessage(err, "opening logging file"))
		}
		logger.SetOutput(f)
	}
	logger.SetLevel(lvl)
	log.Set(plogrus.FromLogrus(logger))
}
