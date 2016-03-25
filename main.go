package main

import (
	"crypto/tls"
	"flag"

	"github.com/Sirupsen/logrus"

	"github.com/kelproject/router/datasources"
	"github.com/kelproject/router/server"
	"golang.org/x/net/context"
)

var (
	flagDataStore = flag.String("data-store", "kubernetes", "data store")
	flagTLSCert   = flag.String("tls-cert", "", "TLS fallback certificate")
	flagTLSKey    = flag.String("tls-key", "", "TLS fallback key")
	flagLogLevel  = flag.String("log-level", "warn", "log level")
	logger        = logrus.New()
)

func main() {
	flag.Parse()
	logLevel, err := logrus.ParseLevel(*flagLogLevel)
	if err != nil {
		logger.Fatalln(err)
	}
	logger.Level = logLevel
	var tlsConfig *tls.Config
	if *flagTLSCert != "" && *flagTLSKey != "" {
		cert, err := tls.LoadX509KeyPair(*flagTLSCert, *flagTLSKey)
		if err != nil {
			logger.Fatal(err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	s := server.NewServer(&server.Server{
		Logger:           logger,
		DefaultTLSConfig: tlsConfig,
	})
	if err := s.Listen(); err != nil {
		logger.Fatal(err)
	}
	ctx := context.Background()
	ctx, stopSync := context.WithCancel(ctx)
	switch *flagDataStore {
	case "file":
		startFileDataStore(ctx, logger, s)
		break
	case "kubernetes":
		startKubernetesDataStore(ctx, logger, s)
		break
	default:
		logger.Fatalf("unknown data store %q", *flagDataStore)
	}
	if err := s.Serve(); err != nil {
		stopSync()
		logger.Fatal(err)
	}
}

func startFileDataStore(ctx context.Context, logger *logrus.Logger, sh datasources.SyncHandler) {
	ds, err := datasources.NewFileDataStore()
	if err != nil {
		logger.Fatal(err)
	}
	logger.Println("Starting file watcher")
	go ds.Watch(ctx, sh)
}

func startKubernetesDataStore(ctx context.Context, logger *logrus.Logger, sh datasources.SyncHandler) {
	ds, err := datasources.NewKubernetesDataStore()
	if err != nil {
		logger.Fatal(err)
	}
	logger.Println("Starting kubernetes watcher")
	go ds.Watch(ctx, sh)
}
