package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rojo/hack/web_bounty_flow/pkg/app"
	"github.com/rojo/hack/web_bounty_flow/pkg/config"
)

func main() {
	cfgPath := flag.String("config", "flow.yaml", "path to the YAML configuration file")
	org := flag.String("org", "", "single organization or domain to seed")
	orgList := flag.String("org-list", "", "alternate list of organizations/domains to load")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	logger := log.New(os.Stdout, "[bflow] ", log.LstdFlags)
	a := app.New(cfg, logger, nil, nil)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		logger.Println("shutdown signal received; waiting for operations to finish")
		time.Sleep(100 * time.Millisecond)
	}()

	if err := a.Run(ctx, app.Options{Organization: *org, OrgList: *orgList}); err != nil {
		logger.Fatalf("flow run failed: %v", err)
	}

	fmt.Println("flow run completed successfully")
}
