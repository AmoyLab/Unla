package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amoylab/unla/internal/auth"
	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/core"
	"github.com/amoylab/unla/internal/mcp/session"
	"github.com/amoylab/unla/internal/mcp/storage"
	"github.com/amoylab/unla/internal/mcp/storage/notifier"
	pidHelper "github.com/amoylab/unla/pkg/helper"
	"github.com/amoylab/unla/pkg/logger"
	"github.com/amoylab/unla/pkg/trace"
	"github.com/amoylab/unla/pkg/utils"
	"github.com/amoylab/unla/pkg/version"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	configPath string
	pidFile    string

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of mcp-gateway",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("mcp-gateway version %s\n", version.Get())
		},
	}
	reloadCmd = &cobra.Command{
		Use:   "reload",
		Short: "Reload the configuration of a running mcp-gateway instance",
		Run: func(cmd *cobra.Command, args []string) {
			// Load config to get PID path if not provided via command line
			cfg, _, err := config.LoadConfig[config.MCPGatewayConfig](configPath)
			if err != nil {
				fmt.Printf("Failed to load config: %v\n", err)
				os.Exit(1)
			}

			// Use PID from config if not provided via command line
			if pidFile == "" {
				pidFile = cfg.PID
			}

			if err := utils.SendSignalToPIDFile(pidHelper.GetPIDPath(pidFile), syscall.SIGHUP); err != nil {
				fmt.Printf("Failed to send reload signal: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Reload signal sent successfully")
		},
	}
	testCmd = &cobra.Command{
		Use:   "test",
		Short: "Test the configuration of mcp-gateway",
		Run: func(cmd *cobra.Command, args []string) {
			// Load config
			cfg, _, err := config.LoadConfig[config.MCPGatewayConfig](configPath)
			if err != nil {
				fmt.Printf("Failed to load config: %v\n", err)
				os.Exit(1)
			}

			// Initialize logger
			logger, err := logger.NewLogger(&cfg.Logger)
			if err != nil {
				fmt.Printf("Failed to initialize logger: %v\n", err)
				os.Exit(1)
			}
			defer logger.Sync()

			// Initialize storage
			store, err := storage.NewStore(logger, &cfg.Storage)
			if err != nil {
				fmt.Printf("Failed to initialize storage: %v\n", err)
				os.Exit(1)
			}

			// Load all MCP configurations
			cfgs, err := store.List(context.Background())
			if err != nil {
				fmt.Printf("Failed to load MCP configurations: %v\n", err)
				os.Exit(1)
			}

			// Validate configurations
			if err := config.ValidateMCPConfigs(cfgs); err != nil {
				var validationErr *config.ValidationError
				if errors.As(err, &validationErr) {
					fmt.Printf("Configuration validation failed: %v\n", validationErr)
				} else {
					fmt.Printf("Failed to validate configurations: %v\n", err)
				}
				os.Exit(1)
			}

			fmt.Println("Configuration test is successful")
		},
	}
	rootCmd = &cobra.Command{
		Use:   cnst.CommandName,
		Short: "MCP Gateway service",
		Long:  `MCP Gateway is a service that provides API gateway functionality for MCP ecosystem`,
		Run: func(cmd *cobra.Command, args []string) {
			run()
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "conf", "c", cnst.MCPGatewayYaml, "path to configuration file, like /etc/unla/mcp-gateway.yaml")
	rootCmd.PersistentFlags().StringVar(&pidFile, "pid", "", "path to PID file")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(reloadCmd)
	rootCmd.AddCommand(testCmd)
}

func run() {
	ctx, cancel := context.WithCancel(context.Background())

	// Load configuration first
	cfg, cfgPath, err := config.LoadConfig[config.MCPGatewayConfig](configPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load service configuration: %v", err))
	}

	// Initialize logger with configuration
	logger, err := logger.NewLogger(&cfg.Logger)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
	defer logger.Sync()

	logger.Info("Loaded configuration", zap.String("path", cfgPath))

	// Initialize PID manager
	if pidFile == "" {
		pidFile = cfg.PID
	}

	pidManager := utils.NewPIDManagerFromConfig(pidFile)
	err = pidManager.WritePID()
	if err != nil {
		logger.Fatal("Failed to write PID file",
			zap.String("path", pidManager.GetPIDFile()),
			zap.Error(err))
	}
	defer pidManager.RemovePID()

	logger.Info("Starting mcp-gateway", zap.String("version", version.Get()))

	// Initialize storage and load initial configuration
	store, err := storage.NewStore(logger, &cfg.Storage)
	if err != nil {
		logger.Fatal("failed to initialize storage",
			zap.String("type", cfg.Storage.Type),
			zap.Error(err))
	}

	// Initialize session store
	sessionStore, err := session.NewStore(logger, &cfg.Session)
	if err != nil {
		logger.Fatal("failed to initialize session store",
			zap.String("type", cfg.Session.Type),
			zap.Error(err))
	}

	// Initialize auth service
	a, err := auth.NewAuth(logger, cfg.Auth)
	if err != nil {
		logger.Fatal("Failed to initialize auth service", zap.Error(err))
	}

	// Create server instance
    server, err := core.NewServer(
        logger,
        cfg.Port,
        store,
        sessionStore,
        a,
        core.WithForwardConfig(cfg.Forward),
        core.WithTraceCapture(cfg.Tracing.Capture),
    )
	if err != nil {
		logger.Fatal("Failed to create server", zap.Error(err))
	}

	// Enable gin tracing middleware if tracing is configured
	if cfg.Tracing.Enabled {
		if cfg.Tracing.ServiceName == "" {
			cfg.Tracing.ServiceName = "mcp-gateway"
		}
		shutdown, err := trace.InitTracing(ctx, &cfg.Tracing, logger)
		if err != nil {
			logger.Error("Failed to initialize tracing", zap.Error(err))
		} else {
			// Ensure tracer provider shutdown on exit
			defer func() {
				// try to flush spans with timeout
				ctxTo, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := shutdown(ctxTo); err != nil {
					logger.Warn("Tracing shutdown error", zap.Error(err))
				}
			}()
			logger.Info("Tracing enabled",
				zap.String("endpoint", cfg.Tracing.Endpoint),
				zap.String("protocol", cfg.Tracing.Protocol),
			)

		}

		server.EnableTracing(cfg.Tracing.ServiceName)
	}

	err = server.RegisterRoutes(ctx)
	if err != nil {
		logger.Fatal("failed to register routes",
			zap.Error(err))
	}

	ntf, err := notifier.NewNotifier(ctx, logger, &cfg.Notifier)
	if err != nil {
		logger.Fatal("failed to initialize notifier",
			zap.Error(err))
	}
	updateCh, err := ntf.Watch(ctx)
	if err != nil {
		logger.Fatal("failed to start watching for updates",
			zap.Error(err))
	}

	server.Start()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// periodically reload the configuration as a fallback mechanism for the notifier
	ticker := time.NewTicker(cfg.ReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-quit:
			logger.Info("Received shutdown signal, starting graceful shutdown")

			// First cancel the main context to stop accepting new requests
			cancel()

			// Shutdown the MCP server to close all SSE connections
			err = server.Shutdown(ctx)
			if err != nil {
				logger.Error("failed to shutdown MCP server",
					zap.Error(err))
			} else {
				logger.Info("MCP server shutdown completed successfully")
			}

			return
		case updateMCPConfig := <-updateCh:
			logger.Info("Received update signal")

			if updateMCPConfig == nil {
				logger.Warn("Updated configuration is nil, falling back to full reload")
				server.ReloadConfigs(ctx)
			} else {
				server.UpdateConfig(ctx, updateMCPConfig)
			}
		case <-ticker.C:
			logger.Info("Received ticker signal", zap.Bool("reload_switch", cfg.ReloadSwitch))
			if cfg.ReloadSwitch {
				server.ReloadConfigs(ctx)
			}
		}

	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
