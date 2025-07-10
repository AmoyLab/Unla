package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/amoylab/unla/internal/apiserver/database"
	apiserverHandler "github.com/amoylab/unla/internal/apiserver/handler"
	"github.com/amoylab/unla/internal/apiserver/middleware"
	"github.com/amoylab/unla/internal/auth/jwt"
	"github.com/amoylab/unla/internal/common/cnst"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/i18n"
	"github.com/amoylab/unla/internal/mcp/storage"
	"github.com/amoylab/unla/internal/mcp/storage/notifier"
	"github.com/amoylab/unla/pkg/logger"
	"github.com/amoylab/unla/pkg/version"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

var (
	configPath string

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of apiserver",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("apiserver version %s\n", version.Get())
		},
	}

	rootCmd = &cobra.Command{
		Use:   "apiserver",
		Short: "MCP API Server",
		Long:  `MCP API Server provides API endpoints for MCP ecosystem`,
		Run: func(cmd *cobra.Command, args []string) {
			run()
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "conf", "c", cnst.ApiServerYaml, "path to configuration file, like /etc/unla/apiserver.yaml")
	rootCmd.AddCommand(versionCmd)
}

// initLogger initializes the application logger
func initLogger(cfg *config.APIServerConfig) *zap.Logger {
	logger, err := logger.NewLogger(&cfg.Logger)
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	return logger
}

// initConfig loads and returns the application configuration
func initConfig() *config.APIServerConfig {
	cfg, _, err := config.LoadConfig[config.APIServerConfig](configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	return cfg
}

// initNotifier initializes the notifier service
func initNotifier(ctx context.Context, logger *zap.Logger, cfg *config.NotifierConfig) notifier.Notifier {
	if notifier.Type(cfg.Type) == notifier.TypeComposite {
		log.Fatal("Composite notifier is not supported in apiserver")
	}
	ntf, err := notifier.NewNotifier(ctx, logger, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize notifier", zap.Error(err))
	}
	return ntf
}

// initDatabase initializes the database connection
func initDatabase(logger *zap.Logger, cfg *config.DatabaseConfig) database.Database {
	logger.Info("Initializing database", zap.String("type", cfg.Type))
	db, err := database.NewDatabase(cfg)
	if err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	logger.Info("Database initialized", zap.String("type", cfg.Type))
	return db
}

// initStore initializes the storage service
func initStore(logger *zap.Logger, cfg *config.StorageConfig) storage.Store {
	store, err := storage.NewStore(logger, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize store", zap.Error(err))
	}
	return store
}

// initSuperAdmin initializes the super admin user if it doesn't exist
func initSuperAdmin(ctx context.Context, db database.Database, cfg *config.APIServerConfig) error {
	// Check if super admin user exists
	user, err := db.GetUserByUsername(ctx, cfg.SuperAdmin.Username)
	if err == nil && user != nil {
		return nil // Super admin already exists
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.SuperAdmin.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the super admin user
	superAdmin := &database.User{
		Username:  cfg.SuperAdmin.Username,
		Password:  string(hashedPassword),
		Role:      database.RoleAdmin,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := db.CreateUser(ctx, superAdmin); err != nil {
		return fmt.Errorf("failed to create super admin: %w", err)
	}

	return nil
}

// initRouter initializes the HTTP router and handlers
func initRouter(db database.Database, store storage.Store, ntf notifier.Notifier, cfg *config.APIServerConfig, logger *zap.Logger) *gin.Engine {
	r := gin.Default()

	// Convert APIServerConfig to MCPGatewayConfig
	mcpCfg := &config.MCPGatewayConfig{
		SuperAdmin: cfg.SuperAdmin,
		Logger:     cfg.Logger,
		Storage:    cfg.Storage,
		Notifier:   cfg.Notifier,
	}

	// Initialize auth services
	jwtService := jwt.NewService(jwt.Config{
		SecretKey: cfg.JWT.SecretKey,
		Duration:  cfg.JWT.Duration,
	})
	authH := apiserverHandler.NewHandler(db, jwtService, mcpCfg, logger)

	authG := r.Group("/api/auth")
	authG.POST("/login", authH.Login)

	// Protected routes
	protected := r.Group("/api")
	protected.Use(middleware.JWTAuthMiddleware(jwtService))
	{
		chatHandler := apiserverHandler.NewChat(db, logger)
		mcpHandler := apiserverHandler.NewMCP(db, store, ntf, logger)
		openapiHandler := apiserverHandler.NewOpenAPI(db, store, ntf, logger)
		systemPromptHandler := apiserverHandler.NewSystemPrompt(db, logger)

		// Auth routes
		protected.POST("/auth/change-password", authH.ChangePassword)
		protected.GET("/auth/user/info", authH.GetUserInfo)
		protected.GET("/auth/user", authH.GetUserWithTenants)
		protected.GET("/auth/tenants", authH.ListTenants)

		// User management routes (admin only)
		userMgmt := protected.Group("/auth/users")
		userMgmt.Use(apiserverHandler.AdminAuthMiddleware())
		{
			userMgmt.GET("", authH.ListUsers)
			userMgmt.POST("", authH.CreateUser)
			userMgmt.PUT("", authH.UpdateUser)
			userMgmt.DELETE("/:username", authH.DeleteUser)
			userMgmt.GET("/:username", authH.GetUserWithTenants)
			userMgmt.PUT("/tenants", authH.UpdateUserTenants)
		}

		// Tenant management routes (admin only)
		tenantMgmt := protected.Group("/auth/tenants")
		{
			tenantMgmt.POST("", authH.CreateTenant)
			tenantMgmt.GET("/:name", authH.GetTenantInfo)
		}
		tenantMgmt.Use(apiserverHandler.AdminAuthMiddleware())
		{
			tenantMgmt.PUT("", authH.UpdateTenant)
			tenantMgmt.DELETE("/:name", authH.DeleteTenant)
		}

		// MCP config routes
		mcpGroup := protected.Group("/mcp")
		{
			mcpGroup.GET("/configs/names", mcpHandler.HandleGetConfigNames)
			mcpGroup.GET("/configs/versions", mcpHandler.HandleGetConfigVersions)
			mcpGroup.POST("/configs/:tenant/:name/versions/:version/active", mcpHandler.HandleSetActiveVersion)

			mcpGroup.GET("/configs", mcpHandler.HandleListMCPServers)
			mcpGroup.POST("/configs", mcpHandler.HandleMCPServerCreate)
			mcpGroup.PUT("/configs", mcpHandler.HandleMCPServerUpdate)
			mcpGroup.DELETE("/configs/:tenant/:name", mcpHandler.HandleMCPServerDelete)
			mcpGroup.POST("/configs/sync", mcpHandler.HandleMCPServerSync)
		}

		// OpenAPI routes
		protected.POST("/openapi/import", openapiHandler.HandleImport)

		protected.GET("/chat/sessions", chatHandler.HandleGetChatSessions)
		protected.GET("/chat/sessions/:sessionId/messages", chatHandler.HandleGetChatMessages)
		protected.DELETE("/chat/sessions/:sessionId", chatHandler.HandleDeleteChatSession)
		protected.PUT("/chat/sessions/:sessionId/title", chatHandler.HandleUpdateChatSessionTitle)
		protected.POST("/chat/messages", chatHandler.HandleSaveChatMessage)

		// System prompt routes
		protected.GET("/chat/systemprompt", systemPromptHandler.GetSystemPrompt)
		protected.PUT("/chat/systemprompt", systemPromptHandler.SaveSystemPrompt)

		// Default LLM provider endpoint
		protected.GET("/defaultllmprovider", chatHandler.HandleDefaultLLMProviders)
	}

	// Public runtime config endpoint for frontend
	r.GET("/api/runtime-config", apiserverHandler.HandleRuntimeConfig)

	r.Static("/web", "./web")
	return r
}

// startServer starts the HTTP server
func startServer(logger *zap.Logger, router *gin.Engine) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5234"
	}

	logger.Info("Server starting", zap.String("port", port))
	if err := router.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}

// initI18n initializes the i18n translator
func initI18n(cfg *config.I18nConfig) {
	translationsPath := cfg.Path
	if translationsPath == "" {
		translationsPath = "configs/i18n"
	}

	if err := i18n.InitTranslator(translationsPath); err != nil {
		log.Printf("Warning: Failed to load translations: %v\n", err)
	}
}

func run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration first
	cfg := initConfig()

	// Initialize logger with configuration
	logger := initLogger(cfg)
	defer logger.Sync()

	logger.Info("Starting apiserver", zap.String("version", version.Get()))

	// Initialize services
	ntf := initNotifier(ctx, logger, &cfg.Notifier)
	db := initDatabase(logger, &cfg.Database)
	defer db.Close()

	// Initialize i18n translator
	initI18n(&cfg.I18n)

	// Initialize super admin
	if err := initSuperAdmin(ctx, db, cfg); err != nil {
		logger.Fatal("Failed to initialize super admin", zap.Error(err))
	}

	store := initStore(logger, &cfg.Storage)

	// Initialize router and start server
	router := initRouter(db, store, ntf, cfg, logger)
	startServer(logger, router)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
