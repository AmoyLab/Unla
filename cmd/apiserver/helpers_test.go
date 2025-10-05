package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	adb "github.com/amoylab/unla/internal/apiserver/database"
	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/mcp/storage/notifier"
	"go.uber.org/zap"
)

func TestInitLogger(t *testing.T) {
	cfg := &config.APIServerConfig{}
	lg := initLogger(cfg)
	if lg == nil {
		t.Fatalf("expected logger, got nil")
	}
	_ = lg.Sync()
}

func TestInitDatabase_SQLite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "apiserver.db")
	lg := zap.NewNop()
	db := initDatabase(lg, &config.DatabaseConfig{Type: "sqlite", DBName: dbPath})
	t.Cleanup(func() { _ = db.Close() })
}

func TestInitNotifier_SignalReceiver(t *testing.T) {
	// prepare dummy pid file path
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "apiserver.pid")
	// create empty file path directory only, send won't be called in this test
	cfg := &config.NotifierConfig{Type: string(notifier.TypeSignal), Role: string(config.RoleReceiver), Signal: config.SignalConfig{PID: pidPath}}
	n := initNotifier(context.Background(), zap.NewNop(), cfg)
	if n == nil {
		t.Fatalf("expected notifier, got nil")
	}
}

func TestInitStore_DB_SQLite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "store.db")
	lg := zap.NewNop()
	st := initStore(lg, &config.StorageConfig{Type: "db", Database: config.DatabaseConfig{Type: "sqlite", DBName: dbPath}})
	if st == nil {
		t.Fatalf("expected store, got nil")
	}
}

func TestInitI18n(t *testing.T) {
	// use default configs/i18n path
	initI18n(&config.I18nConfig{Path: "configs/i18n"})
}

func TestInitRouter_Constructs(t *testing.T) {
	// setup minimal dependencies
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lg := zap.NewNop()
	// sqlite database for apiserver database
	dir := t.TempDir()
	apiDB := filepath.Join(dir, "api.db")
	db, err := adb.NewSQLite(&config.DatabaseConfig{Type: "sqlite", DBName: apiDB})
	if err != nil {
		t.Fatalf("init sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// store backed by sqlite as well
	storeDB := filepath.Join(dir, "store.db")
	st := initStore(lg, &config.StorageConfig{Type: "db", Database: config.DatabaseConfig{Type: "sqlite", DBName: storeDB}})

	// signal notifier in receiver role
	pidPath := filepath.Join(dir, "apiserver.pid")
	ntf := initNotifier(ctx, lg, &config.NotifierConfig{Type: string(notifier.TypeSignal), Role: string(config.RoleReceiver), Signal: config.SignalConfig{PID: pidPath}})

	// minimal config
	cfg := &config.APIServerConfig{
		SuperAdmin: config.SuperAdminConfig{Username: "admin", Password: "admin"},
		Logger:     config.LoggerConfig{},
		Storage:    config.StorageConfig{Type: "db", Database: config.DatabaseConfig{Type: "sqlite", DBName: storeDB}},
		Notifier:   config.NotifierConfig{Type: string(notifier.TypeSignal), Role: string(config.RoleReceiver), Signal: config.SignalConfig{PID: pidPath}},
		JWT:        config.JWTConfig{SecretKey: "this-is-a-very-long-secret-key-for-testing-purposes-only", Duration: 3600000000000},
		Auth:       config.AuthConfig{},
	}

	r := initRouter(ctx, db, st, ntf, cfg, lg)
	if r == nil {
		t.Fatalf("expected router, got nil")
	}

	// do not start server; just ensure routes are registered
	// quick sanity: check that static web directory path exists (not required)
	if _, err := os.Stat("./web"); err != nil && !os.IsNotExist(err) {
		t.Fatalf("unexpected web dir stat error: %v", err)
	}
}
