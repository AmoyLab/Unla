package main

import (
	"os"
	"testing"
	"time"
)

// TestMain_CommandExecution tests the main function execution
func TestMain_CommandExecution(t *testing.T) {
	// Test successful command execution by setting help flag
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"mcp-gateway", "--help"}

	// Capture the main function execution
	// Since main() calls os.Exit, we'll test it indirectly by testing rootCmd.Execute()
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("main command execution failed: %v", err)
	}
}

// TestMain_InvalidCommand tests main function with invalid command
func TestMain_InvalidCommand(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Set invalid command
	os.Args = []string{"mcp-gateway", "invalid-command"}

	// rootCmd.Execute should return error for invalid command
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid command, got nil")
	}
}

// TestVersionCommand_OutputFormat tests version command output
func TestVersionCommand_OutputFormat(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs([]string{}) })
	rootCmd.SetArgs([]string{"version"})

	output := captureOutput(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Errorf("version command failed: %v", err)
		}
	})

	if output == "" {
		t.Error("version command should produce output")
	}

	// Check that output contains expected format
	if !containsAnyOf(output, []string{"version", "mcp-gateway"}) {
		t.Errorf("version output should contain version info, got: %s", output)
	}
}

// TestReloadCommand_ConfigValidation tests reload command flag parsing
func TestReloadCommand_ConfigValidation(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs([]string{}) })

	// Test with valid config path
	rootCmd.SetArgs([]string{"reload", "--conf", "/path/to/config.yaml", "--pid", "/path/to/pid"})

	// Parse flags without executing
	cmd := rootCmd
	for _, subCmd := range cmd.Commands() {
		if subCmd.Name() == "reload" {
			// Test that command accepts flags without error during parsing
			if err := subCmd.ParseFlags([]string{"--conf", "/path/to/config.yaml", "--pid", "/path/to/pid"}); err != nil {
				t.Errorf("reload command should accept config and pid flags: %v", err)
			}
			break
		}
	}
}

// TestTestCommand_FlagParsing tests test command flag parsing
func TestTestCommand_FlagParsing(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs([]string{}) })

	rootCmd.SetArgs([]string{"test", "--conf", "/path/to/test.yaml"})

	// Parse flags without executing
	cmd := rootCmd
	for _, subCmd := range cmd.Commands() {
		if subCmd.Name() == "test" {
			if err := subCmd.ParseFlags([]string{"--conf", "/path/to/test.yaml"}); err != nil {
				t.Errorf("test command should accept config flag: %v", err)
			}
			break
		}
	}
}

// TestInit_FlagValidation tests that init function properly sets up flags
func TestInit_FlagValidation(t *testing.T) {
	// Verify persistent flags are set correctly
	flags := rootCmd.PersistentFlags()

	confFlag := flags.Lookup("conf")
	if confFlag == nil {
		t.Fatal("conf flag should be initialized")
	}

	if confFlag.Shorthand != "c" {
		t.Errorf("conf flag shorthand should be 'c', got '%s'", confFlag.Shorthand)
	}

	pidFlag := flags.Lookup("pid")
	if pidFlag == nil {
		t.Fatal("pid flag should be initialized")
	}

	// Test default value for conf flag
	defaultValue := confFlag.DefValue
	if defaultValue == "" {
		t.Error("conf flag should have a default value")
	}
}

// TestCommandStructure_Complete tests all expected commands exist
func TestCommandStructure_Complete(t *testing.T) {
	commands := rootCmd.Commands()

	expectedCommands := map[string]bool{
		"version":    false,
		"reload":     false,
		"test":       false,
		"completion": false, // cobra adds this automatically
	}

	for _, cmd := range commands {
		if _, exists := expectedCommands[cmd.Name()]; exists {
			expectedCommands[cmd.Name()] = true
		}
	}

	// Check required commands are present
	requiredCommands := []string{"version", "reload", "test"}
	for _, required := range requiredCommands {
		if !expectedCommands[required] {
			t.Errorf("required command '%s' not found", required)
		}
	}
}

// Helper function to check if string contains any of the provided substrings
func containsAnyOf(s string, substrings []string) bool {
	for _, substr := range substrings {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}

// TestRootCommand_DefaultBehavior tests root command when run without subcommands
func TestRootCommand_DefaultBehavior(t *testing.T) {
	// Test that root command structure is correct
	if rootCmd.Use == "" {
		t.Error("root command should have Use field set")
	}

	if rootCmd.Short == "" {
		t.Error("root command should have Short description")
	}

	if rootCmd.Long == "" {
		t.Error("root command should have Long description")
	}

	if rootCmd.Run == nil {
		t.Error("root command should have Run function")
	}
}

// TestCommandTimeout tests that commands don't hang indefinitely
func TestCommandTimeout(t *testing.T) {
	timeout := time.Second * 5
	done := make(chan bool)

	go func() {
		// Test version command completes in reasonable time
		t.Cleanup(func() { rootCmd.SetArgs([]string{}) })
		rootCmd.SetArgs([]string{"version"})
		_ = rootCmd.Execute()
		done <- true
	}()

	select {
	case <-done:
		// Command completed successfully
	case <-time.After(timeout):
		t.Error("command took too long to complete")
	}
}
