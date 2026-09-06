package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/mohitbadwal/team-relay/internal/lifecycle"
)

type lifecycleOptions struct {
	action     string
	configPath string
	follow     bool
}

func lifecycleCommand(role string, arguments []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("find working directory: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find Team Relay executable: %w", err)
	}
	options, err := parseLifecycleOptions(role, arguments, defaultLifecycleConfig(cwd, executable), os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return lifecycle.Run(ctx, role, options.action, options.configPath, options.follow, os.Stdout, os.Stderr)
}

func parseLifecycleOptions(role string, arguments []string, defaultConfig string, out io.Writer) (lifecycleOptions, error) {
	var options lifecycleOptions
	flags := flag.NewFlagSet("team-relay "+role, flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&options.configPath, "config", defaultConfig, "service settings file (team-relay.conf; separate from receiver enrollment config.yaml)")
	flags.BoolVar(&options.follow, "follow", false, "follow log output; valid only with logs")
	flags.Usage = func() {
		_, _ = fmt.Fprintf(out, "Usage: team-relay %s start|stop|restart|status|logs [--config PATH] [--follow]\n\n", role)
		flags.PrintDefaults()
	}
	if len(arguments) == 0 {
		flags.Usage()
		return options, fmt.Errorf("%s requires start, stop, restart, status, or logs", role)
	}
	options.action = arguments[0]
	if options.action == "--help" || options.action == "-h" || options.action == "help" {
		flags.Usage()
		return options, flag.ErrHelp
	}
	switch options.action {
	case "start", "stop", "restart", "status", "logs":
	default:
		return options, fmt.Errorf("unknown %s action %q; use start, stop, restart, status, or logs", role, options.action)
	}
	if err := flags.Parse(arguments[1:]); err != nil {
		return options, err
	}
	if flags.NArg() != 0 {
		return options, fmt.Errorf("%s %s does not accept positional arguments", role, options.action)
	}
	if options.follow && options.action != "logs" {
		return options, errors.New("--follow is valid only with logs")
	}
	if strings.TrimSpace(options.configPath) == "" {
		return options, errors.New("--config cannot be empty")
	}
	var err error
	options.configPath, err = filepath.Abs(options.configPath)
	if err != nil {
		return options, fmt.Errorf("resolve service settings path: %w", err)
	}
	return options, nil
}

func defaultLifecycleConfig(cwd, executable string) string {
	// A local config takes priority. Native installs normally place binaries in
	// checkout/bin; checking beside and above the binary also works from elsewhere.
	candidates := []string{
		filepath.Join(cwd, "team-relay.conf"),
		filepath.Join(filepath.Dir(executable), "team-relay.conf"),
		filepath.Join(filepath.Dir(filepath.Dir(executable)), "team-relay.conf"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return candidates[0]
}
