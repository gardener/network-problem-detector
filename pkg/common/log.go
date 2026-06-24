/*
 * SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package common

import (
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogOptions configures logger construction. Bind it to a cobra command's
// flags with AddFlags, then call Build to get a logr.Logger.
type LogOptions struct {
	// Development selects human-readable console output instead of JSON.
	Development bool
	// Verbosity raises the log level: 0 = Info, 1+ = Debug (logr V(n)).
	Verbosity int
}

// SharedLogOptions is the process-wide options instance. main() binds it to
// the root command's persistent flags; subcommands read from it via Build.
var SharedLogOptions = &LogOptions{}

// AddFlags registers --log-dev and -v/--verbosity on the given flag set.
func (o *LogOptions) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&o.Development, "log-dev", o.Development,
		"human-readable console log output instead of JSON")
	fs.IntVarP(&o.Verbosity, "verbosity", "v", o.Verbosity,
		"log verbosity level (0=info, 1+=debug)")
}

// Build constructs the logr.Logger. Panics on misconfiguration —
// zap config errors here are programmer errors, not runtime conditions.
func (o *LogOptions) Build(cmd string) logr.Logger {
	var cfg zap.Config
	if o.Development {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg = zap.NewProductionConfig()
	}
	// logr V(n) maps to zap level -n; raise verbosity by lowering the floor.
	cfg.Level = zap.NewAtomicLevelAt(zapcore.Level(-o.Verbosity))

	zapLog, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	return zapr.NewLogger(zapLog).WithValues("cmd", cmd)
}

// SetInteractiveDefault flips Development to true on the shared options
// unless the user explicitly set --log-dev on the command line. Call from
// a cobra PersistentPreRun on commands meant for interactive use (collect,
// list, deploy) so they default to human-readable console output while
// still honoring an explicit --log-dev=false.
func SetInteractiveDefault(cmd *cobra.Command) {
	if !cmd.Flags().Changed("log-dev") {
		SharedLogOptions.Development = true
	}
}

// NewLogger builds a logger using the shared options (set by main from
// CLI flags). Pass a short identifier for the "cmd" field.
func NewLogger(cmd string) logr.Logger {
	return SharedLogOptions.Build(cmd)
}

// Sync flushes any buffered log entries. Best-effort: stderr-on-tty
// commonly returns EINVAL on Sync, which is harmless. Call from main()
// via defer.
func Sync(log logr.Logger) {
	if u, ok := log.GetSink().(zapr.Underlier); ok {
		_ = u.GetUnderlying().Sync()
	}
	_ = os.Stderr.Sync()
}
