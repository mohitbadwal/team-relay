package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/server"
	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/config"
	"github.com/mohitbadwal/team-relay/internal/mcpserver"
)

const recipientRunMarker = "AGENT_RELAY_RECIPIENT_RUN"

func main() {
	// Check before parsing a config path or loading a device token. Recipient
	// runtimes may inherit ordinary local MCPs, but they must never recursively
	// use the credential-bearing Team Relay MCP under any configured alias.
	if recipientRunBlocked(os.Getenv(recipientRunMarker)) {
		fatalf("Team Relay MCP is disabled inside an approved teammate runtime")
	}
	configPath := flag.String("config", "", "path to Team Relay config.yaml")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatalf("configuration error: %v", err)
	}
	token, err := cfg.DeviceToken()
	if err != nil {
		fatalf("credential error: %v", err)
	}
	relay, err := client.New(cfg.Relay.URL, token, nil)
	if err != nil {
		fatalf("relay client error: %v", err)
	}
	mcpServer, err := mcpserver.New(relay, mcpserver.Options{Attachments: mcpserver.AttachmentOptions{
		OutboundEnabled: cfg.OutboundAttachments,
		Workspaces:      cfg.Workspaces,
	}})
	if err != nil {
		fatalf("MCP server error: %v", err)
	}

	// Stdout is reserved exclusively for MCP JSON-RPC framing.
	if err := server.ServeStdio(mcpServer); err != nil {
		fatalf("MCP stdio error: %v", err)
	}
}

func recipientRunBlocked(value string) bool { return value == "1" }

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
