package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/jpinsonn/mcp-shield/internal/handlers"
)

func main() {
	// Command line flags
	listenAddr := flag.String("listen", ":8080", "Address to listen on")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	// Setup logger
	loggerOpts := &slog.HandlerOptions{}
	switch *logLevel {
	case "debug":
		loggerOpts.Level = slog.LevelDebug
	case "warn":
		loggerOpts.Level = slog.LevelWarn
	case "error":
		loggerOpts.Level = slog.LevelError
	default:
		loggerOpts.Level = slog.LevelInfo
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, loggerOpts))
	slog.SetDefault(logger)

	logger.Info("Starting MCP Shield", "listen", *listenAddr)

	// Create HTTP mux
	mux := http.NewServeMux()

	// Initialize OAuth handlers
	// Note: TokenStore is created inside OAuthTokenHandler and shared with MCPProxyHandler
	oauthDiscoveryHandler := handlers.NewOAuthDiscoveryHandler(logger)
	oauthTokenHandler := handlers.NewOAuthTokenHandler(logger)
	oauthCallbackHandler := handlers.NewOAuthCallbackHandler(logger)
	mcpProxyHandler := handlers.NewMCPProxyHandler(logger, oauthTokenHandler.GetTokenStore())

	// Register OAuth endpoints
	mux.HandleFunc("/.well-known/oauth-authorization-server", oauthDiscoveryHandler.HandleAuthorizationServer)
	mux.HandleFunc("/oauth/register", oauthDiscoveryHandler.HandleClientRegistration)
	mux.HandleFunc("/oauth2/start", oauthDiscoveryHandler.HandleOAuthStart)
	mux.HandleFunc("/oauth/callback", oauthCallbackHandler.Handle)
	mux.HandleFunc("/oauth/token", oauthTokenHandler.Handle)

	// Register MCP proxy endpoint - this forwards requests to the prometheus-mcp-server container
	mux.HandleFunc("/mcp", mcpProxyHandler.Handle)
	mux.HandleFunc("/mcp/", mcpProxyHandler.Handle)

	// Handle root path - Agentic CLI may POST to root instead of /mcp
	// If it's a POST request, forward to MCP handler; otherwise return 404
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Forward POST requests to root to MCP handler
			mcpProxyHandler.Handle(w, r)
		} else {
			// For non-POST requests, return 404
			http.NotFound(w, r)
		}
	})

	// Health check endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Start server
	logger.Info("MCP Shield server listening", "address", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, mux); err != nil {
		logger.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
