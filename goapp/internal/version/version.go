package version

// Version is injected at build time via -ldflags.
// Example: -X vpshelper-go/internal/version.Version=v1.2.3
var Version = "dev"
