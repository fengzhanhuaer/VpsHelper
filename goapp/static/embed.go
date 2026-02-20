package static

import "embed"

// FS contains embedded static assets (CSS, JS, images, etc.).
//
//go:embed *
var FS embed.FS
