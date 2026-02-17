package templates

import "embed"

// FS contains embedded HTML templates.
//
//go:embed *.html
var FS embed.FS
