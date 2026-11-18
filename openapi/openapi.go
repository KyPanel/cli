// Package openapi embeds the KyPanel API description (also served at /api/v1/openapi.json).
package openapi

import _ "embed"

//go:embed openapi.json
var JSON []byte
