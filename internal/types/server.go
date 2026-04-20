package types

import "net/http"

// Middleware is a function type that wraps an http.Handler
type Middleware func(http.Handler) http.Handler
