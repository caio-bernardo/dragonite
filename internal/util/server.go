package util

import (
	"net/http"
	"time"
)

const (
	RequestTimeout time.Duration = 2 * time.Second
)

// UnimplementedHandler representa um handler não implementado ainda.
func UnimplementedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Implemented", http.StatusNotImplemented)
}
