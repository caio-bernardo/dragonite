package server

import (
	"log"
	"net/http"
	"time"
)

// reponseWriter é uma estrutura auxiliar pra incluir o statusCode na resposta
type responseWriter struct {
	statusCode int
	http.ResponseWriter
}

// Middleware que gerencia o cabeçalho de CORS
func (s *AppServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*") // Replace "*" with specific origins if needed
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "false") // Set to "true" if credentials are required

		// Handle preflight OPTIONS requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Proceed with the next handler
		next.ServeHTTP(w, r)
	})
}

// Middleware para logar o resultado das requisições
func (s *AppServer) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()

		res := responseWriter{statusCode: http.StatusOK, ResponseWriter: w}

		next.ServeHTTP(&res, r)

		log.Printf("[%s] %s %d %s in %s", r.Method, r.URL.Path, res.statusCode, http.StatusText(res.statusCode), time.Since(now))
	})
}

// WriteHeader é uma implementação personalizada de WriteHeader que armazena o statusCode
func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
