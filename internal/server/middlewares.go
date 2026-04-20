package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/golang-jwt/jwt/v5"
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

// Middleware que confere se o usuário possui um token no header "Bearer"
// Confere se o token é válido
func (s *AppServer) TokenBearerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//Header de autorização no formato "Bearer <token>"
		authHeader := r.Header.Get("Authorization")

		//Verifica se o token está presente no header
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		//Confere se está no formato correto ("Bearer <token>")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		// Extrai apenas a string do token
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		//Delega a validação criptográfica e de federação ao serviço
		claims := &types.MatrixClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
			// Checagem de segurança se o token não teve o algoritmo substituido
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return types.JWTSecretKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), types.UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, types.DeviceIDKey, claims.DeviceID)
		// Cria um novo request com o contexto atualizado
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// WriteHeader é uma implementação personalizada de WriteHeader que armazena o statusCode
func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
