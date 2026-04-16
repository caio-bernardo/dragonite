package auth

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"time"

	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/joho/godotenv/autoload"
)

var JWTSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
var AccessTokenExpiration = 15 * time.Minute
var RefreshTokenExpiration = 30 * 24 * time.Hour

// GenerateAccessToken gera um token de acesso JWT para o usuário e dispositivo
// especificados, retorna o token, o tempo de expiração e uma mensagem de erro.
func GenerateAccessToken(userID, deviceID string) (string, int64, error) {
	expirationTime := time.Now().Add(AccessTokenExpiration)

	claims := &types.JWTClaims{
		UserID:   userID,
		DeviceID: deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "dragonite-homeserver", // TODO: trocar pelo nome do servidor
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JWTSecretKey)

	// Retorna o token e o tempo de expiração em milissegundos para a resposta
	expiresInMs := time.Until(expirationTime).Milliseconds()
	return tokenString, expiresInMs, err
}

// GenerateRefreshToken gera um token de "refresco" para o token de acesso
func GenerateRefreshToken() (string, time.Time, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", time.Now().Add(RefreshTokenExpiration), err
	}
	// Usamos URLEncoding para garantir que é seguro para tráfego HTTP/JSON
	return base64.URLEncoding.EncodeToString(bytes), time.Now().Add(RefreshTokenExpiration), nil
}
