package auth

import (
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAccessToken(t *testing.T) {
	originalKey := JWTSecretKey
	JWTSecretKey = []byte("test-secret")
	defer func() {
		JWTSecretKey = originalKey
	}()

	userID := "@alice:example.com"
	deviceID := "DEVICE123"

	tokenString, expiresMS, err := GenerateAccessToken(userID, deviceID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if tokenString == "" {
		t.Fatalf("expected non-empty token string")
	}
	if expiresMS <= 0 {
		t.Fatalf("expected expiresMS to be positive, got %d", expiresMS)
	}

	parsedToken, err := jwt.ParseWithClaims(tokenString, &types.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return JWTSecretKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if !parsedToken.Valid {
		t.Fatalf("expected token to be valid")
	}

	claims, ok := parsedToken.Claims.(*types.JWTClaims)
	if !ok {
		t.Fatalf("expected JWTClaims type")
	}
	if claims.UserID != userID {
		t.Fatalf("expected userID %q; got %q", userID, claims.UserID)
	}
	if claims.DeviceID != deviceID {
		t.Fatalf("expected deviceID %q; got %q", deviceID, claims.DeviceID)
	}
	if claims.Issuer != "dragonite-homeserver" {
		t.Fatalf("expected issuer %q; got %q", "dragonite-homeserver", claims.Issuer)
	}
	if claims.ExpiresAt == nil {
		t.Fatalf("expected ExpiresAt to be set")
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	token, expiresAt, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty refresh token")
	}

	now := time.Now()
	if expiresAt.Before(now) {
		t.Fatalf("expected refresh token expiration in the future")
	}

	expected := now.Add(RefreshTokenExpiration)
	diff := expiresAt.Sub(expected)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Fatalf("expected refresh token expiration close to %v; got %v (diff %v)", expected, expiresAt, diff)
	}
}

func TestGenerateRefreshToken_Uniqueness(t *testing.T) {
	tokenA, _, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	tokenB, _, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if tokenA == tokenB {
		t.Fatalf("expected refresh tokens to be different")
	}
}
