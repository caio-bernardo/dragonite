package config

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/caio-bernardo/dragonite/internal/util"
	_ "github.com/joho/godotenv/autoload"
)

type AppConfig struct {
	ServerName    string `env:"SERVER_NAME"`
	ServerPort    int    `env:"BACKEND_PORT"`
	Version       string `env:"VERSION"`
	JWTToken      string `env:"JWT_TOKEN"`
	KeyID         string `env:"KEY_ID"`
	DatabaseURL   string
	RedisHost     string `env:"REDIS_HOST"`
	RedisPort     int    `env:"REDIS_PORT"`
	RedisPassword string `env:"REDIS_PASSWORD"`
	RedisDB       int
	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
	// Configurações do MinIO (object storage para arquivos de mídia)
	MinioEndpoint  string `env:"MINIO_ENDPOINT"`
	MinioAccessKey string `env:"MINIO_ACCESS_KEY"`
	MinioSecretKey string `env:"MINIO_SECRET_KEY"`
	MinioUseSSL    bool   `env:"MINIO_USE_SSL"`
	// Limite máximo de tamanho de upload em bytes (default: 50 MB)
	MaxUploadBytes int64 `env:"MAX_UPLOAD_BYTES"`
}

func LoadConfig() (*AppConfig, error) {
	if os.Getenv("BACKEND_PORT") == "" {
		return nil, errors.New("BACKEND_PORT variable is not set")
	}
	port, err := strconv.Atoi(os.Getenv("BACKEND_PORT"))
	if err != nil {
		return nil, errors.New("BACKEND_PORT is not a valid integer")
	}

	if os.Getenv("SERVER_NAME") == "" {
		return nil, errors.New("SERVER_NAME variable is not set")
	}

	if os.Getenv("VERSION") == "" {
		return nil, errors.New("VERSION variable is not set")
	}

	if os.Getenv("JWT_TOKEN") == "" {
		return nil, errors.New("JWT_TOKEN variable is not set")
	}

	if os.Getenv("REDIS_HOST") == "" {
		return nil, errors.New("REDIS_HOST variable is not set")
	}

	if os.Getenv("REDIS_PORT") == "" {
		return nil, errors.New("REDIS_PORT variable is not set")
	}

	redis_port, err := strconv.Atoi(os.Getenv("REDIS_PORT"))
	if err != nil {
		return nil, errors.New("REDIS_PORT is not a valid integer")
	}

	if os.Getenv("REDIS_PASSWORD") == "" {
		return nil, errors.New("REDIS_PASSWORD variable is not set")
	}

	// Validação das variáveis do MinIO
	if os.Getenv("MINIO_ENDPOINT") == "" {
		return nil, errors.New("MINIO_ENDPOINT variable is not set")
	}
	if os.Getenv("MINIO_ACCESS_KEY") == "" {
		return nil, errors.New("MINIO_ACCESS_KEY variable is not set")
	}
	if os.Getenv("MINIO_SECRET_KEY") == "" {
		return nil, errors.New("MINIO_SECRET_KEY variable is not set")
	}

	databaseUrl := fmt.Sprintf(
		"user=%s password=%s host=%s port=%s dbname=%s",
		os.Getenv("DRAGONITE_DB_USERNAME"),
		os.Getenv("DRAGONITE_DB_PASSWORD"),
		os.Getenv("DRAGONITE_DB_HOST"),
		os.Getenv("DRAGONITE_DB_PORT"),
		os.Getenv("DRAGONITE_DB_DATABASE"),
	)

	key, pubKey, privKey, err := util.GenerateServerKey(os.Getenv("SERVER_NAME"), os.Getenv("VERSION"))
	if err != nil {
		return nil, err
	}

	// MinIO SSL: false por padrão (ambiente local/dev), true em produção
	minioUseSSL := os.Getenv("MINIO_USE_SSL") == "true"

	// Limite de upload: padrão 50 MB se não configurado
	var maxUploadBytes int64 = 50 * 1024 * 1024
	if raw := os.Getenv("MAX_UPLOAD_BYTES"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, errors.New("MAX_UPLOAD_BYTES is not a valid integer")
		}
		maxUploadBytes = parsed
	}

	config := AppConfig{
		ServerName:     os.Getenv("SERVER_NAME"),
		ServerPort:     port,
		Version:        os.Getenv("VERSION"),
		JWTToken:       os.Getenv("JWT_TOKEN"),
		DatabaseURL:    databaseUrl,
		RedisHost:      os.Getenv("REDIS_HOST"),
		RedisPort:      redis_port,
		RedisPassword:  os.Getenv("REDIS_PASSWORD"),
		RedisDB:        0,
		KeyID:          key,
		PublicKey:      pubKey,
		PrivateKey:     privKey,
		MinioEndpoint:  os.Getenv("MINIO_ENDPOINT"),
		MinioAccessKey: os.Getenv("MINIO_ACCESS_KEY"),
		MinioSecretKey: os.Getenv("MINIO_SECRET_KEY"),
		MinioUseSSL:    minioUseSSL,
		MaxUploadBytes: maxUploadBytes,
	}

	return &config, nil
}
