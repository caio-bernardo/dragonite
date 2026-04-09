package server

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/database"
	_ "github.com/joho/godotenv/autoload"
)

// AppServer representa o servidor em nível de aplicação
type AppServer struct {
	port int

	db database.Service
}

// Cria um novo servidor http
func NewServer() *http.Server {
	port, _ := strconv.Atoi(os.Getenv("BACKEND_PORT"))
	NewServer := &AppServer{
		port: port,
		db:   database.New(),
	}

	// servidor http, com endpoints registrados e timeout para operações R/W
	server := http.Server{
		Addr:         ":" + strconv.Itoa(port),
		Handler:      NewServer.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return &server
}
