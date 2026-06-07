package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter"
	"github.com/caio-bernardo/dragonite/internal/infrastructure/config"
	"github.com/caio-bernardo/dragonite/internal/infrastructure/postgres"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

func main() {
	ctx := context.Background()

	// infraestrutura
	config, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}

	dbPool, err := postgres.ConnectBD(ctx, config.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}
	defer dbPool.Close()

	// storage implementa TODAS as funções que cada interface requer
	storage := postgres.NewPostgresStorage(dbPool)
	notifier := postgres.NewPostgresNotifier(dbPool)
	// eventBus := eventbus.NewEventBus()

	// cria usecases
	// TODO: implementar storage apropriadamente
	authService := usecase.NewAuthService()
	dirService := usecase.NewDirectoryService(storage, storage)
	profileService := usecase.NewProfileService(storage)
	roomAdminService := usecase.NewRoomAdminService(storage)
	roomInteractionsService := usecase.NewRoomInteractionService(storage, storage, , storage)
	syncService := usecase.NewSyncService(storage, notifier)
	systemService := usecase.NewHealthService(storage)
	usuarioService := usecase.NewUsuarioService(storage, storage, storage, eventBus)

	// cria servidor
	server := http_adapter.NewServer(config.ServerPort, config.JWTToken,
		config.ServerName, authService, dirService, profileService,
		roomAdminService, roomInteractionsService, syncService, systemService,
		usuarioService,
	)

	// cria um novo channel do tipo booleano e espaço de memória 1 byte
	// Um channel é um meio de comunicação entre threads (goroutines)
	done := make(chan bool, 1)

	// Cria uma goroutine/thread para ouvir o sinal de término
	go gracefulShutdown(server, done)

	// O servidor escuta na porta correspondente e serve as requisições
	log.Println("Listening on port", server.Addr)
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Panic("Server ERROR ", err)
	}

	// espera o sinal do gracefulShutdown
	<-done
	log.Println("Graceful shutdown complete.")
}

// Cria um graceful shutdown (desativação elegante), esperando as operações do
// servidor finalizarem antes de derrubá-lo, envia um sinal de finalização pelo
// channel done
func gracefulShutdown(apiServer *http.Server, done chan bool) {
	// Cria um contexto que escuta pela notificação de término (e.g. Ctrl-C, kill, etc)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Escuta pelo sinal de interrupção (bloqueia a thread)
	<-ctx.Done()

	log.Println("Shutting down gracefully, press Ctrl-C again to force termination.")

	stop() // Permite forçar o shutdown com Ctrl-C

	// O contexto diz que o servidor tem 5 segundos para encerrar suas atividades
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Diz ao servidor para encerrar
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down: %v", err)
	}

	log.Println("Server exiting.")

	// notifica a thread principal que o shutdown foi completado
	done <- true
}
