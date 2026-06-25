package http_adapter

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/federation"
	"github.com/caio-bernardo/dragonite/internal/infrastructure"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// AppServer representa o servidor em nível de aplicação
type Server struct {
	jwtSecret               string
	port                    int
	serverName              string
	authService             *usecase.AuthService
	dirService              *usecase.DirectoryService
	fedService              *usecase.FederationService
	profileService          *usecase.ProfileService
	roomAdminService        *usecase.RoomAdminService
	roomMembershipService   *usecase.RoomMembershipService
	roomInteractionsService *usecase.RoomInteractionService
	syncService             *usecase.SyncService
	systemService           *usecase.SystemService
	usuarioService          *usecase.UsuarioService
	mediaService            *usecase.MediaService
	idempotencyCache        infrastructure.IdempotencyCache
}

// Cria um novo servidor http
func NewServer(port int,
	jwtSecret string,
	serverName string,
	authService *usecase.AuthService,
	dirService *usecase.DirectoryService,
	fedService *usecase.FederationService,
	profileService *usecase.ProfileService,
	roomMembershipService *usecase.RoomMembershipService,
	roomAdminService *usecase.RoomAdminService,
	roomInteractionsService *usecase.RoomInteractionService,
	syncService *usecase.SyncService,
	systemService *usecase.SystemService,
	usuarioService *usecase.UsuarioService,
	mediaService *usecase.MediaService,
	idempotencyCache infrastructure.IdempotencyCache,
) *http.Server {

	NewServer := &Server{
		authService: authService,
		dirService:  dirService,
		fedService:  fedService,
		jwtSecret:   jwtSecret,
		port:        port,

		profileService:          profileService,
		roomAdminService:        roomAdminService,
		roomMembershipService:   roomMembershipService,
		roomInteractionsService: roomInteractionsService,
		syncService:             syncService,
		systemService:           systemService,
		usuarioService:          usuarioService,
		mediaService:            mediaService,
		idempotencyCache:        idempotencyCache,
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

// Registra os endpoints do servidor
func (s *Server) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	clientHandler := client.NewHandler(
		s.serverName,
		s.authService,
		s.usuarioService,
		s.dirService,
		s.profileService,
		s.syncService,
		s.roomAdminService,
		s.roomMembershipService,
		s.roomInteractionsService,
		s.mediaService,
		s.idempotencyCache,
	)
	clientHandler.RegisterRoutes(mux, s.TokenBearerMiddleware)

	federationHandler := federation.NewHandler(s.systemService, s.fedService, s.roomInteractionsService, s.profileService, s.dirService)
	federationHandler.RegisterRoutes(mux)

	// Registra rotas
	mux.HandleFunc("GET /health", s.healthHandler)

	// wildcard
	mux.HandleFunc("GET /", s.HelloWorldHandler)

	// Adiciona middlewares
	// NOTE: a ordem dos middleware importa! O mais interno é chamado primeiro.
	return s.logMiddleware(s.corsMiddleware(mux))
}

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{"message": "Hello World"}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(jsonResp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := json.Marshal(s.systemService.PingDB())
	if err != nil {
		http.Error(w, "Failed to marshal health check response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
