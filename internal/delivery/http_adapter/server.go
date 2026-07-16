package http_adapter

import (
	"encoding/json"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/federation"
	"github.com/caio-bernardo/dragonite/internal/infrastructure"
	"github.com/caio-bernardo/dragonite/internal/usecase"
	"github.com/caio-bernardo/dragonite/internal/util"
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
	accountService          *usecase.AccountService
	roomAdminService        *usecase.RoomAdminService
	roomMembershipService   *usecase.RoomMembershipService
	roomInteractionsService *usecase.RoomInteractionService
	syncService             *usecase.SyncService
	systemService           *usecase.SystemService
	usuarioService          *usecase.UsuarioService
	mediaService            *usecase.MediaService
	idempotencyCache        infrastructure.IdempotencyCache
	keyFetcher              federation.KeyFetcherFn
}

// Cria um novo servidor http
func NewServer(port int,
	jwtSecret string,
	serverName string,
	authService *usecase.AuthService,
	dirService *usecase.DirectoryService,
	fedService *usecase.FederationService,
	profileService *usecase.ProfileService,
	accountService *usecase.AccountService,
	roomMembershipService *usecase.RoomMembershipService,
	roomAdminService *usecase.RoomAdminService,
	roomInteractionsService *usecase.RoomInteractionService,
	syncService *usecase.SyncService,
	systemService *usecase.SystemService,
	usuarioService *usecase.UsuarioService,
	mediaService *usecase.MediaService,
	idempotencyCache infrastructure.IdempotencyCache,
	keyFetcher federation.KeyFetcherFn,
) *http.Server {

	NewServer := &Server{
		authService: authService,
		dirService:  dirService,
		fedService:  fedService,
		jwtSecret:   jwtSecret,
		port:        port,

		profileService:          profileService,
		accountService:          accountService,
		roomAdminService:        roomAdminService,
		roomMembershipService:   roomMembershipService,
		roomInteractionsService: roomInteractionsService,
		syncService:             syncService,
		systemService:           systemService,
		usuarioService:          usuarioService,
		mediaService:            mediaService,
		idempotencyCache:        idempotencyCache,
		keyFetcher:              util.FetchRemoteServerKey,
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
		s.accountService,
		s.syncService,
		s.roomAdminService,
		s.roomMembershipService,
		s.roomInteractionsService,
		s.mediaService,
		s.idempotencyCache,
	)
	clientHandler.RegisterRoutes(mux, s.TokenBearerMiddleware)

	federationHandler := federation.NewHandler(s.systemService, s.fedService, s.roomInteractionsService, s.profileService, s.dirService, s.mediaService, s.keyFetcher, s.serverName)
	federationHandler.RegisterRoutes(mux)

	// Registra rotas
	mux.HandleFunc("GET /health", s.healthHandler)
	mux.HandleFunc("GET /.well-known/matrix/{fileName}", s.wellKnownMatrixHandler)

	// wildcard
	// mux.HandleFunc("GET /", s.HelloWorldHandler)

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

func (s *Server) wellKnownMatrixHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.PathValue("fileName")
	if !isAllowedWellKnownMatrixFile(fileName) {
		http.NotFound(w, r)
		return
	}

	http.ServeFile(w, r, filepath.Join("static", ".well-known", "matrix", fileName))
}

func isAllowedWellKnownMatrixFile(fileName string) bool {
	if fileName == "" || strings.Contains(fileName, "/") || strings.Contains(fileName, "..") {
		return false
	}

	switch fileName {
	case "client", "server", "support":
		return true
	default:
		return false
	}
}
