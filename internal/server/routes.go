package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/services/client"
)

type API struct {
	DB *sql.DB
}

// Registra os endpoints do servidor
func (s *AppServer) RegisterRoutes() http.Handler {
	// repositorios
	userStore := repository.NewUsuarioStore(s.db.Get())
	deviceStore := repository.NewDispositivoStore(s.db.Get())
	canalStore := repository.NewChannelStore(s.db.Get())
	usuarioCanalStore := repository.NewUsuarioCanalStore(s.db.Get())

	mux := http.NewServeMux()

	clientHandler := client.NewHandler(userStore, deviceStore, canalStore, usuarioCanalStore)

	// Registra rotas
	mux.HandleFunc("GET /health", s.healthHandler)
	clientHandler.RegisterRoutes(mux, s.TokenBearerMiddleware)

	// wildcard
	mux.HandleFunc("GET /", s.HelloWorldHandler)

	// Adiciona middlewares
	// NOTE: a ordem dos middleware importa! O mais interno é chamado primeiro.
	return s.logMiddleware(s.corsMiddleware(mux))
}

func (s *AppServer) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
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

func (s *AppServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := json.Marshal(s.db.Health())
	if err != nil {
		http.Error(w, "Failed to marshal health check response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// mapMatrixKeyToDB converte a chave do Matrix para a coluna do bd.
// Isso evita SQL Injection, pois não usamos a string do usuário direto na query.
func mapMatrixKeyToDB(keyName string) string {
	switch keyName {
	case "displayname":
		return "nome_usuario"
	case "avatar_url":
		return "foto_usuario"
	default:
		return ""
	}
}

// GET /_matrix/client/v3/profile/{userId}
func (api *API) getProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")

	var nome, foto sql.NullString

	query := `SELECT nome_usuario, foto_usuario FROM Usuario WHERE id_usuario = $1`
	err := api.DB.QueryRow(query, userID).Scan(&nome, &foto)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"errcode": "M_NOT_FOUND", "error": "Profile not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"errcode": "M_UNKNOWN", "error": "Internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Monta a resposta. Se o valor for NULL, a string ficará vazia ("").
	response := model.ProfileResponse{
		DisplayName: nome.String,
		AvatarURL:   foto.String,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GET /_matrix/client/v3/profile/{userId}/{keyName}
func (api *API) getProfileKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	keyName := r.PathValue("keyName")

	colunaDB := mapMatrixKeyToDB(keyName)
	if colunaDB == "" {
		http.Error(w, `{"errcode": "M_BAD_JSON", "error": "Invalid profile key"}`, http.StatusBadRequest)
		return
	}

	var valor sql.NullString

	query := fmt.Sprintf("SELECT %s FROM Usuario WHERE id_usuario = $1", colunaDB)
	err := api.DB.QueryRow(query, userID).Scan(&valor)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"errcode": "M_NOT_FOUND", "error": "User not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"errcode": "M_UNKNOWN", "error": "Internal server error"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]string{keyName: valor.String}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// PUT /_matrix/client/v3/profile/{userId}/{keyName}
func (api *API) putProfileKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	keyName := r.PathValue("keyName")

	colunaDB := mapMatrixKeyToDB(keyName)
	if colunaDB == "" {
		http.Error(w, `{"errcode": "M_BAD_JSON", "error": "Invalid profile key"}`, http.StatusBadRequest)
		return
	}

	var reqBody map[string]string
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, `{"errcode": "M_BAD_JSON", "error": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	novoValor, existe := reqBody[keyName]
	if !existe {
		http.Error(w, `{"errcode": "M_BAD_JSON", "error": "Missing key in body"}`, http.StatusBadRequest)
		return
	}

	query := fmt.Sprintf("UPDATE Usuario SET %s = $1 WHERE id_usuario = $2", colunaDB)
	resultado, err := api.DB.Exec(query, novoValor, userID)

	if err != nil {
		http.Error(w, `{"errcode": "M_UNKNOWN", "error": "Database error"}`, http.StatusInternalServerError)
		return
	}

	// Verifica se o usuário realmente existia para ser atualizado
	linhasAfetadas, _ := resultado.RowsAffected()
	if linhasAfetadas == 0 {
		http.Error(w, `{"errcode": "M_NOT_FOUND", "error": "User not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{}`))
}

// DELETE /_matrix/client/v3/profile/{userId}/{keyName}
func (api *API) deleteProfileKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	keyName := r.PathValue("keyName")

	colunaDB := mapMatrixKeyToDB(keyName)
	if colunaDB == "" {
		http.Error(w, `{"errcode": "M_BAD_JSON", "error": "Invalid profile key"}`, http.StatusBadRequest)
		return
	}

	// No SQL, "deletar" um perfil parcial significa setar a coluna como NULL
	query := fmt.Sprintf("UPDATE Usuario SET %s = NULL WHERE id_usuario = $1", colunaDB)
	_, err := api.DB.Exec(query, userID)

	if err != nil {
		http.Error(w, `{"errcode": "M_UNKNOWN", "error": "Database error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{}`))
}
