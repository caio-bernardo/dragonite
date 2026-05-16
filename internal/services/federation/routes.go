package federation

import (
	"net/http"
	"os"

	"github.com/caio-bernardo/dragonite/internal/util"
	_ "github.com/joho/godotenv/autoload"
)

var (
	ServerName = os.Getenv("SERVER_NAME")
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /_matrix/federation/v1/version", h.getVersion)

}

func (h *Handler) getVersion(w http.ResponseWriter, r *http.Request) {
	res := VersionResponse{}
	res.Server.Name = ServerName
	res.Server.Version = "1.0.0"
	util.WriteJSON(w, http.StatusOK, res)
}
