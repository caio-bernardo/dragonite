package utils

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/caio-bernardo/dragonite/internal/types"
)

var (
	RequestTimeout = 2 * time.Second
)

// WriteJSON escreve uma reposta com o corpo em JSON e o status code, a partir de qualquer objeto
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	res, err := json.Marshal(v)
	if err != nil {
		return err
	}

	if _, err = w.Write(res); err != nil {
		return err
	}
	return nil
}

// WriteError escreve uma resposta de erro em uma reponse, acompanhada de um status Code
func WriteError(w http.ResponseWriter, status int, message types.ErrorResponse) {
	WriteJSON(w, status, message)
}

// UnimplementedHandler representa um handler não implementado ainda.
func UnimplementedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Implemented", http.StatusNotImplemented)
}
