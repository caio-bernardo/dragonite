package util

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/caio-bernardo/dragonite/internal/types"
)

var (
	ErrInvalidID = errors.New("invalid id parameter")
)

// / Escreve uma reposta com o corpo em JSON com o status passado
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

// / Lê o corpo (em json) da requisição, decodifica e armazena no destino
func ReadJSON(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

func GetIDParam(r *http.Request) (int64, error) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return 0, ErrInvalidID
	}
	return id, nil
}

func GetComposedID(r *http.Request) (int64, int64, error) {
	idStr1 := r.PathValue("id_produto")
	idStr2 := r.PathValue("id_oferta")

	id1, err := strconv.ParseInt(idStr1, 10, 64)

	if err != nil {
		return 0, 0, ErrInvalidID
	}

	id2, err := strconv.ParseInt(idStr2, 10, 64)

	if err != nil {
		return 0, 0, ErrInvalidID
	}
	return id1, id2, nil
}

// WriteError escreve uma resposta de erro em uma reponse, acompanhada de um status Code
func WriteError(w http.ResponseWriter, status int, message types.ErrorResponse) {
	WriteJSON(w, status, message)
}


