package httputil

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

var (
	ErrInvalidID = errors.New("invalid id parameter")
)

// / Escreve uma reposta com o corpo em JSON com o status passado
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	res, err := util.CanonicalJSON(v)
	if err != nil {
		return err
	}

	if _, err = w.Write(res); err != nil {
		return err
	}
	return nil
}

// ParseBody lê o corpo (em json) da requisição, decodifica e armazena no destino
func ParseBody(r *http.Request, payload any) error {
	if r.Body == nil {
		return types.ErrNoBodyFound
	}
	err := json.NewDecoder(r.Body).Decode(payload)
	return err
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
func WriteError(w http.ResponseWriter, status int, message MatrixErrorResponse) {
	WriteJSON(w, status, message)
}

func WriteMatrixError(w http.ResponseWriter, status int, errcode MatrixErrorCode, message string) {
	log.Printf("[%s] [DEBUG] MatrixError: %s - %s", time.Now().Format("2006-01-02 15:04:05"), errcode, message)
	WriteJSON(w, status, MatrixErrorResponse{
		ErrCode: errcode,
		Message: message,
	})
}
