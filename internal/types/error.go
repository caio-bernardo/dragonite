package types

import "errors"

var (
	ErrNotFound = errors.New("Not found")
	ErrInternalServer = errors.New("Internal error")
)

type ErrorResponse struct {
	Message string `json:"detail"`
}

func NewErrorResponse(msg string) ErrorResponse {
	return ErrorResponse{Message: msg}
}
