package types

import "errors"

var (
	ErrNotFound           = errors.New("Not found")
	ErrInvalidSearchTerm  = errors.New("Invalid search term")
	ErrNoBodyFound        = errors.New("No body found")
	ErrTimeout            = errors.New("Timeout")
	ErrLooseConnection    = errors.New("Loose connection")
	ErrInvalidUserID      = errors.New("Invalid user ID")
	ErrForbidden          = errors.New("Forbidden")
	ErrUnimplemented      = errors.New("Unimplemented")
	ErrUnauthorized       = errors.New("Unauthorized")
	ErrInvalidParam       = errors.New("Invalid param")
	ErrInvalidCredentials = errors.New("Invalid credentials")
	ErrInternalError      = errors.New("Internal error")
	ErrAlreadyInUse       = errors.New("Already in use")
)

func InternalError(reason error) error {
	return errors.Join(ErrInternalError, reason)
}
