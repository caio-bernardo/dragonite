package model

import (
	"fmt"
	"regexp"
	"time"

	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	"golang.org/x/crypto/bcrypt"
)

type Usuario struct {
	ID          string    `json:"id_usuario"`
	LocalPart   string    `json:"localpart_usuario"`
	Nome        string    `json:"nome_usuario"`
	Senha       string    `json:"senha_usuario"`
	Foto        string    `json:"foto_usuario"`
	DataCriacao time.Time `json:"data_criacao_usuario"`
}

type UsuarioCreate struct {
	LocalPart   string    `json:"localpart_usuario"`
	Nome        string    `json:"nome_usuario"`
	Senha       string    `json:"senha_usuario"`
	Foto        string    `json:"foto_usuario"`
	DataCriacao time.Time `json:"data_criacao_usuario"`
}

// ToUsuario converte um UsuarioCreate em um Usuario fazendo validação e hash da senha
func (uc UsuarioCreate) ToUsuario() (Usuario, error) {
	if !ValidateLocalPart(uc.LocalPart) {
		return Usuario{}, types.ErrInvalidUsername
	}

	passwordHash, err := HashPassword(uc.Senha)
	if err != nil {
		return Usuario{}, err
	}

	return Usuario{
		ID:          GenerateUsuarioID(uc.LocalPart),
		LocalPart:   uc.LocalPart,
		Nome:        uc.Nome,
		Senha:       passwordHash,
		Foto:        uc.Foto,
		DataCriacao: uc.DataCriacao,
	}, nil
}

// GenerateUsuarioID gera um ID de usuário no formato @localpart:server_name
func GenerateUsuarioID(localpart string) string {
	return fmt.Sprintf("@%s:%s", localpart, util.ServerName)
}

// ValidateLocalPart valida o localpart do usuário usando uma expressão regular
func ValidateLocalPart(localpart string) bool {
	return regexp.MustCompile(`^[\w\d._=+-]+$`).MatchString(localpart)
}

// HashPassword gera um hash da senha usando bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
