package domain

import (
	"encoding/json"
	"strconv"
	"time"
)

// VersaoBackup representa uma versão do backup de chaves de sessão (Server-side Key Backup)
// de um usuário, usado no fluxo de E2EE (megolm backup)
// Uma nova versão nunca sobrescreve uma anterior: cada POST cria uma linha nova,
// e a "latest" é sempre a de maior IDVersao para aquele usuário
type VersaoBackup struct {
	IDVersao  int64 // PK interna, autoincrementável
	IDUsuario string
	Algorithm string
	AuthData  json.RawMessage
	Count     int64  // número de chaves armazenadas nesta versão do backup
	ETag      string // string opaca que muda a cada alteração no conteúdo do backup
	CreatedAt time.Time
}

// VersionString retorna o identificador de versão no formato string opaco
func (v VersaoBackup) VersionString() string {
	return strconv.FormatInt(v.IDVersao, 10)
}

// ChaveBackup representa uma chave de sessão megolm armazenada numa versão de backup
type ChaveBackup struct {
	IDVersao          int64
	IDCanal           string // room ID
	IDSessao          string // session ID
	FirstMessageIndex int64
	ForwardedCount    int64
	IsVerified        bool
	SessionData       json.RawMessage
}
