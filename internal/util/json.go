package util

import "github.com/gibson042/canonicaljson-go"

// Escreve um corpo em json canônico (essencial para o Matrix)
func CanonicalJSON(obj any) ([]byte, error) {
	return canonicaljson.Marshal(obj)
}
