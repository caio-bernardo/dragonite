package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// KeysService contém a lógica de gerenciamento de chaves de dispositivo E2EE (device keys,
// one-time keys, fallback keys)
type KeysService struct {
	uow        WorkUnit
	keysStore  KeysStorage
	federation *FederationService
	serverName string
}

func NewKeysService(uow WorkUnit, keysStore KeysStorage, federation *FederationService, serverName string) *KeysService {
	return &KeysService{uow: uow, keysStore: keysStore, federation: federation, serverName: serverName}
}

// UploadKeysParams agrupa os dados recebidos em POST /_matrix/client/v3/keys/upload
type UploadKeysParams struct {
	UserID       string
	DeviceID     string
	Algorithms   []string
	IdentityKeys json.RawMessage
	Signatures   json.RawMessage
	OneTimeKeys  map[string]json.RawMessage
	FallbackKeys map[string]json.RawMessage
}

// UploadKeys persiste as chaves de identidade, one-time keys e fallback keys de um dispositivo
// numa única transação, retornando a contagem de one-time keys remanescentes por algoritmo
func (s *KeysService) UploadKeys(ctx context.Context, params UploadKeysParams) (map[string]int, error) {
	var counts map[string]int

	err := s.uow.Execute(ctx, func(txCtx context.Context) error {
		if len(params.Algorithms) > 0 {
			err := s.keysStore.UpsertDeviceKeys(txCtx, domain.ChavesDispositivo{
				DispositivoID: params.DeviceID,
				UsuarioID:     params.UserID,
				Algorithms:    params.Algorithms,
				Keys:          params.IdentityKeys,
				Signatures:    params.Signatures,
			})
			if err != nil {
				return err
			}
		}

		if len(params.OneTimeKeys) > 0 {
			otks := make([]domain.ChaveUsoUnico, 0, len(params.OneTimeKeys))
			for keyID, data := range params.OneTimeKeys {
				algorithm, _, _ := strings.Cut(keyID, ":")
				otks = append(otks, domain.ChaveUsoUnico{
					DispositivoID: params.DeviceID,
					KeyID:         keyID,
					Algorithm:     algorithm,
					KeyData:       data,
				})
			}
			if err := s.keysStore.UpsertOneTimeKeys(txCtx, params.DeviceID, otks); err != nil {
				return err
			}
		}

		for keyID, data := range params.FallbackKeys {
			algorithm, _, _ := strings.Cut(keyID, ":")
			err := s.keysStore.UpsertFallbackKey(txCtx, domain.ChaveFallback{
				DispositivoID: params.DeviceID,
				Algorithm:     algorithm,
				KeyID:         keyID,
				KeyData:       data,
				Usada:         false,
			})
			if err != nil {
				return err
			}
		}

		var err error
		counts, err = s.keysStore.CountOneTimeKeys(txCtx, params.DeviceID)
		return err
	})
	if err != nil {
		return nil, types.InternalError(err)
	}

	return counts, nil
}

// QueryKeysResult é o resultado agregado (local + federado) de uma consulta de chaves
type QueryKeysResult struct {
	DeviceKeys      map[string]map[string]domain.ChavesDispositivo // userID -> deviceID -> chaves
	MasterKeys      map[string]domain.ChaveCrossSigning            // userID -> master key
	SelfSigningKeys map[string]domain.ChaveCrossSigning            // userID -> self-signing key
	UserSigningKeys map[string]domain.ChaveCrossSigning            // apenas para requestingUserID, se presente na query
	Failures        map[string]any
}

// QueryKeys busca as chaves de identidade (e, para usuários locais, de cross-signing) dos
// dispositivos pedidos, roteando para o storage local ou pra federação de acordo com o domínio
// de cada userID. requestingUserID é necessário porque o user_signing_key só é retornado quando
// o próprio usuário consulta a si mesmo (ver "Key and signature security" na spec).
func (s *KeysService) QueryKeys(ctx context.Context, requestingUserID string, requested map[string][]string) QueryKeysResult {
	result := QueryKeysResult{
		DeviceKeys:      make(map[string]map[string]domain.ChavesDispositivo),
		MasterKeys:      make(map[string]domain.ChaveCrossSigning),
		SelfSigningKeys: make(map[string]domain.ChaveCrossSigning),
		UserSigningKeys: make(map[string]domain.ChaveCrossSigning),
		Failures:        make(map[string]any),
	}

	remoteByServer := make(map[string]map[string][]string)

	for userID, deviceIDs := range requested {
		domainName := util.ExtractDomainFromUserID(userID)
		if domainName != s.serverName {
			if remoteByServer[domainName] == nil {
				remoteByServer[domainName] = make(map[string][]string)
			}
			remoteByServer[domainName][userID] = deviceIDs
			continue
		}

		keys, err := s.keysStore.GetDeviceKeys(ctx, userID, deviceIDs)
		if err != nil {
			log.Printf("[ERROR] QueryKeys (local user=%s): %v", userID, err)
		} else if len(keys) > 0 {
			devMap := make(map[string]domain.ChavesDispositivo, len(keys))
			for _, k := range keys {
				devMap[k.DispositivoID] = k
			}
			result.DeviceKeys[userID] = devMap
		}

		crossKeys, err := s.keysStore.GetCrossSigningKeys(ctx, userID)
		if err != nil {
			log.Printf("[ERROR] QueryKeys cross-signing (user=%s): %v", userID, err)
			continue
		}
		if mk, ok := crossKeys["master"]; ok {
			result.MasterKeys[userID] = mk
		}
		if ssk, ok := crossKeys["self_signing"]; ok {
			result.SelfSigningKeys[userID] = ssk
		}
		if usk, ok := crossKeys["user_signing"]; ok && userID == requestingUserID {
			result.UserSigningKeys[userID] = usk
		}
	}

	// Uma requisição de federação por servidor remoto envolvido (device keys + cross-signing)
	for server, deviceKeysReq := range remoteByServer {
		remoteResult, err := s.federation.QueryKeysCall(ctx, server, deviceKeysReq)
		if err != nil {
			log.Printf("[ERROR] QueryKeys (remote server=%s): %v", server, err)
			result.Failures[server] = map[string]any{}
			continue
		}
		for userID, devices := range remoteResult.DeviceKeys {
			devMap := make(map[string]domain.ChavesDispositivo, len(devices))
			for deviceID, raw := range devices {
				var parsed struct {
					Algorithms []string        `json:"algorithms"`
					Keys       json.RawMessage `json:"keys"`
					Signatures json.RawMessage `json:"signatures"`
				}
				if err := json.Unmarshal(raw, &parsed); err != nil {
					continue
				}
				devMap[deviceID] = domain.ChavesDispositivo{
					DispositivoID: deviceID,
					UsuarioID:     userID,
					Algorithms:    parsed.Algorithms,
					Keys:          parsed.Keys,
					Signatures:    parsed.Signatures,
				}
			}
			result.DeviceKeys[userID] = devMap
		}

		// user_signing_key nunca é federado (decisão de confiança privada do próprio
		// usuário), por isso só master_keys/self_signing_keys são processados aqui
		for userID, raw := range remoteResult.MasterKeys {
			key, err := parseCrossSigningKeyResponse(userID, "master", raw)
			if err != nil {
				log.Printf("[ERROR] QueryKeys (remote master key user=%s): %v", userID, err)
				continue
			}
			result.MasterKeys[userID] = key
		}
		for userID, raw := range remoteResult.SelfSigningKeys {
			key, err := parseCrossSigningKeyResponse(userID, "self_signing", raw)
			if err != nil {
				log.Printf("[ERROR] QueryKeys (remote self_signing key user=%s): %v", userID, err)
				continue
			}
			result.SelfSigningKeys[userID] = key
		}
	}

	return result
}

// parseCrossSigningKeyResponse converte o CrossSigningKey bruto recebido via federação
// (POST .../user/keys/query) para domain.ChaveCrossSigning
func parseCrossSigningKeyResponse(userID, usage string, raw json.RawMessage) (domain.ChaveCrossSigning, error) {
	var parsed struct {
		Keys       json.RawMessage `json:"keys"`
		Signatures json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return domain.ChaveCrossSigning{}, err
	}

	bareKeyID, err := extractBareKeyID(parsed.Keys)
	if err != nil {
		return domain.ChaveCrossSigning{}, err
	}

	return domain.ChaveCrossSigning{
		UsuarioID:  userID,
		Usage:      usage,
		KeyID:      bareKeyID,
		Keys:       parsed.Keys,
		Signatures: parsed.Signatures,
	}, nil
}

// ClaimKeysResult é o resultado agregado (local + federado) de uma reivindicação de one-time keys
type ClaimKeysResult struct {
	OneTimeKeys map[string]map[string]map[string]json.RawMessage // userID -> deviceID -> keyID -> KeyObject
	Failures    map[string]any
}

// ClaimKeys reivindica one-time keys (ou fallback, se as OTKs se esgotaram) dos dispositivos pedidos
func (s *KeysService) ClaimKeys(ctx context.Context, requested map[string]map[string]string) ClaimKeysResult {
	result := ClaimKeysResult{
		OneTimeKeys: make(map[string]map[string]map[string]json.RawMessage),
		Failures:    make(map[string]any),
	}

	remoteByServer := make(map[string]map[string]map[string]string)

	for userID, devices := range requested {
		domainName := util.ExtractDomainFromUserID(userID)
		if domainName == s.serverName {
			for deviceID, algorithm := range devices {
				claimed, err := s.keysStore.ClaimOneTimeKey(ctx, deviceID, algorithm)
				if err != nil {
					log.Printf("[ERROR] ClaimKeys (local device=%s): %v", deviceID, err)
					continue
				}
				if claimed == nil {
					// Sem OTKs sobrando, tenta a fallback key
					fallback, err := s.keysStore.ClaimFallbackKey(ctx, deviceID, algorithm)
					if err != nil || fallback == nil {
						continue
					}
					s.addClaimedKey(result.OneTimeKeys, userID, deviceID, fallback.KeyID, fallback.KeyData)
					continue
				}
				s.addClaimedKey(result.OneTimeKeys, userID, deviceID, claimed.KeyID, claimed.KeyData)
			}
			continue
		}

		if remoteByServer[domainName] == nil {
			remoteByServer[domainName] = make(map[string]map[string]string)
		}
		remoteByServer[domainName][userID] = devices
	}

	for server, oneTimeKeysReq := range remoteByServer {
		remoteResult, err := s.federation.ClaimKeysCall(ctx, server, oneTimeKeysReq)
		if err != nil {
			log.Printf("[ERROR] ClaimKeys (remote server=%s): %v", server, err)
			result.Failures[server] = map[string]any{}
			continue
		}
		for userID, devices := range remoteResult {
			if result.OneTimeKeys[userID] == nil {
				result.OneTimeKeys[userID] = make(map[string]map[string]json.RawMessage)
			}
			for deviceID, keys := range devices {
				result.OneTimeKeys[userID][deviceID] = keys
			}
		}
	}

	return result
}

func (s *KeysService) addClaimedKey(dst map[string]map[string]map[string]json.RawMessage, userID, deviceID, keyID string, data json.RawMessage) {
	if dst[userID] == nil {
		dst[userID] = make(map[string]map[string]json.RawMessage)
	}
	if dst[userID][deviceID] == nil {
		dst[userID][deviceID] = make(map[string]json.RawMessage)
	}
	dst[userID][deviceID][keyID] = data
}

// UploadCrossSigningKeysParams agrupa os dados de POST /_matrix/client/v3/keys/device_signing/upload.
// Cada campo é o objeto CrossSigningKey bruto (json.RawMessage) como enviado pelo cliente; nil se omitido
type UploadCrossSigningKeysParams struct {
	UserID         string
	MasterKey      json.RawMessage
	SelfSigningKey json.RawMessage
	UserSigningKey json.RawMessage
}

// UploadCrossSigningKeys persiste as chaves de cross-signing do usuário.
// NOTE: não exige User-Interactive Authentication nem valida criptograficamente as assinaturas
// entre as chaves, mesma simplificação já adotada em ProcessInboundPDU
func (s *KeysService) UploadCrossSigningKeys(ctx context.Context, params UploadCrossSigningKeysParams) error {
	entries := []struct {
		usage string
		raw   json.RawMessage
	}{
		{"master", params.MasterKey},
		{"self_signing", params.SelfSigningKey},
		{"user_signing", params.UserSigningKey},
	}

	for _, e := range entries {
		if len(e.raw) == 0 {
			continue
		}

		var parsed struct {
			Keys       json.RawMessage `json:"keys"`
			Signatures json.RawMessage `json:"signatures"`
		}
		if err := json.Unmarshal(e.raw, &parsed); err != nil {
			return fmt.Errorf("invalid %s key: %w", e.usage, err)
		}

		bareKeyID, err := extractBareKeyID(parsed.Keys)
		if err != nil {
			return fmt.Errorf("invalid %s key: %w", e.usage, err)
		}

		err = s.keysStore.UpsertCrossSigningKey(ctx, domain.ChaveCrossSigning{
			UsuarioID:  params.UserID,
			Usage:      e.usage,
			KeyID:      bareKeyID,
			Keys:       parsed.Keys,
			Signatures: parsed.Signatures,
		})
		if err != nil {
			return fmt.Errorf("failed to store %s key: %w", e.usage, err)
		}
	}

	return nil
}

// extractBareKeyID extrai o identificador cru (sem prefixo de algoritmo) da única entrada
// do objeto "keys" de uma CrossSigningKey, ex: {"ed25519:PUBKEY": "PUBKEY"} -> "PUBKEY"
func extractBareKeyID(keysMap json.RawMessage) (string, error) {
	var parsed map[string]string
	if err := json.Unmarshal(keysMap, &parsed); err != nil {
		return "", err
	}
	for fullKeyID := range parsed {
		if _, bare, found := strings.Cut(fullKeyID, ":"); found {
			return bare, nil
		}
		return fullKeyID, nil
	}
	return "", fmt.Errorf("empty keys object")
}

// UploadSignaturesResult é o resultado de POST /_matrix/client/v3/keys/signatures/upload
type UploadSignaturesResult struct {
	Failures map[string]map[string]any // userID -> keyID -> erro
}

// UploadSignatures funde novas assinaturas nas chaves de dispositivo ou de cross-signing já
// armazenadas localmente (assinaturas sobre usuários remotos não são suportadas por ora).
// NOTE: não valida criptograficamente as assinaturas (mesma simplificação de UploadCrossSigningKeys)
func (s *KeysService) UploadSignatures(ctx context.Context, requested map[string]map[string]json.RawMessage) UploadSignaturesResult {
	result := UploadSignaturesResult{Failures: make(map[string]map[string]any)}

	fail := func(userID, keyID, errcode, message string) {
		if result.Failures[userID] == nil {
			result.Failures[userID] = make(map[string]any)
		}
		result.Failures[userID][keyID] = map[string]string{"errcode": errcode, "error": message}
	}

	for userID, keys := range requested {
		if util.ExtractDomainFromUserID(userID) != s.serverName {
			for keyID := range keys {
				fail(userID, keyID, "M_NOT_FOUND", "Cannot sign keys of remote users")
			}
			continue
		}

		for keyID, signedObj := range keys {
			var parsed struct {
				Signatures json.RawMessage `json:"signatures"`
			}
			if err := json.Unmarshal(signedObj, &parsed); err != nil || len(parsed.Signatures) == 0 {
				fail(userID, keyID, "M_INVALID_SIGNATURE", "Missing or invalid signatures in signed object")
				continue
			}

			found, err := s.keysStore.MergeDeviceSignatures(ctx, userID, keyID, parsed.Signatures)
			if err != nil {
				log.Printf("[ERROR] UploadSignatures (device user=%s key=%s): %v", userID, keyID, err)
				fail(userID, keyID, "M_UNKNOWN", "Failed to store signature")
				continue
			}
			if found {
				continue
			}

			found, err = s.keysStore.MergeCrossSigningSignatures(ctx, userID, keyID, parsed.Signatures)
			if err != nil {
				log.Printf("[ERROR] UploadSignatures (cross-signing user=%s key=%s): %v", userID, keyID, err)
				fail(userID, keyID, "M_UNKNOWN", "Failed to store signature")
				continue
			}
			if !found {
				fail(userID, keyID, "M_NOT_FOUND", "Unknown key")
			}
		}
	}

	return result
}
