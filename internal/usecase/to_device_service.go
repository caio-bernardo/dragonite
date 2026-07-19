package usecase

import (
	"context"
	"encoding/json"
	"log"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// ToDeviceService contém a lógica de mensagens send-to-device: sinalização E2EE ponto-a-ponto
// que não é persistida no DAG da sala (ex: troca de sessões Olm)
type ToDeviceService struct {
	store      ToDeviceStorage
	keysStore  KeysStorage // usado só pra expandir device_id "*" nos dispositivos conhecidos do usuário
	federation *FederationService
	serverName string
}

func NewToDeviceService(store ToDeviceStorage, keysStore KeysStorage, federation *FederationService, serverName string) *ToDeviceService {
	return &ToDeviceService{store: store, keysStore: keysStore, federation: federation, serverName: serverName}
}

// SendParams agrupa os dados de PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
type SendParams struct {
	Sender    string
	EventType string
	Messages  map[string]map[string]json.RawMessage // userID -> deviceID (ou "*") -> content
}

// Send entrega localmente (ou repassa via federação, se remoto) as mensagens pedidas por um cliente local
func (s *ToDeviceService) Send(ctx context.Context, params SendParams) error {
	var pending []domain.ToDeviceMessage
	remoteByServer := make(map[string]map[string]map[string]json.RawMessage) // server -> userID -> deviceID -> content

	for userID, devices := range params.Messages {
		domainName := util.ExtractDomainFromUserID(userID)

		if domainName != s.serverName {
			if remoteByServer[domainName] == nil {
				remoteByServer[domainName] = make(map[string]map[string]json.RawMessage)
			}
			if remoteByServer[domainName][userID] == nil {
				remoteByServer[domainName][userID] = make(map[string]json.RawMessage)
			}
			for deviceID, content := range devices {
				remoteByServer[domainName][userID][deviceID] = content
			}
			continue
		}

		for deviceID, content := range devices {
			targetDevices := []string{deviceID}
			if deviceID == "*" {
				keys, err := s.keysStore.GetDeviceKeys(ctx, userID, nil)
				if err != nil {
					log.Printf("[ERROR] ToDeviceService.Send: failed to expand '*' for user %s: %v", userID, err)
					continue
				}
				targetDevices = make([]string, len(keys))
				for i, k := range keys {
					targetDevices[i] = k.DispositivoID
				}
			}
			for _, devID := range targetDevices {
				pending = append(pending, domain.ToDeviceMessage{
					UserID:   userID,
					DeviceID: devID,
					Sender:   params.Sender,
					Type:     params.EventType,
					Content:  content,
				})
			}
		}
	}

	if len(pending) > 0 {
		if err := s.store.InsertToDeviceMessages(ctx, pending); err != nil {
			return types.InternalError(err)
		}
	}

	// Envio federado, best-effort: não bloqueia nem falha a resposta ao cliente
	for server, messages := range remoteByServer {
		go s.federation.SendToDeviceCall(context.WithoutCancel(ctx), server, params.Sender, params.EventType, messages)
	}

	return nil
}

// DeliverFromFederation insere localmente as mensagens send-to-device recebidas de um servidor
// remoto via EDU m.direct_to_device. Usuários/dispositivos que não são locais são ignorados
func (s *ToDeviceService) DeliverFromFederation(ctx context.Context, sender, eventType string, messages map[string]map[string]json.RawMessage) error {
	var pending []domain.ToDeviceMessage
	for userID, devices := range messages {
		if util.ExtractDomainFromUserID(userID) != s.serverName {
			continue
		}
		for deviceID, content := range devices {
			pending = append(pending, domain.ToDeviceMessage{
				UserID:   userID,
				DeviceID: deviceID,
				Sender:   sender,
				Type:     eventType,
				Content:  content,
			})
		}
	}
	if len(pending) == 0 {
		return nil
	}
	return s.store.InsertToDeviceMessages(ctx, pending)
}
