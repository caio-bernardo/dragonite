package usecase

import (
	"context"
	"log"
	"strings"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

type FederationClient interface {
	// Assinatura esperada para o client que fará a requisição para fora
	QueryRemoteProfile(ctx context.Context, serverName string, userID string) (*domain.Profile, error)
}

type ProfileService struct {
	userStore              UsuarioStorage
	canalStore             CanalStorage
	roomMembershipService  *RoomMembershipService  
	roomInteractionService *RoomInteractionService 
	fedClient              FederationClient        
	serverName             string                  
}

func NewProfileService(userStore UsuarioStorage, canalStore CanalStorage, roomMembershipService *RoomMembershipService, roomInteractionService *RoomInteractionService, fedClient FederationClient, serverName string) *ProfileService {
	return &ProfileService{
		userStore:              userStore,
		canalStore:             canalStore,
		roomMembershipService:  roomMembershipService,
		roomInteractionService: roomInteractionService,
		fedClient:              fedClient,
		serverName:             serverName,
	}
}

func (p *ProfileService) GetProfileByUserID(ctx context.Context, userID string) (*domain.Profile, error) {
	if userID == "" {
		return nil, types.ErrInvalidUserID
	}

	// CORREÇÃO: Usar SplitN para quebrar a string apenas no primeiro ":"
	// Assim, "@lucas2:localhost:8090" vira ["@lucas2", "localhost:8090"]
	parts := strings.SplitN(userID, ":", 2)
	if len(parts) != 2 {
		return nil, types.ErrInvalidUserID
	}
	userDomain := parts[1]

	// 2. Bifurcação: Local vs Remoto
	if userDomain == p.serverName {
		// Fluxo Local
		profile, err := p.userStore.GetProfileByID(ctx, userID)
		if err != nil {
			return nil, types.ErrNotFound
		}
		if profile == nil {
			return nil, types.ErrNotFound
		}
		return profile, nil
	}

	// 3. Fluxo Remoto: Chamar a federação
	profile, err := p.fedClient.QueryRemoteProfile(ctx, userDomain, userID)
	if err != nil {
		log.Printf("Falha ao buscar profile remoto para %s: %v", userID, err)
		return nil, types.ErrNotFound
	}

	return profile, nil
}

type ProfileParams struct {
	DisplayName *string `json:"displayname,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

func (p *ProfileService) UpdateProfile(ctx context.Context, userID string, props ProfileParams) error {
	if userID == "" {
		return types.ErrInvalidUserID
	}

	profile := domain.Profile{
		IDUsuario:   userID,
		DisplayName: props.DisplayName,
		AvatarURL:   props.AvatarURL,
	}

	err := p.userStore.UpdateProfile(ctx, profile)
	if err != nil {
		return err
	}

	perfilCompleto, err := p.GetProfileByUserID(ctx, userID)
	if err != nil {
    return err
	}

	salas, err := p.roomMembershipService.GetJoinedRooms(ctx, userID) //[cite: 13]
	if err != nil {
    return err
	}

	for _, roomID := range salas {
    // Constrói o conteúdo exigido pelo Element para atualizar a interface
    content := map[string]any{
        "membership":  "join",
        "displayname": perfilCompleto.DisplayName,
        "avatar_url":  perfilCompleto.AvatarURL,
    }

    // Preenche a struct exata que o seu SendStateEvent exige
    params := StateParams{
        RoomID:    roomID,
        UserID:    userID,
        EventType: "m.room.member",
        StateKey:  userID, // O StateKey de um evento de membro deve ser o próprio userID
        Content:   content,
    }

    // Dispara o evento! Essa função já lida com a transação no banco e com a fila de federação
    _, err = p.roomInteractionService.SendStateEvent(ctx, params) //[cite: 12]

    if err != nil {
        // Apenas registre o erro no log, mas não interrompa o loop para não quebrar a sincronização das outras salas
        log.Printf("Erro ao propagar perfil na sala %s: %v", roomID, err)
    }
	}
	return nil
}
