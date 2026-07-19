package redis_infra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/usecase"
	"github.com/redis/go-redis/v9"
)

const (
	retryKeyPrefix   = "dragonite:fed:retries:"
	outboundQueueKey = "dragonite:fed:outbound_queue"
)

type federationCacheRepo struct {
	client *redis.Client
}

func NewFederationCacheRepo(client *redis.Client) usecase.FederationCacheStorage {
	return &federationCacheRepo{
		client: client,
	}
}

// SavePendingRetry adiciona o evento ao final da lista de retries de um servidor remoto.
func (r *federationCacheRepo) SavePendingRetry(ctx context.Context, destServer string, event *domain.Evento, ttl time.Duration) error {
	key := fmt.Sprintf("%s%s", retryKeyPrefix, destServer)

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event for redis: %w", err)
	}

	// Usamos Pipeline para garantir que o RPUSH e o EXPIRE sejam executados na mesma viagem de rede
	pipe := r.client.Pipeline()
	pipe.RPush(ctx, key, data)
	if ttl > 0 {
		pipe.Expire(ctx, key, ttl)
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("redis pipeline failed on SavePendingRetry: %w", err)
	}

	return nil
}

// GetAndClearPendingRetries usa uma transação (TxPipeline) para ler e deletar a fila de uma só vez.
func (r *federationCacheRepo) GetAndClearPendingRetries(ctx context.Context, destServer string) ([]domain.Evento, error) {
	key := fmt.Sprintf("%s%s", retryKeyPrefix, destServer)

	// Executa LRANGE e DEL de forma atômica
	pipe := r.client.TxPipeline()
	lrangeCmd := pipe.LRange(ctx, key, 0, -1)
	pipe.Del(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("redis tx failed on GetAndClearPendingRetries: %w", err)
	}

	rawEvents, err := lrangeCmd.Result()
	if err != nil || len(rawEvents) == 0 {
		return []domain.Evento{}, nil
	}

	events := make([]domain.Evento, 0, len(rawEvents))
	for _, raw := range rawEvents {
		var ev domain.Evento
		if err := json.Unmarshal([]byte(raw), &ev); err == nil {
			events = append(events, ev)
		}
	}

	return events, nil
}

// PushOutboundQueue adiciona um evento na fila geral de saída.
func (r *federationCacheRepo) PushOutboundQueue(ctx context.Context, event domain.Evento) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event for outbound queue: %w", err)
	}

	if err := r.client.RPush(ctx, outboundQueueKey, data).Err(); err != nil {
		return fmt.Errorf("failed to push to redis outbound queue: %w", err)
	}

	return nil
}

// PopOutboundQueue remove o primeiro item da fila. Usa BLPOP para bloquear até que um evento chegue.
func (r *federationCacheRepo) PopOutboundQueue(ctx context.Context, timeout time.Duration) (*domain.Evento, error) {
	result, err := r.client.BLPop(ctx, timeout, outboundQueueKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil // Timeout atingido, fila vazia
		}
		return nil, fmt.Errorf("redis BLPOP failed: %w", err)
	}

	// BLPop retorna um slice de 2 posições: [nome_da_chave, valor]
	if len(result) < 2 {
		return nil, nil
	}

	var ev domain.Evento
	if err := json.Unmarshal([]byte(result[1]), &ev); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event from queue: %w", err)
	}

	return &ev, nil
}
