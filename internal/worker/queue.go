package worker

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/caio-bernardo/dragonite/internal/types"
)

const CHANNEL_SIZE int = 128

type JobType string

const (
	EDU JobType = "EDU"
	PDU JobType = "PDU"
)

type Job struct {
	Dest    string
	Type    JobType
	TxnID   string
	Payload []byte
}

type WorkerQueue struct {
	mu      sync.RWMutex
	workers map[string]chan Job // TODO: substituir isso pelo Postgres Queue
	ctx     context.Context
	config  types.ServerConfig
}

// Cria nova Worker Queue
func NewWorkerQueue(ctx context.Context, config types.ServerConfig) *WorkerQueue {
	return &WorkerQueue{
		workers: make(map[string]chan Job),
		ctx:     ctx,
		config:  config,
	}
}

// Enfila uma nova tarefa
func (wq *WorkerQueue) Push(job Job) {
	wq.mu.Lock()
	defer wq.mu.Unlock()

	ch, exists := wq.workers[job.Dest]
	if !exists {
		ch = make(chan Job, CHANNEL_SIZE)
		wq.workers[job.Dest] = ch

		go wq.runWorker(job.Dest, ch)
	}

	select {
	case ch <- job:
	default:
		log.Printf("Queue is full, dropping job %s", job.Dest)
	}
}

func (wq *WorkerQueue) runWorker(dest string, ch <-chan Job) {
	log.Printf("Start worker for %s", dest)

	const maxBatchSize = 50
	const maxWaitTime = 500 * time.Millisecond

	var batch []Job
	timer := time.NewTimer(maxWaitTime)
	if !timer.Stop() {
		<-timer.C
	}

	for {
		select {
		case <-wq.ctx.Done():
			log.Printf("Shutting down worker for %s", dest)
			if len(batch) > 0 {
				wq.trySendBatch(dest, batch)
			}
			return
		case job := <-ch:
			batch = append(batch, job)

			if len(batch) == 1 {
				timer.Reset(maxWaitTime)
			}

			if len(batch) >= maxBatchSize {
				if !timer.Stop() {
					<-timer.C
				}

				wq.trySendBatch(dest, batch)
				batch = nil
			}
		case <-timer.C:
			if len(batch) > 0 {
				wq.trySendBatch(dest, batch)
				batch = nil
			}
		}
	}
}

func (wq *WorkerQueue) trySendBatch(dest string, batch []Job) {
	// Tenta enviar a requisição mais de uma vez caso ela falhe
	maxRetries := 5
	backoff := 2 * time.Second

	for range maxRetries {
		err := wq.sendBatchRequest(dest, batch)
		if err == nil {
			return
		}

		select {
		case <-time.After(backoff):
			backoff *= 2 // falha => tenta depois
		case <-wq.ctx.Done():
			return // timeout => parar
		}
	}

	log.Printf("Failed to send job %s after %d attempts", dest, maxRetries)
}

func (wq *WorkerQueue) sendBatchRequest(dest string, batch []Job) error {
	txn := NewTransaction(wq.config.ServerName, batch)
	txnID := fmt.Sprintf("%d", time.Now().UnixNano())
	return sendTransaction(dest, txnID, txn, wq.config.ServerName, wq.config.KeyID, wq.config.PrivateKey)
}
