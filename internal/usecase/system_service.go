package usecase

type SystemStorage interface {
	PingDB() map[string]string
}

type HealthService struct {
	storage SystemStorage
}

func NewHealthService(storage SystemStorage) *HealthService {
	return &HealthService{storage: storage}
}

func (h *HealthService) PingDB() map[string]string {
	return h.storage.PingDB()
}
