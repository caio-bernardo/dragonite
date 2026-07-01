package minio_infra

import (
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const defaultBucket = "dragonite-media"

// MinioStorage implementa a interface FileStorage usando o MinIO como backend de armazenamento
// Cada arquivo de mídia é armazenado como um objeto, usando o mediaID como chave.
type MinioStorage struct {
	client *minio.Client
	bucket string
}

// NewMinioStorage cria um novo cliente MinIO e retorna um MinioStorage
func NewMinioStorage(endpoint, accessKey, secretKey string, useSSL bool) (*MinioStorage, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	return &MinioStorage{
		client: client,
		bucket: defaultBucket,
	}, nil
}

// EnsureBucket garante que o bucket de mídia existe, criando-o caso contrário
// Deve ser chamado UMA VEZ durante a inicialização da aplicação (em main.go).
func (s *MinioStorage) EnsureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("falha ao verificar existência do bucket '%s': %w", s.bucket, err)
	}

	if !exists {
		if err := s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("failed to create bucket '%s': %w", s.bucket, err)
		}
	}

	return nil
}

// Upload armazena o conteúdo no MinIO usando o mediaID como chave do objeto
// size deve ser o número exato de bytes em content, ou -1 para streaming (menos eficiente)
func (s *MinioStorage) Upload(ctx context.Context, mediaID string, content io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, s.bucket, mediaID, content, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return fmt.Errorf("failed to upload the object '%s': %w", mediaID, err)
	}

	return nil
}

// Download retorna um ReadCloser com o conteúdo do objeto
// O chamador é responsável por fechar o reader
func (s *MinioStorage) Download(ctx context.Context, mediaID string) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, mediaID, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get object '%s': %w", mediaID, err)
	}

	return obj, nil
}

// Delete remove permanentemente o objeto do MinIO
func (s *MinioStorage) Delete(ctx context.Context, mediaID string) error {
	if err := s.client.RemoveObject(ctx, s.bucket, mediaID, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to delete object '%s': %w", mediaID, err)
	}

	return nil
}
