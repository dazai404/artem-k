package repository

import "github.com/dazai404/artem-k/internal/api/models"

type Repository interface {
	Close() error

	SaveUser(u *models.User) error
	GetUser(login string) (*models.User, error)

	SetSession(s *models.Session) error
	GetSession(sessionToken string) (*models.Session, error)
	DeleteSession(sessionToken string) error
}
