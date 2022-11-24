package repository

import "github.com/dazai404/artem-k/internal/api/models"

type Repository interface {
	SaveUser(u *models.User) error
	GetUser(login string) (*models.User, error)
}