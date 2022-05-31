package repository

import (
	models "go-jwt/model"
)

type UserRepo interface {
	FindUserByEmail(name string) (models.User, error)
	CheckLoginInfo(name string) (models.User, error)
	Insert(u models.User) error
}
