package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID   primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"` // tag golang
	Name string             `json:"name" bson:"name"`
}
