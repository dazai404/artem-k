package models

import "time"

type Order struct {
	Id int `json:"id"`
	Data string `json:"data"`
	CreatedAt time.Time `json:"created_at"`
	User *User
}