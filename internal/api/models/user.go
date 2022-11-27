package models

type User struct {
	ID           int    `json:"id"`
	Login        string `json:"login"`
	PasswordHash []byte `json:"password_hash"`
	Role         string `json:"role"`
}
