package models

type InputUser struct {
	ID int `json:"id"`
	Login string `json:"login"`
	Password string `json:"password"`
	Role string `json:"role"`
}

type User struct {
	ID int `json:"id"`
	Login string `json:"login"`
	PasswordHash []byte `json:"password_hash"`
	Role string `json:"role"`
}