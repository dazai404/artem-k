package models

import "time"

type Session struct {
	SessionToken string    `json:"session_token"`
	UserID       int       `json:"user_id"`
	Expiry       time.Time `json:"expiry"`
}

func (s Session) IsExpired() bool {
	return s.Expiry.Before(time.Now())
}
