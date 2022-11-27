package mysql

import (
	"database/sql"
	"errors"

	"github.com/dazai404/artem-k/internal/api/models"
	_ "github.com/go-sql-driver/mysql"
)

type MySQLRepo struct {
	db *sql.DB
}

func NewMySQLRepo() (*MySQLRepo, error) {
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/gin_shop?parseTime=true")
	if err != nil {
		return nil, err
	}
	err = db.Ping()
	return &MySQLRepo{db: db}, err
}

func (m *MySQLRepo) SaveUser(u *models.User) (err error) {
	if u == nil {
		return errors.New("user is nil")
	}
	_, err = m.db.Exec("INSERT INTO users (login, password_hash, role) VALUES (?, ?, ?)", u.Login, u.PasswordHash, u.Role)
	return err
}

func (m *MySQLRepo) GetUser(login string) (*models.User, error) {
	if login == "" {
		return nil, errors.New("login must not be empty")
	}
	res := m.db.QueryRow("SELECT * FROM users WHERE login = ?", login)
	user := &models.User{}
	err := res.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Role)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (m *MySQLRepo) Close() error {
	return m.db.Close()
}

func (m *MySQLRepo) SetSession(s *models.Session) error {
	_, err := m.db.Exec("INSERT INTO sessions (session, user_id, expires_at) VALUES (?, ?, ?)", s.SessionToken, s.UserID, s.Expiry)
	return err
}

func (m *MySQLRepo) GetSession(sessionToken string) (*models.Session, error) {
	if sessionToken == "" {
		return nil, errors.New("empty session")
	}
	res := m.db.QueryRow("SELECT * FROM sessions WHERE session = ?", sessionToken)
	session := &models.Session{}
	err := res.Scan(&session.SessionToken, &session.UserID, &session.Expiry)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (m *MySQLRepo) DeleteSession(sessionToken string) error {
	_, err := m.db.Exec("DELETE FROM sessions WHERE session = ?", sessionToken)
	return err
}
