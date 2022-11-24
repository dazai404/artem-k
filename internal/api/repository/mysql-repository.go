package repository

import (
	"database/sql"
	"errors"
    "log"

    "github.com/dazai404/artem-k/internal/api/models"
	_ "github.com/go-sql-driver/mysql"
)

type MySQLRepo struct {
	db *sql.DB
}

func NewMySQLRepo() (*MySQLRepo, error) {
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/gin_shop")
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
	err := m.db.Close()
    if err != nil {
        log.Fatal(err)
    }
    return nil
}