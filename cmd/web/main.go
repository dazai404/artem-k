package main

import (
	"github.com/dazai404/artem-k/internal/api/repository/mysql"
	"log"

	"github.com/dazai404/artem-k/internal/api"
)

func main() {
	db, err := mysql.NewMySQLRepo()
	if err != nil {
		log.Fatal(err)
	}
	app := api.NewAPI(db)
	defer app.CloseDB(db)
	log.Fatal(app.Run())
}
