package main

import (
	"log"

	"github.com/dazai404/artem-k/internal/api"
	"github.com/dazai404/artem-k/internal/api/repository"
)

func main()  {
	db, err := repository.NewMySQLRepo()
	if err != nil {
		log.Fatal(err)
	}
    defer db.Close()
	api := api.NewAPI(db)
    log.Fatal(api.Run())
}