package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/dazai404/artem-k/internal/api/models"
	"github.com/dazai404/artem-k/internal/api/repository"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type API struct {
	Router *mux.Router
	Repo repository.Repository
}

func NewAPI(repo repository.Repository) *API {
	api := &API{
		Router: mux.NewRouter(),
		Repo: repo,
	}
	auth := api.Router.Methods(http.MethodPost).Subrouter()
	auth.HandleFunc("/api/auth/signup", api.SignUpHandlerPOST)
	auth.HandleFunc("/api/auth/login", api.LogInHandlerPOST)
	return api
}

func (api *API) Run() error {
    log.Println("Server has been started on port :8080")
	return http.ListenAndServe(":8080", api.Router)
}

func (api *API) SignUpHandlerPOST(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "must be POST method", http.StatusBadRequest)
		return
	}
	input := &models.InputUser{}
	err := json.NewDecoder(r.Body).Decode(input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if input.Role != models.RoleManager && input.Role != models.RoleConsumer {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	user := &models.User{
		Login: input.Login,
		PasswordHash: hash,
		Role: input.Role,
	}
	err = api.Repo.SaveUser(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	output := &models.OutputMessage{Message: "success"}
	jsonMessage, err := json.Marshal(output)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Write(jsonMessage)
}

func (api *API) LogInHandlerPOST(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "must be POST method", http.StatusBadRequest)
		return
	}
	input := &models.InputUser{}
	err := json.NewDecoder(r.Body).Decode(input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user, err := api.Repo.GetUser(input.Login)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(fmt.Sprintf("%s, you are successefully logged in now!", user.Login)))
}

func (api *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := &models.InputUser{}
		err := json.NewDecoder(r.Body).Decode(input)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if input.Role != models.RoleManager && input.Role != models.RoleConsumer {
			http.Error(w, "Invalid role", http.StatusBadRequest)
			return
		}
		user, err := api.Repo.GetUser(input.Login)
		if err != nil {
			http.Error(w, "Invalid user", http.StatusInternalServerError)
		}
		err = bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(input.Password))
		if err != nil {
			http.Error(w, "Invalid password", http.StatusBadRequest)
			return
		}
		log.Printf("%s has been successefully authorized",user.Login)
		next.ServeHTTP(w, r)
	})
}