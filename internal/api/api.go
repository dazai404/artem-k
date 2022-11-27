package api

import (
	"encoding/json"
	"fmt"
	"github.com/dazai404/artem-k/internal/api/models"
	"github.com/dazai404/artem-k/internal/api/repository"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

type API struct {
	Router *mux.Router
	Repo   repository.Repository
}

func NewAPI(repo repository.Repository) *API {
	api := &API{
		Router: mux.NewRouter(),
		Repo:   repo,
	}
	auth := api.Router.Methods(http.MethodPost).Subrouter()
	login := auth.Methods(http.MethodPost).Subrouter()
	auth.HandleFunc("/api/auth/signup", api.signUpHandlerPOST)
	login.HandleFunc("/api/auth/login", api.logInHandlerPOST)
	auth.HandleFunc("/api/auth/refresh", api.refreshHandler)
	auth.HandleFunc("/api/auth/check", api.testHandlerGET)
	auth.HandleFunc("/api/auth/logout", api.logoutHandlerPOST)
	login.Use(api.refreshing)
	return api
}

func (api *API) Run() error {
	log.Println("Server has been started on port :8080")
	return http.ListenAndServe(":8080", api.Router)
}

func (api *API) signUpHandlerPOST(w http.ResponseWriter, r *http.Request) {
	var hash, jsonMessage []byte

	if r.Method != "POST" {
		return
	}

	input := &struct {
		Login    string  `json:"login"`
		Password string  `json:"password"`
		Role     *string `json:"role"`
	}{}

	output := &struct {
		Error string `json:"error"`
	}{}

	user := &models.User{}

	err := json.NewDecoder(r.Body).Decode(input)
	if err != nil {
		output.Error = err.Error()
		goto FINISH
	}
	if input.Role == nil || (*input.Role != models.RoleManager && *input.Role != models.RoleConsumer) {
		output.Error = err.Error()
		goto FINISH
	}
	hash, err = bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		output.Error = err.Error()
		goto FINISH
	}
	user = &models.User{
		Login:        input.Login,
		PasswordHash: hash,
		Role:         *input.Role,
	}
	err = api.Repo.SaveUser(user)
	if err != nil {
		output.Error = err.Error()
		goto FINISH
	}
	user, err = api.Repo.GetUser(input.Login)
	if err != nil {
		output.Error = err.Error()
		goto FINISH
	}
	jsonMessage, err = json.Marshal(output)
	if err != nil {
		log.Println(err.Error())
		goto FINISH
	}
FINISH:
	_, err = w.Write(jsonMessage)
	if err != nil {
		log.Println(err.Error())
	}
}

func (api *API) logInHandlerPOST(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "must be POST method", http.StatusBadRequest)
		return
	}

	input := &struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}{}

	output := &struct {
		User         *models.User `json:"user"`
		Error        string       `json:"error"`
		SessionToken string       `json:"session_token"`
	}{}

	err := json.NewDecoder(r.Body).Decode(input)
	if err != nil {
		output.Error = err.Error()
		jsonMessage, err := json.Marshal(output)
		if err != nil {
			log.Println(err.Error())
		}
		_, err = w.Write(jsonMessage)
		if err != nil {
			log.Println(err.Error())
		}
		return
	}

	user, err := api.Repo.GetUser(input.Login)
	if err != nil {
		output.Error = err.Error()
		jsonMessage, err := json.Marshal(output)
		if err != nil {
			log.Println(err.Error())
		}
		_, err = w.Write(jsonMessage)
		if err != nil {
			log.Println(err.Error())
		}
		return
	}

	err = bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(input.Password))
	if err != nil {
		output.Error = "invalid password"
		jsonMessage, err := json.Marshal(output)
		if err != nil {
			log.Println(err.Error())
		}
		_, err = w.Write(jsonMessage)
		if err != nil {
			log.Println(err.Error())
		}
		return
	}

	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(4 * time.Hour)

	session := &models.Session{
		SessionToken: sessionToken,
		UserID:       user.ID,
		Expiry:       expiresAt,
	}

	err = api.Repo.SetSession(session)

	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_cookie",
		Value:   sessionToken,
		Expires: expiresAt,
	})

	output.User = user
	output.SessionToken = sessionToken

	jsonMessage, err := json.Marshal(output)
	if err != nil {
		log.Println(err.Error())
	}

	_, err = w.Write(jsonMessage)
	if err != nil {
		log.Println(err.Error())
	}
}

//func (api *API) authMiddleware(next http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		input := &models.InputUser{}
//		err := json.NewDecoder(r.Body).Decode(input)
//		if err != nil {
//			http.Error(w, err.Error(), http.StatusInternalServerError)
//			return
//		}
//		if input.Role != models.RoleManager && input.Role != models.RoleConsumer {
//			http.Error(w, "Invalid role", http.StatusBadRequest)
//			return
//		}
//		_, user, err := api.Repo.GetUser(input.Login)
//		if err != nil {
//			http.Error(w, "Invalid user", http.StatusInternalServerError)
//		}
//		err = bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(input.Password))
//		if err != nil {
//			http.Error(w, "Invalid password", http.StatusBadRequest)
//			return
//		}
//		log.Printf("%s has been successefully authorized", user.Login)
//		next.ServeHTTP(w, r)
//	})
//}

func (api *API) testHandlerGET(w http.ResponseWriter, r *http.Request) {
	output := &struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}{}
	fmt.Println("123")
	cookie, err := r.Cookie("session_cookie")
	if err != nil {
		output.Error = err.Error()
		jsonMessage, err := json.Marshal(output)
		if err != nil {
			log.Println(err.Error())
		}
		_, err = w.Write(jsonMessage)
		if err != nil {
			log.Println(err.Error())
		}
		return
	}
	fmt.Println("123")
	if err != nil {
		output.Error = err.Error()
		jsonMessage, err := json.Marshal(output)
		if err != nil {
			log.Println(err.Error())
		}
		_, err = w.Write(jsonMessage)
		if err != nil {
			log.Println(err.Error())
		}
		return
	}

	sessionToken := cookie.Value

	fmt.Println(sessionToken)

	session, err := api.Repo.GetSession(sessionToken)
	if err != nil {
		output.Error = err.Error()
		jsonMessage, err := json.Marshal(output)
		if err != nil {
			log.Println(err.Error())
		}
		_, err = w.Write(jsonMessage)
		if err != nil {
			log.Println(err.Error())
		}
		return
	}

	if session.IsExpired() {
		err = api.Repo.DeleteSession(sessionToken)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		output.Error = "session is expired"
		jsonMessage, err := json.Marshal(output)
		if err != nil {
			log.Println(err.Error())
		}
		_, err = w.Write(jsonMessage)
		if err != nil {
			log.Println(err.Error())
		}
		return
	}

	output.Message = fmt.Sprintf("Welcome %d", session.UserID)
	jsonMessage, err := json.Marshal(output)
	if err != nil {
		log.Println(err.Error())
	}
	_, err = w.Write(jsonMessage)
	if err != nil {
		log.Println(err.Error())
	}
}

func (api *API) refreshHandler(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session_cookie")
	if err != nil {
		log.Println(err.Error())
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionToken := cookie.Value

	userSession, err := api.Repo.GetSession(sessionToken)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if userSession.IsExpired() {
		log.Println("session is expired")
		err = api.Repo.DeleteSession(sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	newSessionToken := uuid.NewString()
	expiresAt := time.Now().Add(4 * time.Hour)

	newSession := &models.Session{
		SessionToken: newSessionToken,
		UserID:       userSession.UserID,
		Expiry:       expiresAt,
	}

	err = api.Repo.DeleteSession(sessionToken)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = api.Repo.SetSession(newSession)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   newSessionToken,
		Expires: expiresAt,
	})
}

func (api *API) logoutHandlerPOST(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_cookie")
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	sessionToken := c.Value

	_, err = api.Repo.GetSession(sessionToken)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = api.Repo.DeleteSession(sessionToken)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "",
		Value:   "",
		Expires: time.Now(),
	})
}

func (api *API) refreshing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("session_cookie")
		if err != nil {
			log.Println(err.Error())
			if err == http.ErrNoCookie {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		sessionToken := cookie.Value

		userSession, err := api.Repo.GetSession(sessionToken)
		if err != nil {
			log.Println(err.Error())
			next.ServeHTTP(w, r)
			return
		}

		if userSession.IsExpired() {
			log.Println("session is expired")
			err = api.Repo.DeleteSession(sessionToken)
			if err != nil {
				fmt.Println(err.Error())
			}
			next.ServeHTTP(w, r)
			return
		}

		newSessionToken := uuid.NewString()
		expiresAt := time.Now().Add(4 * time.Hour)

		newSession := &models.Session{
			SessionToken: newSessionToken,
			UserID:       userSession.UserID,
			Expiry:       expiresAt,
		}

		err = api.Repo.DeleteSession(sessionToken)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = api.Repo.SetSession(newSession)
		if err != nil {
			log.Println(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "session_cookie",
			Value:   newSessionToken,
			Expires: expiresAt,
		})
	})
}

func (api *API) CloseDB(db repository.Repository) {
	err := db.Close()
	if err != nil {
		log.Fatal("ERROR: error with closing repository")
	}
	return
}
