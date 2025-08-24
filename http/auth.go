package http

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"

	fbErrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/users"
)

const (
	DefaultTokenExpirationTime = time.Hour * 2
)

type userInfo struct {
	ID           uint              `json:"id"`
	Locale       string            `json:"locale"`
	ViewMode     users.ViewMode    `json:"viewMode"`
	SingleClick  bool              `json:"singleClick"`
	Perm         users.Permissions `json:"perm"`
	Commands     []string          `json:"commands"`
	LockPassword bool              `json:"lockPassword"`
	HideDotfiles bool              `json:"hideDotfiles"`
	DateFormat   bool              `json:"dateFormat"`
	Username     string            `json:"username"`
}

type authToken struct {
	User userInfo `json:"user"`
	jwt.RegisteredClaims
}

type extractor []string

func (e extractor) ExtractToken(r *http.Request) (string, error) {
	token, _ := request.HeaderExtractor{"X-Auth"}.ExtractToken(r)

	// Checks if the token isn't empty and if it contains two dots.
	// The former prevents incompatibility with URLs that previously
	// used basic auth.
	if token != "" && strings.Count(token, ".") == 2 {
		return token, nil
	}

	auth := r.URL.Query().Get("auth")
	if auth != "" && strings.Count(auth, ".") == 2 {
		return auth, nil
	}

	if r.Method == http.MethodGet {
		cookie, _ := r.Cookie("auth")
		if cookie != nil && strings.Count(cookie.Value, ".") == 2 {
			return cookie.Value, nil
		}
	}

	return "", request.ErrNoTokenInRequest
}

func withUser(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		keyFunc := func(_ *jwt.Token) (interface{}, error) {
			return d.settings.Key, nil
		}

		var tk authToken
		token, err := request.ParseFromRequest(r, &extractor{}, keyFunc, request.WithClaims(&tk))

		if err != nil || !token.Valid {
			return http.StatusUnauthorized, nil
		}

		expired := !tk.VerifyExpiresAt(time.Now().Add(time.Hour), true)
		updated := tk.IssuedAt != nil && tk.IssuedAt.Unix() < d.store.Users.LastUpdate(tk.User.ID)

		if expired || updated {
			w.Header().Add("X-Renew-Token", "true")
		}

		d.user, err = d.store.Users.Get(d.server.Root, tk.User.ID)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		return fn(w, r, d)
	}
}

func withAdmin(fn handleFunc) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		return fn(w, r, d)
	})
}

func loginHandler(tokenExpireTime time.Duration) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		auther, err := d.store.Auth.Get(d.settings.AuthMethod)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		user, err := auther.Auth(r, d.store.Users, d.settings, d.server)
		switch {
		case errors.Is(err, os.ErrPermission):
			return http.StatusForbidden, nil
		case err != nil:
			return http.StatusInternalServerError, err
		}

		return printToken(w, r, d, user, tokenExpireTime)
	}
}

// fastLoginHandler authenticates a user using credentials provided via
// URL query parameters. It performs constant-time password comparison and
// returns a JWT token if the credentials are valid. Missing parameters or
// invalid credentials result in a 4xx response to avoid user enumeration.
// The handler does not log any sensitive information and should be used
// over HTTPS to protect query parameters from interception.
func fastLoginHandler(tokenExpireTime time.Duration) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		username := r.URL.Query().Get("user")
		password := r.URL.Query().Get("password")
		if username == "" || password == "" {
			return http.StatusBadRequest, nil
		}

		u, err := d.store.Users.Get(d.server.Root, username)
		if err != nil {
			if errors.Is(err, fbErrors.ErrNotExist) {
				return http.StatusForbidden, nil
			}
			return http.StatusInternalServerError, err
		}

		if !users.CheckPwd(password, u.Password) {
			return http.StatusForbidden, nil
		}

		// Version finale (master) : renvoyer simplement le token en clair.
		return printToken(w, r, d, u, tokenExpireTime)
	}
}

type signupBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var signupHandler = func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if !d.settings.Signup {
		return http.StatusMethodNotAllowed, nil
	}

	if r.Body == nil {
		return http.StatusBadRequest, nil
	}

	info := &signupBody{}
	err := json.NewDecoder(r.Body).Decode(info)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if info.Password == "" || info.Username == "" {
		return http.StatusBadRequest, nil
	}

	user := &users.User{
		Username: info.Username,
	}

	d.settings.Defaults.Apply(user)

	pwd, err := users.ValidateAndHashPwd(info.Password, d.settings.MinimumPasswordLength)
	if err != nil {
		return http.StatusBadRequest, err
	}

	user.Password = pwd
	if d.settings.CreateUserDir {
		user.Scope = ""
	}

	userHome, err := d.settings.MakeUserDir(user.Username, user.Scope, d.server.Root)
	if err != nil {
		log.Printf("create user: failed to mkdir user home dir: [%s]", userHome)
		return http.StatusInternalServerError, err
	}
	user.Scope = userHome
	log.Printf("new user: %s, home dir: [%s].", user.Username, userHome)

	err = d.store.Users.Save(user)
	if errors.Is(err, fbErrors.ErrExist) {
		return http.StatusConflict, err
	} else if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func renewHandler(tokenExpireTime time.Duration) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		w.Header().Set("X-Renew-Token", "false")
		return printToken(w, r, d, d.user, tokenExpireTime)
	})
}

func issueToken(user *users.User, key []byte, tokenExpirationTime time.Duration) (string, error) {
	claims := &authToken{
		User: userInfo{
			ID:           user.ID,
			Locale:       user.Locale,
			ViewMode:     user.ViewMode,
			SingleClick:  user.SingleClick,
			Perm:         user.Perm,
			LockPassword: user.LockPassword,
			Commands:     user.Commands,
			HideDotfiles: user.HideDotfiles,
			DateFormat:   user.DateFormat,
			Username:     user.Username,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpirationTime)),
			Issuer:    "File Browser",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

func printToken(w http.ResponseWriter, _ *http.Request, d *data, user *users.User, tokenExpirationTime time.Duration) (int, error) {
	signed, err := issueToken(user, d.settings.Key, tokenExpirationTime)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(signed)); err != nil {
		return http.StatusInternalServerError, err
	}
	return 0, nil
}
