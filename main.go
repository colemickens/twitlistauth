package main

import (
	"encoding/json"
	"flag"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/mrjones/oauth"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type TwitlistauthConfig struct {
	AppId         string `json:"app_id"`
	AppSecret     string `json:"app_secret"`
	Hostname      string `json:"hostname"`
	SecretGroupId string `json:"secret_group_id"`
	ServeRoot     string `json:"serve_root"`
	InternalPort  int    `json:"internal_port"`
	SessionSecret string `json:"session_secret"`
}

var CONFIG TwitlistauthConfig

var tokens map[string]*oauth.RequestToken
var store *sessions.CookieStore
var SESSION_NAME = "session-name"
var COOKIE_HAS_AUTH = "hasAuth"

var FACEBOOK_AUTH_CALLBACK_ROUTE = "/auth/login/twitter/callback"
var consumer *oauth.Consumer

func init() {
	tokens = make(map[string]*oauth.RequestToken)

	var configFile = flag.String("config", "./twitlistauth.config", "config file location")
	flag.Parse()
	log.Println("reading config from:", *configFile)
	file, err := os.Open(*configFile)
	if err != nil {
		panic(err)
	}
	decoder := json.NewDecoder(file)
	decoder.Decode(&CONFIG)

	log.Println(CONFIG)

	if CONFIG.SessionSecret == "" {
		panic("SessionSecret should never be empty")
	}
	store = sessions.NewCookieStore([]byte(CONFIG.SessionSecret))

	consumer = oauth.NewConsumer(
		CONFIG.AppId,
		CONFIG.AppSecret,
		oauth.ServiceProvider{
			RequestTokenUrl:   "https://api.twitter.com/oauth/request_token",
			AuthorizeTokenUrl: "https://api.twitter.com/oauth/authorize",
			AccessTokenUrl:    "https://api.twitter.com/oauth/access_token",
		},
	)
}

func handleFiles(prefix string) http.Handler {
	fs := http.FileServer(http.Dir(CONFIG.ServeRoot))
	return http.StripPrefix(prefix, fs)
}

func requireAuth(innerHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, SESSION_NAME)
		v, ok := session.Values[COOKIE_HAS_AUTH]
		if ok && v.(bool) {
			innerHandler.ServeHTTP(w, r)
		} else {
			w.WriteHeader(403)
			serveString("You're not logged in, login first").ServeHTTP(w, r)
		}
	})
}

func promptFacebookLogin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callback := "http://" + CONFIG.Hostname + FACEBOOK_AUTH_CALLBACK_ROUTE
		token, requestUrl, err := consumer.GetRequestTokenAndUrl(callback)
		if err != nil {
			log.Fatal(err)
		}

		tokens[token.Token] = token
		http.Redirect(w, r, requestUrl, http.StatusTemporaryRedirect)
	})
}

func isUserAllowed(accessToken *oauth.AccessToken) (bool, error) {
	resp, err := consumer.Get(
		"https://api.twitter.com/1.1/account/verify_credentials.json",
		map[string]string {},
		accessToken)

	if err != nil {
		return false, err
	}
	
	var result map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&result)
	resp.Body.Close()

	userId := result["id"].(float64)
	log.Println("read a user id")

	resp, err = consumer.Get(
		"https://api.twitter.com/1.1/lists/members.json",
		map[string]string {"slug": "files-mickens-io-users", "owner_screen_name": "colemickens"},
		accessToken)

	if err != nil {
		return false, err
	}

	decoder = json.NewDecoder(resp.Body)
	decoder.Decode(&result)
	resp.Body.Close()

	userList := result["users"].([]interface{})
	for _, user := range userList {
		curUserId := user.(map[string]interface{})["id"].(float64)
		log.Println("found user id in list", curUserId)
		if curUserId == userId {
			return true, nil
		}
	}

	// TODO(@colemickens): read pages of ids? Gross...

	return false, nil
}

func handleFacebookAuth() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifier := r.FormValue("oauth_verifier")
		tokenKey := r.FormValue("oauth_token")

		accessToken, err := consumer.AuthorizeToken(tokens[tokenKey], verifier)
		if err != nil {
			log.Fatal(err)
		}

		allowed, err := isUserAllowed(accessToken)
		if err != nil {
			// TODO(@colemickens): handle this better
			log.Fatal(err)
		}

		if allowed {
			login(w, r)
		} else {
			logout(w, r)
		}

		http.Redirect(w, r, "/", 301)
	})
}

func handleLogout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logout(w, r)
		http.Redirect(w, r, "/", 301)
	})
}

func serveString(message string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isLoggedInStr := "yes!"
		if !isLoggedIn(r) {
			isLoggedInStr = "No!"
		}
		contents := strings.Replace(CONTENTS, "[[[LOGGED IN]]]", isLoggedInStr, 1)
		contents = strings.Replace(contents, "[[[MESSAGE]]]", message, 1)
		w.Write([]byte(contents))
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, SESSION_NAME)
	session.Values[COOKIE_HAS_AUTH] = true
	session.Save(r, w)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, SESSION_NAME)
	session.Values[COOKIE_HAS_AUTH] = false
	session.Save(r, w)
}

func isLoggedIn(r *http.Request) bool {
	session, _ := store.Get(r, SESSION_NAME)
	authd, ok := session.Values[COOKIE_HAS_AUTH]
	if ok && authd.(bool) {
		return true
	}
	return false
}

func main() {
	http.Handle(FACEBOOK_AUTH_CALLBACK_ROUTE, handleFacebookAuth())
	http.Handle("/auth/login", promptFacebookLogin())
	http.Handle("/auth/logout", handleLogout())

	FILES_PREFIX := "/files/"
	http.Handle(FILES_PREFIX, requireAuth(handleFiles(FILES_PREFIX)))

	http.Handle("/", serveString(""))

	err := http.ListenAndServe(":"+strconv.Itoa(CONFIG.InternalPort), context.ClearHandler(http.DefaultServeMux))
	if err != nil {
		panic(err)
	}
}

const CONTENTS = `
<html>
<head></head>
<body>
<p>Message: [[[MESSAGE]]]</p>
<p>Logged in? [[[LOGGED IN]]] </p>
<ul>
<li><a href="/auth/login">login</a><br/></li>
<li><a href="/auth/logout">logout</a></li>
<li><a href="/files">files</a><br/></li>
</ul>
</body>
</html>
`
