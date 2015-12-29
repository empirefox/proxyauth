package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/empirefox/gin-oauth2"
	"github.com/empirefox/ic-server-conductor/proxy"
	"github.com/gin-gonic/gin"
)

func init() {
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()
}

func TestTransport_newProxyToken(t *testing.T) {
	key := []byte("sk")
	tp := &Transport{AuthAlg: "HS256", SkProxy: key}
	tokStr, err := tp.newProxyToken()
	if err != nil {
		t.Errorf("should not get err: %v\n", err)
	}
	tok, err := jwt.Parse(tokStr, func(*jwt.Token) (interface{}, error) { return key, nil })
	if err != nil {
		t.Errorf("should not get err: %v\n", err)
	}
	if !tok.Valid {
		t.Errorf("should get a valid token\n")
	}
}

func newProvidersBytes() []byte {
	return []byte(`[{
		"Name":"github",
		"Path":"p",
		"ClientID":"cid",
		"ClientSecret":"cs"
	}]`)
}

func TestServer_initProviders(t *testing.T) {
	key := []byte("sk_ip")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/ps" {
			t.Errorf("Unexpected providers request URL, %v is found.\n", r.URL)
		}
		if r.Method != "GET" {
			t.Errorf("Expected GET method\n")
		}
		tok, err := jwt.ParseFromRequest(r, func(*jwt.Token) (interface{}, error) { return key, nil })
		if err != nil {
			t.Errorf("should not get err: %v\n", err)
		}
		if !tok.Valid {
			t.Errorf("should get a valid token\n")
		}
		w.WriteHeader(http.StatusOK)
		w.Write(newProvidersBytes())
	}))
	defer ts.Close()

	s := &Server{
		Origins:      "*",
		BaseServer:   ts.URL,
		PostInfoPath: "/pt",
		GetPrdsPath:  "/ps",
		SkProxy:      key,
		AuthAlg:      "HS256",
	}

	s.initHttpClient()
	s.initGoauthConfig()
	defer func() {
		if err := recover(); err != nil {
			t.Errorf("should not panic, but got: %v\n", err)
		}
	}()
	s.initProviders()

	if len(s.GoauthConfig.Providers) != 1 {
		t.Errorf("should init one provider, but got %d\n", len(s.GoauthConfig.Providers))
	}

	if s.GoauthConfig.Providers["p"].Name != "github" {
		t.Errorf("should init corect provider name, but got '%s'\n", s.GoauthConfig.Providers["p"].Name)
	}
}

type ginWriter struct {
	*httptest.ResponseRecorder
}

func (w *ginWriter) WriteHeaderNow()                              {}
func (w *ginWriter) WriteString(s string) (n int, err error)      { return 0, nil }
func (w *ginWriter) Written() bool                                { return true }
func (w *ginWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, nil }
func (w *ginWriter) CloseNotify() <-chan bool                     { return nil }
func (w *ginWriter) Flush()                                       {}
func (w *ginWriter) Status() int                                  { return 0 }
func (w *ginWriter) Size() int                                    { return 0 }

func TestServer_handleUserInfo_handler(t *testing.T) {
	key := []byte("sk_token")
	targetTokenString := "target_token"
	clientTokenString := "client_token"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/pt" {
			t.Errorf("Unexpected providers request URL, %v is found.\n", r.URL)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST method\n")
		}
		proxyAuth := r.Header.Get("Authorization")
		if !strings.HasPrefix(proxyAuth, "BEARER ") {
			t.Errorf("should auth with proxy token first, but got %s\n", proxyAuth)
		}
		var data proxy.PostProxyTokenData
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Errorf("should decode token/info data, but got err: %v\n", err)
		}
		if data.Token != clientTokenString {
			t.Errorf("should get token from client, but got: %s\n", data.Token)
		}
		if data.Info.Name != "user1" {
			t.Errorf("should get right info name, but got %s\n", data.Info.Name)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(targetTokenString))
	}))
	defer ts.Close()

	s := &Server{
		Origins:      "*",
		BaseServer:   ts.URL,
		PostInfoPath: "/pt",
		GetPrdsPath:  "/ps",
		SkProxy:      key,
		AuthAlg:      "HS256",
	}

	s.initHttpClient()
	s.initGoauthConfig()
	s.GoauthConfig.AddProvider("github", "/auth/github", "id", "sec")
	s.initRouter()

	payload := bytes.NewReader([]byte(`{"code":"any_code"}`))
	req, err := http.NewRequest("POST", "/auth/github", payload)
	if err != nil {
		t.Errorf("should create new req ok, but got: %v\n", err)
	}
	req.Header.Set("Authorization", "BEARER "+clientTokenString)

	w := httptest.NewRecorder()

	c := &gin.Context{
		Request: req,
		Writer:  &ginWriter{w},
	}

	info := &goauth.UserInfo{
		Provider: "github",
		Oid:      "oid",
		Name:     "user1",
		Picture:  "pic1",
	}

	if err = s.handleUserInfo(c, info); err != nil {
		t.Errorf("should handle user info ok, but got: %v\n", err)
	}

	body := w.Body.String()
	if body != targetTokenString {
		t.Errorf("should response token from target, but got %s\n", body)
	}
}
