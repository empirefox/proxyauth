package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/empirefox/gin-oauth2"
	"github.com/empirefox/gotool/paas"
	"github.com/empirefox/ic-server-conductor/proxy"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/golang/glog"
	"github.com/itsjamie/gin-cors"
)

func main() {
	flag.Parse()

	s := &Server{
		Origins:      paas.GetEnv("ORIGINS", "*"),
		BaseServer:   os.Getenv("BASE_SERVER"),
		PostInfoPath: "/proxy/token",
		GetPrdsPath:  "/proxy/providers",
		SkProxy:      []byte(os.Getenv("API_SK_PROXY")),
		AuthAlg:      "HS256",
	}

	s.initGoauthConfig()
	s.initHttpClient()
	s.initProviders()
	s.initRouter()

	glog.Fatal(s.Run())
}

func (s *Server) Run() error {
	return s.Router.Run(paas.BindAddr)
}

type Server struct {
	GoauthConfig *goauth.Config
	Origins      string
	BaseServer   string
	PostInfoPath string
	GetPrdsPath  string
	httpClient   *http.Client
	RoundTripper http.RoundTripper
	SkProxy      []byte
	AuthAlg      string
	Router       *gin.Engine
}

func (s *Server) Target(path string) string {
	return s.BaseServer + path
}

func (s *Server) initRouter() {
	s.Router = gin.Default()
	s.Router.GET("/", Ok)

	corsMiddleWare := s.Cors("GET, PUT, POST, DELETE")
	authMiddleWare := goauth.Middleware(s.GoauthConfig)
	for path := range s.GoauthConfig.Providers {
		s.Router.POST(path, corsMiddleWare, authMiddleWare, Ok)
		s.Router.OPTIONS(path, corsMiddleWare, authMiddleWare, Ok)
	}
}

func (s *Server) initProviders() {
	ps, err := s.getProviders()
	if err != nil {
		glog.Fatalln(err)
	}
	for _, p := range ps {
		if err = s.GoauthConfig.AddProvider(p.Name, p.Path, p.ClientID, p.ClientSecret); err != nil {
			glog.Errorln(err)
		}
	}
}

func (s *Server) initHttpClient() {
	tp := &Transport{
		RoundTripper: s.RoundTripper,
		SkProxy:      s.SkProxy,
		AuthAlg:      s.AuthAlg,
	}
	s.httpClient = &http.Client{
		Transport: tp,
	}
}

func (s *Server) Cors(method string) gin.HandlerFunc {
	return cors.Middleware(cors.Config{
		Origins:         s.Origins,
		Methods:         method,
		RequestHeaders:  "Origin, Authorization, Content-Type",
		ExposedHeaders:  "",
		MaxAge:          48 * time.Hour,
		Credentials:     false,
		ValidateHeaders: false,
	})
}

func (s *Server) initGoauthConfig() {
	if paas.IsDevMode {
		goauth.ProviderPresets["mock"] = goauth.ProviderPreset{
			TokenURL:     "http://127.0.0.1:14000/token",
			UserEndpoint: "http://127.0.0.1:14000/info",
			JsonPathOid:  "oid",
			JsonPathName: "name",
			JsonPathPic:  "pic",
		}
	}
	s.GoauthConfig = &goauth.Config{
		Origin:             strings.TrimSpace(strings.Split(s.Origins, ",")[0]),
		NewUserFunc:        func() goauth.OauthUser { return nil },
		HandleUserInfoFunc: s.handleUserInfo,
	}
}

func (s *Server) handleUserInfo(c *gin.Context, info *goauth.UserInfo) error {
	data := &proxy.PostProxyTokenData{Info: *info}
	if reqToken := c.Request.Header.Get("Authorization"); strings.HasPrefix(reqToken, "BEARER") {
		data.Token = reqToken[7:]
	}
	payload, err := json.Marshal(data)
	glog.Infoln("Post with:", string(payload))
	if err != nil {
		return err
	}
	res, err := s.httpClient.Post(s.Target(s.PostInfoPath), binding.MIMEJSON, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	res.Header[cors.AllowOriginKey] = c.Writer.Header()[cors.AllowOriginKey]
	cw, _, _ := c.Writer.Hijack()
	res.Write(cw)
	return nil
}

func (s *Server) getProviders() ([]proxy.Provider, error) {
	res, err := s.httpClient.Get(s.Target(s.GetPrdsPath))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var ps []proxy.Provider
	if err = json.NewDecoder(res.Body).Decode(&ps); err != nil {
		return nil, err
	}
	return ps, nil
}

type Transport struct {
	http.RoundTripper
	SkProxy []byte
	AuthAlg string
}

func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	token, err := t.newProxyToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "BEARER "+token)
	if t.RoundTripper == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return t.RoundTripper.RoundTrip(req)
}

func (t *Transport) newProxyToken() (string, error) {
	token := jwt.New(jwt.GetSigningMethod(t.AuthAlg))
	token.Header["kid"] = "proxy"
	token.Claims["exp"] = time.Now().Add(time.Second * 10).Unix()
	return token.SignedString(t.SkProxy)
}

func Ok(c *gin.Context)       { c.AbortWithStatus(http.StatusOK) }
func NotFound(c *gin.Context) { c.AbortWithStatus(http.StatusNotFound) }
