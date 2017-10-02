package couchdb

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
)

// Server - Basic struct for a connection
type Server struct {
	Address         string
	Port            int
	SSL             bool
	Authentication  Authentication
	Database        string
	schemeAuthority string
	ServerInfo      ServerInfo
	tlsConfig       *tls.Config
	httpTransport   *http.Transport
	httpClient      *http.Client
}

// Authentication -
type Authentication struct {
	BasicAuth   BasicAuth
	AuthSession string
}

// BasicAuth -
type BasicAuth struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// ServerInfo - Base struct from couchdb /
type ServerInfo struct {
	Couchdb string `json:"couchdb"`
	UUID    string `json:"uuid"`
	Version string `json:"version"`
	Vendor  vendor
}
type vendor struct {
	Version string `json:"version"`
	Name    string `json:"name"`
}

// ViewResponse - Basic struct for a view
type ViewResponse struct {
	TotalRow int               `json:"total_rows"`
	Offset   int               `json:"offset"`
	Rows     []viewResponseRow `json:"rows"`
}
type viewResponseRow struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// PutResponse - Generic struct for all answers
type PutResponse struct {
	Ok     string `json:"ok"`
	ID     string `json:"id"`
	Rev    string `json:"rev"`
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

var cipherSuiteTable = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

var tlsVersionTable = map[string]uint16{
	"VersionSSL30": tls.VersionSSL30,
	"VersionTLS10": tls.VersionTLS10,
	"VersionTLS11": tls.VersionTLS11,
	"VersionTLS12": tls.VersionTLS12,
}

// ConvertCipherSuiteArray - Returns a proper uint16 array instead of readable string array
func ConvertCipherSuiteArray(sa []string) (ia []uint16, err error) {
	for _, cipher := range sa {
		if cipherInt := cipherSuiteTable[cipher]; cipherInt != 0 {
			ia = append(ia, cipherInt)
		}
	}
	if len(ia) == 0 {
		err = errors.New("No ciphers appended")
	}
	return
}

// ConvertTLSVersion - Returns a proper uint16 value instead of readable string
func ConvertTLSVersion(s string) (i uint16) {
	if i = tlsVersionTable[s]; i == 0 {
		fmt.Println("No or bad TLS version configured. Fallback is TLS 1.0")
	}
	return
}

func (s *Server) createTransportLayer() {
	// Default config if nothing is set
	if s.tlsConfig == nil {
		s.tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			},
		}
	}
	s.httpTransport = &http.Transport{
		TLSClientConfig: s.tlsConfig,
	}
}

func (s *Server) createClientLayer() {
	s.httpClient = &http.Client{
		Transport: s.httpTransport,
	}
}

func (s *Server) newConnection() {
	if s.SSL == true {
		s.schemeAuthority = "https://" + s.Address + ":" + strconv.Itoa(s.Port)
	} else {
		s.schemeAuthority = "http://" + s.Address + ":" + strconv.Itoa(s.Port)
	}
	s.createTransportLayer()
	s.createClientLayer()
}

func (s *Server) query(method string, path string, data io.Reader) (b []byte, err error) {
	if s.httpClient == nil {
		s.newConnection()
	}
	url := s.schemeAuthority + path
	req, err := http.NewRequest(method, url, data)
	if err != nil {
		return
	}

	switch method {
	case "PUT", "POST":
		req.Header.Set("Content-Type", "application/json")
	default:
		req.Header.Set("Accept", "application/json")
	}

	s.setCookie(req)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		err = s.authenticate()
		if err != nil {
			return
		}
		return s.query(method, path, data) // Recurse handle defer on resp.Body.Close() better
	}
	return ioutil.ReadAll(resp.Body) // Since resp.Body.Close() we cannot return io.Reader
}

func (s *Server) setCookie(r *http.Request) {
	if s.Authentication.AuthSession != "" {
		r.AddCookie(&http.Cookie{
			Name:  "AuthSession",
			Value: s.Authentication.AuthSession,
		})
	}
}

// authenticate - Is called upon if http.StatusUnauthorized is returned.
// Cannot inherite query-method since we need the cookie.
func (s *Server) authenticate() (err error) {
	url := s.schemeAuthority + "/_session"
	auth, err := json.Marshal(s.Authentication.BasicAuth)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(auth))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode == http.StatusUnauthorized {
		err = errors.New("[-] Bad credentials")
		return
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "AuthSession" {
			s.Authentication.AuthSession = cookie.Value
		}
	}
	return
}

// GetServerInfo - returns a struct with information about the server
func (s *Server) GetServerInfo() (si ServerInfo, err error) {
	path := "/"
	body, err := s.query("GET", path, nil)
	if err != nil {
		return
	}
	err = json.Unmarshal(body, &si)
	if err == nil {
		s.ServerInfo = si
	}
	return
}

// GetAllDatabases - returns an array with all dbs
func (s *Server) GetAllDatabases() (ss []string, err error) {
	path := "/_all_dbs"
	body, err := s.query("GET", path, nil)
	if err != nil {
		return
	}
	err = json.Unmarshal(body, &ss)
	return
}

// GetView - returns a struct for a view response
func (s *Server) GetView(document string, view string) (vr ViewResponse, err error) {
	path := "/" + s.Database + "/_design/" + document + "/_view/" + view
	body, err := s.query("GET", path, nil)
	if err != nil {
		return
	}
	err = json.Unmarshal(body, &vr)
	return
}

// GetDocument - returns a single document as raw bytes
func (s *Server) GetDocument(document string) (b []byte, err error) {
	path := "/" + s.Database + "/" + document
	return s.query("GET", path, nil)
}

// PutDocument -
func (s *Server) PutDocument(document string, data io.Reader) (pr PutResponse, err error) {
	path := "/" + s.Database + "/" + document
	body, err := s.query("PUT", path, data)
	if err != nil {
		return
	}
	err = json.Unmarshal(body, &pr)
	return
}

func (s Server) String() (text string) {
	text = "[*] - IP: " + s.Address + "\n"
	text += "[*] - UUID: " + s.ServerInfo.UUID + "\n"
	text += "[*] - Version: " + s.ServerInfo.Version + "\n"
	return
}
