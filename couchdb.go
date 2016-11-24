package couchdb

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// Server - Basic struct for a connection
type Server struct {
	Address         string
	Port            int
	SSL             bool
	Database        string
	SchemeAuthority string
	ServerInfo      ServerInfo
	TLSConfig       *tls.Config
	HTTPTransport   *http.Transport
	HTTPClient      *http.Client
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
	if s.TLSConfig == nil {
		s.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			},
		}
	}
	s.HTTPTransport = &http.Transport{
		TLSClientConfig: s.TLSConfig,
	}
}

func (s *Server) createClientLayer() {
	s.HTTPClient = &http.Client{
		Transport: s.HTTPTransport,
	}
}

func (s *Server) newConnection() {
	if s.SSL == true {
		s.SchemeAuthority = "https://" + s.Address + ":" + strconv.Itoa(s.Port)
	} else {
		s.SchemeAuthority = "http://" + s.Address + ":" + strconv.Itoa(s.Port)
	}
	s.createTransportLayer()
	s.createClientLayer()
}

func (s *Server) newQuery(method string, path string, data []byte) (body []byte, err error) {
	if s.HTTPClient == nil {
		s.newConnection()
	}
	url := s.SchemeAuthority + path
	req, err := http.NewRequest(method, url, strings.NewReader(string(data)))
	if err != nil {
		return
	}
	resp, err := s.HTTPClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, err = ioutil.ReadAll(resp.Body)
	}
	return
}

// GetServerInfo - returns a struct with information about the database
func (s *Server) GetServerInfo() (serverInfo ServerInfo, err error) {
	path := "/"
	body, err := s.newQuery("GET", path, nil)
	if err == nil {
		err = json.Unmarshal(body, &serverInfo)
		err = json.Unmarshal(body, &s.ServerInfo)
	}
	return
}

// GetAllDatabases - returns an array with all dbs
func (s *Server) GetAllDatabases() (allDatabases []string, err error) {
	path := "/_all_dbs"
	body, err := s.newQuery("GET", path, nil)
	if err == nil {
		err = json.Unmarshal(body, &allDatabases)
	}
	return
}

// GetView - returns a struct for a view response
func (s *Server) GetView(document string, view string) (viewResponse ViewResponse, err error) {
	path := "/" + s.Database + "/_design/" + document + "/_view/" + view
	body, err := s.newQuery("GET", path, nil)
	if err == nil {
		err = json.Unmarshal(body, &viewResponse)
	}
	return
}

// GetDocument - returns a single document in []byte
func (s *Server) GetDocument(document string) (getResponse []byte, err error) {
	path := "/" + s.Database + "/" + document
	getResponse, err = s.newQuery("GET", path, nil)
	return
}

// PutDocument -
func (s *Server) PutDocument(document string, documentData []byte) (putResponse PutResponse, err error) {
	path := "/" + s.Database + "/" + document
	body, err := s.newQuery("PUT", path, documentData)
	if err == nil {
		err = json.Unmarshal(body, &putResponse)
	}
	return
}
func (s Server) String() (text string) {
	text = "[*] - IP: " + s.Address + "\n"
	text += "[*] - UUID: " + s.ServerInfo.UUID + "\n"
	text += "[*] - Version: " + s.ServerInfo.Version + "\n"
	return
}
