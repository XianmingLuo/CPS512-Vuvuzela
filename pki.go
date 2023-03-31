package vuvuzela

import (
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/crypto/onionbox"
	. "vuvuzela.io/vuvuzela/internal"
)

type ServerInfo struct {
	Address   string
	PublicKey *BoxKey
}

type PKI struct {
	People      map[string]*BoxKey
	Servers     map[string]*ServerInfo
	ServerOrder []string
	EntryServer string
}

func ReadPKI(jsonPath string) *PKI {
	pki := new(PKI)
	ReadJSONFile(jsonPath, pki)
	if len(pki.ServerOrder) == 0 {
		log.Fatalf("%q: ServerOrder must contain at least one server", jsonPath)
	}
	for _, s := range pki.ServerOrder {
		info, ok := pki.Servers[s]
		if !ok {
			log.Fatalf("%q: server %q not found", jsonPath, s)
		}
		addr := info.Address
		if addr == "" {
			log.Fatalf("%q: server %q does not specify an Address", jsonPath, s)
		}

		if strings.IndexByte(addr, ':') == -1 {
			info.Address = net.JoinHostPort(addr, DefaultServerPort)
		}
	}
	return pki
}

func (pki *PKI) ServerKeys(route []string) BoxKeys {
	//TODO: 3?
	keys := make([]*BoxKey, 0, 3)
	for _, s := range route {
		// TODO: May still need dynamic membership to update pki.Servers
		info := pki.Servers[s]
		keys = append(keys, info.PublicKey)
	}
	return keys
}

func (pki *PKI) FirstServer(route []string) string {
	s := route[0]
	return pki.Servers[s].Address
}

func (pki *PKI) LastServer(route []string) string {
	s := route[len(route)-1]
	return pki.Servers[s].Address
}

func (pki *PKI) Index(serverName string, route []string) int {
	for i, s := range route {
		if s == serverName {
			return i
		}
	}
	log.Fatalf("pki.Index: server %q not found", serverName)
	return -1
}

func (pki *PKI) NextServerName(serverName string, route []string) string {
	// What if the server is not in the route?
	i := pki.Index(serverName, route)
	if i < len(route)-1 {
		s := route[i+1]
		return s
	} else {
		return ""
	}
}

func (pki *PKI) NextServer(serverName string, route []string) string {
	// What if the server is not in the route?
	serverName = pki.NextServerName(serverName, route)
	if serverName != "" {
		return pki.Servers[serverName].Address		
	} else {
		return ""
	}

}

func (pki *PKI) SkipServer(serverName string, route []string) string {
	i := pki.Index(serverName, route)
	if i < len(route)-2 {
		s:= route[i+2]
		return pki.Servers[s].Address		
	} else {
		return ""
	}
}

func (pki *PKI) NextServerKeys(serverName string, route []string) BoxKeys {
	i := pki.Index(serverName, route)
	var keys []*BoxKey
	for _, s := range route[i+1:] {
		keys = append(keys, pki.Servers[s].PublicKey)
	}
	return keys
}

func (pki *PKI) IncomingOnionOverhead(serverName string, route []string) int {
	i := len(route) - pki.Index(serverName, route)
	return i * onionbox.Overhead
}

func (pki *PKI) OutgoingOnionOverhead(serverName string, route []string) int {
	i := len(route) - pki.Index(serverName, route)
	return i * box.Overhead
}
