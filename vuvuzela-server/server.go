package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/rpc"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"

	vrand "vuvuzela.io/crypto/rand"
	. "vuvuzela.io/vuvuzela"
	. "vuvuzela.io/vuvuzela/internal"
	"vuvuzela.io/vuvuzela/vrpc"
)

var doInit = flag.Bool("init", false, "create default config file")
var confPath = flag.String("conf", "", "config file")
// Use Absolute Path for now?
var pkiPath = flag.String("pki", "../confs/pki.conf", "pki file")
var muOverride = flag.Float64("mu", -1.0, "override ConvoMu in conf file")

type Conf struct {
	ServerName string
	PublicKey  *BoxKey
	PrivateKey *BoxKey
	ListenAddr string `json:",omitempty"`
	DebugAddr  string `json:",omitempty"`

	ConvoMu float64
	ConvoB  float64

	DialMu float64
	DialB  float64
}

func WriteDefaultConf(path string) {
	myPublicKey, myPrivateKey, err := GenerateBoxKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey: %s", err)
	}
	conf := &Conf{
		ServerName: "mit",
		PublicKey:  myPublicKey,
		PrivateKey: myPrivateKey,
	}

	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		log.Fatalf("json encoding error: %s", err)
	}
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		log.Fatalf("WriteFile: %s", err)
	}
	fmt.Printf("wrote %q\n", path)
}

func main() {
	// command-line parsing
	flag.Parse()
	log.SetFormatter(&ServerFormatter{})

	if *confPath == "" {
		log.Fatalf("must specify -conf flag")
	}

	if *doInit {
		WriteDefaultConf(*confPath)
		return
	}

	pki := ReadPKI(*pkiPath)

	conf := new(Conf)
	ReadJSONFile(*confPath, conf)
	if conf.ServerName == "" || conf.PublicKey == nil || conf.PrivateKey == nil {
		log.Fatalf("missing required fields: %s", *confPath)
	}

	if *muOverride >= 0 {
		conf.ConvoMu = *muOverride
	}

	var err error
	var client *vrpc.Client
	if addr := pki.NextServer(conf.ServerName, pki.ServerOrder); addr != "" {
		// Extend connection
		client, err = vrpc.Dial("tcp", addr, runtime.NumCPU())
		if err != nil {
			log.Fatalf("vrpc.Dial: %s", err)
		}
	}
	// skip client for backup use
	// TODO: Should one server know the address of skip client?	
	var skipClient *vrpc.Client
	if addr := pki.SkipServer(conf.ServerName, pki.ServerOrder); addr != "" {
		skipClient, err = vrpc.Dial("tcp", addr, runtime.NumCPU())
		if err != nil {
			log.Fatalf("vrpc.Dial: %s", err)
		}
	}
	

	var idle sync.Mutex

	convoService := &ConvoService{
		Idle: &idle,

		Laplace: vrand.Laplace{
			Mu: conf.ConvoMu,
			B:  conf.ConvoB,
		},

		PKI:        pki,
		ServerName: conf.ServerName,
		PrivateKey: conf.PrivateKey,

		Client:     client,
		// SkipClient is for backup use
		// Or discover when needed?
		SkipClient: skipClient,
		LastServer: client == nil,
	}
	InitConvoService(convoService)

	if convoService.LastServer {
		histogram := &Histogram{Mu: conf.ConvoMu, NumServers: len(pki.ServerOrder)}
		go histogram.run(convoService.AccessCounts)
	}

	dialService := &DialService{
		Idle: &idle,

		Laplace: vrand.Laplace{
			Mu: conf.ConvoMu,
			B:  conf.ConvoB,
		},

		PKI:        pki,
		ServerName: conf.ServerName,
		PrivateKey: conf.PrivateKey,

		Client:     client,
		LastServer: client == nil,
	}
	InitDialService(dialService)

	if err := rpc.Register(dialService); err != nil {
		log.Fatalf("rpc.Register: %s", err)
	}
	if err := rpc.Register(convoService); err != nil {
		log.Fatalf("rpc.Register: %s", err)
	}

	if conf.DebugAddr != "" {
		go func() {
			log.Println(http.ListenAndServe(conf.DebugAddr, nil))
		}()
		runtime.SetBlockProfileRate(1)
	}

	if conf.ListenAddr == "" {
		conf.ListenAddr = DefaultServerAddr
	}
	// Listen to incoming connection from previous server
	// Before
	// FirstServer:2718 ---> MiddleServer:2719 --> LastServer:2720
	// Now
	// FirstServer:2718 ---> MiddleServer1:3719 --> MiddleServer2:3720 --> LastServer:2720
	// 1. When middleserver2 is down, middleserver directly forward message to last server
	// May have some issue
	// Last server can not break the onion layer that is supposed to be decrypted by middleserver2
	// Does client has retry machanism?
	// One possible solution
	// middleserver1 / middleserver2.1
	//               \ middleserver2.2
	// middleserver2 group shares the same key pair
	// security implication: larger attack surface
	// Another possible solution
	// middleserver1 --X--> middleserver2 --X--> last server
	//               |--------------------------->|
	// skip the middleserver2
	// Problem: last server does not have private key of middleserver2, can not decrypt middleserver2 layer
	// Possible Solution: client retry with one onion layer less
	// Security implication: differential privacy may be broken?
	// Try skip middleserver2 for now
	listen, err := net.Listen("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatal("Listen:", err)
	}
	rpc.Accept(listen)
}
