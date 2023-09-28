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
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

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

func logSIGINT(serverName string) {
	to_write := fmt.Sprintf("%d\n", time.Now().UnixMicro())
	filename := serverName + ".int";
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)		
		return
	}
	//fmt.Printf("Writing %s to %s...\n", to_write, filename)
	if _, err := f.Write([]byte(to_write)); err != nil {
		fmt.Println(err)
		f.Close()
		return
	}
	if err := f.Close(); err != nil {
		fmt.Println(err)
	}
	
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

	// Create a channel to receive the SIGINT signal.
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
	
	// Start a goroutine to listen for SIGINT.
	go func() {
		<-sigint
		logSIGINT(conf.ServerName)
		fmt.Println("Received SIGINT, shutting down gracefully...")
		// Clean up resources and shut down the server here.
		os.Exit(0)
	}()

	if *muOverride >= 0 {
		conf.ConvoMu = *muOverride
	}

	var err error
	var client *vrpc.Client  
	var firstClient *vrpc.Client  
  var nextClients = make(map[string]*vrpc.Client)
	if addrs := pki.NextServers(conf.ServerName); addrs != nil {
    for i, addr := range addrs{
      client , err = vrpc.Dial("tcp", addr, runtime.NumCPU())
      nextClients[addr] = client
      if i == 0 {
        firstClient = client
      }
      if err != nil {
        log.Fatalf("vrpc.Dial: %s", err)
      }
    }
	}
  client =  firstClient 
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
    NextClients: nextClients,
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
