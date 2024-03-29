package vuvuzela

import (
	"encoding/binary"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/crypto/shuffle"
	"vuvuzela.io/vuvuzela/vrpc"
)

type ConvoService struct {
	roundsMu sync.RWMutex
	rounds   map[uint32]*ConvoRound

	Idle *sync.Mutex

	Laplace rand.Laplace

	PKI        *PKI
	ServerName string
	PrivateKey *BoxKey
	Client     *vrpc.Client
  NextClients map[string]*vrpc.Client
	SkipClient *vrpc.Client
	LastServer bool

	AccessCounts chan *AccessCount
}

type ConvoRound struct {
	srv    *ConvoService
	status convoStatus

	// Include routing information in each round
	route         []string
	numIncoming   int
	sharedKeys    []*[32]byte
	incoming      [][]byte
	incomingIndex []int

	replies [][]byte

	numFakeSingles uint32
	numFakeDoubles uint32

	noise   [][]byte
	noiseWg sync.WaitGroup
}

type convoStatus int

const (
	convoRoundNew convoStatus = iota + 1
	convoRoundOpen
	convoRoundClosed
)

type AccessCount struct {
	Singles int64
	Doubles int64
}

func InitConvoService(srv *ConvoService) {
	srv.rounds = make(map[uint32]*ConvoRound)
	srv.AccessCounts = make(chan *AccessCount, 8)
}

func (srv *ConvoService) getRound(round uint32, expectedStatus convoStatus) (*ConvoRound, error) {
	srv.roundsMu.RLock()
	r, ok := srv.rounds[round]
	srv.roundsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("round %d not found", round)
	}
	if r.status != expectedStatus {
		return r, fmt.Errorf("round %d: status %v, expecting %v", round, r.status, expectedStatus)
	}
	return r, nil
}

// NewRound RPC
func (srv *ConvoService) NewRound(args *ConvoNewRoundArgs, _ *struct{}) error {
	log.WithFields(log.Fields{"service": "convo", "rpc": "NewRound", "round": args.Round, "route": args.Route}).Info()

	Round := args.Round
	// wait for the service to become idle before starting a new round
	// TODO temporary hack
	srv.Idle.Lock()
	srv.roundsMu.Lock()
	// TODO: What is defer?
	defer srv.roundsMu.Unlock()

	_, exists := srv.rounds[Round]
	if exists {
		return fmt.Errorf("round %d already exists", Round)
	}

	round := &ConvoRound{
		srv: srv,
		route: args.Route,
	}
	srv.rounds[Round] = round
	// Add Cover Traffic
	if !srv.LastServer {
		round.numFakeSingles = srv.Laplace.Uint32()
		round.numFakeDoubles = srv.Laplace.Uint32()
		round.numFakeDoubles += round.numFakeDoubles % 2 // ensure numFakeDoubles is even
		round.noise = make([][]byte, round.numFakeSingles+round.numFakeDoubles)

		nonce := ForwardNonce(Round)
		nextKeys := srv.PKI.NextServerKeys(srv.ServerName,
			round.route).Keys()
		// ServerKeys may change due to middle server failure
		// TODO: May need lock
		// One possible race condition
		// Round N Close RPC :middle server fails. change server order
		// Round N+1 Newround: read server order
		round.noiseWg.Add(1)
		go func() {
			FillWithFakeSingles(round.noise[:round.numFakeSingles], nonce, nextKeys)
			FillWithFakeDoubles(round.noise[round.numFakeSingles:], nonce, nextKeys)
			round.noiseWg.Done()
		}()
	}

	round.status = convoRoundNew
	return nil
}

type ConvoOpenArgs struct {
	Round       uint32
	NumIncoming int
}

func (srv *ConvoService) Open(args *ConvoOpenArgs, _ *struct{}) error {
	log.WithFields(log.Fields{"service": "convo", "rpc": "Open", "round": args.Round, "incoming": args.NumIncoming}).Info()

	round, err := srv.getRound(args.Round, convoRoundNew)
	if err != nil {
		return err
	}

	round.numIncoming = args.NumIncoming
	// shareKeys = round.numIncoming x *[32]byte
	round.sharedKeys = make([]*[32]byte, round.numIncoming)
	// incoming  = round.numIncoming x []byte
	round.incoming = make([][]byte, round.numIncoming)
	round.status = convoRoundOpen

	return nil
}

type ConvoAddArgs struct {
	Round  uint32
	Offset int
	Onions [][]byte
}

// What does Add actually do?
// Peel a batch of onions
func (srv *ConvoService) Add(args *ConvoAddArgs, _ *struct{}) error {
	log.WithFields(log.Fields{"service": "convo", "rpc": "Add", "round": args.Round, "onions": len(args.Onions)}).Debug()

	round, err := srv.getRound(args.Round, convoRoundOpen)
	if err != nil {
		return err
	}

	nonce := ForwardNonce(args.Round)
	// Needs a correct view of server order
	// How does the update propagate to the tail of the server chain?
	// Head of the server chain may know the update of the server chain because of error propagation
	// Tail of the server chain may only know the update when some server explicitly tell them
	// Solution 1: Query entry server actively every round
	// Solution 2: Passively informed by the previous server
	// Solution 3: Include the path in the round information (May also apply to dynamic routing)
	// TODO: Any security implication?
	// Solution 4: Dynamic Membership from Raft?
	expectedOnionSize := srv.PKI.IncomingOnionOverhead(
		srv.ServerName,
		round.route) + SizeConvoExchange

	if args.Offset+len(args.Onions) > round.numIncoming {
		return fmt.Errorf("overflowing onions (offset=%d, onions=%d, incoming=%d)", args.Offset, len(args.Onions), round.numIncoming)
	}

	// Deal with onions
	for k, onion := range args.Onions {
		i := args.Offset + k
		round.sharedKeys[i] = new([32]byte)

		if len(onion) == expectedOnionSize {
			var theirPublic [32]byte
			// TODO: Does onion has their public key
			// What does their mean?
			copy(theirPublic[:], onion[0:32])

			box.Precompute(round.sharedKeys[i], &theirPublic, srv.PrivateKey.Key())

			// Open one layer of onion?
			message, ok := box.OpenAfterPrecomputation(nil, onion[32:], nonce, round.sharedKeys[i])
			if ok {
				round.incoming[i] = message
			}
		} else {
			// for debugging
      log.WithFields(log.Fields{"round": args.Round, "offset": args.Offset,"expected size": expectedOnionSize,  "onions": len(args.Onions), "onion": k, "onionLen": len(onion)}).Error("bad onion size")
		}
	}

	return nil
}

func (srv *ConvoService) filterIncoming(round *ConvoRound) {
	incomingValid := make([][]byte, len(round.incoming))
	incomingIndex := make([]int, len(round.incoming))

	seen := make(map[uint64]bool)
	v := 0
	for i, msg := range round.incoming {
		if msg == nil {
			incomingIndex[i] = -1
			continue
		}
		msgkey := binary.BigEndian.Uint64(msg[len(msg)-8:])
		if seen[msgkey] {
			incomingIndex[i] = -1
		} else {
			seen[msgkey] = true
			incomingValid[v] = msg
			incomingIndex[i] = v
			v++
		}
	}

	round.incoming = incomingValid[:v]
	round.incomingIndex = incomingIndex
}

func (srv *ConvoService) Close(Round uint32, _ *struct{}) error {
	log.WithFields(log.Fields{"service": "convo", "rpc": "Close", "round": Round}).Info()

	round, err := srv.getRound(Round, convoRoundOpen)
	if err != nil {
		return err
	}

	srv.filterIncoming(round)
	if !srv.LastServer {
		round.noiseWg.Wait()

		// Generate noise
		// TODO: Is noise the so-called cover traffic?
		outgoing := append(round.incoming, round.noise...)		
		round.noise = nil

		shuffler := shuffle.New(rand.Reader, len(outgoing))
		shuffler.Shuffle(outgoing)

		// Critical Part for Fault Tolerance
		// if next server is dead
		// err will be returned
    nextServer := srv.PKI.NextServer(srv.ServerName, srv.rounds[Round].route)
    client :=  srv.NextClients[nextServer] 
    if client != nil {
      srv.Client = client
    } else {
      srv.Client = srv.SkipClient
    }
		if err := NewConvoRound(srv.Client, Round, srv.rounds[Round].route); err != nil {
			// TODO: Catch specific type of error
			nextServerName := 
				srv.PKI.NextServerName(
				srv.ServerName,
				round.route)
			log.Println("NewConvoRound: ", err)
			// TODO: Only substitute next client before new round start
			if srv.SkipClient != nil {
				// Update server order
				// TODO: Potential Race Condition
				log.Println("Remove  ", nextServerName)
				// SkipClient becomes new client
				srv.Client = srv.SkipClient
				//srv.SkipClient = nil				
				// return connection error
				srv.Idle.Unlock()
				log.Println("unlock ", nextServerName)
				// TODO: Better to Customize error type
				return fmt.Errorf("NewConvoRound: %s", nextServerName)
			} else {
				// The entire system is down
				// Differentiate from error with backup
				srv.Idle.Unlock()
				return fmt.Errorf("NewConvoRound: %s", err)	
			}
			
		}
		srv.Idle.Unlock()

		// TODO: What is replies?
		// Ask the next server in the chain to run convo round
		// Previous Server --incoming--> this server --> outgoing --> Next Server
		// len(incoming) != len(outgoing)
		// because of added cover traffic

		replies, err := RunConvoRound(srv.Client, Round, outgoing)
		if err != nil {
			//log.Println("RunConvoRound: %s", err)
			// TODO: Abstract out to avoid duplicate		
			if srv.SkipClient != nil {
				// SkipClient becomes new client
				srv.Client = srv.SkipClient
				//srv.SkipClient = nil
				return fmt.Errorf("RunConvoRound: %s", err)
			} else {
				// The entire system is down
				// Defferentiate from error with backup
				fmt.Errorf("RunConvoround: %s", err)			
			}

		}

		// Reverse operation
		// Why reverse operation is needed?
		// message needs to be returned to the correct sender
		// Cover traffic needs to be removed
		shuffler.Unshuffle(replies)
		round.replies = replies[:round.numIncoming]
	} else { // Dead Drop Server
		exchanges := make([]*ConvoExchange, len(round.incoming))
		concurrency.ParallelFor(len(round.incoming), func(p *concurrency.P) {
			for i, ok := p.Next(); ok; i, ok = p.Next() {
				exchanges[i] = new(ConvoExchange)
				if err := exchanges[i].Unmarshal(round.incoming[i]); err != nil {
					log.WithFields(log.Fields{"bug": true, "call": "ConvoExchange.Unmarshal"}).Error(err)
				}
			}
		})

		var singles, doubles int64
		deadDrops := make(map[DeadDrop][]int)
		for i, ex := range exchanges {
			drop := deadDrops[ex.DeadDrop]
			if len(drop) == 0 {
				singles++
				deadDrops[ex.DeadDrop] = append(drop, i)
			} else if len(drop) == 1 {
				singles--
				doubles++
				deadDrops[ex.DeadDrop] = append(drop, i)
			}
		}

		round.replies = make([][]byte, len(round.incoming))
		concurrency.ParallelFor(len(exchanges), func(p *concurrency.P) {
			for i, ok := p.Next(); ok; i, ok = p.Next() {
				ex := exchanges[i]
				drop := deadDrops[ex.DeadDrop]
				if len(drop) == 1 {
					round.replies[i] = ex.EncryptedMessage[:]
				}
				if len(drop) == 2 {
					var k int
					if i == drop[0] {
						k = drop[1]
					} else {
						k = drop[0]
					}
					round.replies[i] = exchanges[k].EncryptedMessage[:]
				}
			}
		})
		srv.Idle.Unlock()

		ac := &AccessCount{
			Singles: singles,
			Doubles: doubles,
		}
		select {
		case srv.AccessCounts <- ac:
		default:
		}
	}

	round.status = convoRoundClosed
	return nil
}

type ConvoGetArgs struct {
	Round  uint32
	Offset int
	Count  int
}

type ConvoGetResult struct {
	Onions [][]byte
}

// RPC: Get
func (srv *ConvoService) Get(args *ConvoGetArgs, result *ConvoGetResult) error {
	log.WithFields(log.Fields{"service": "convo", "rpc": "Get", "round": args.Round, "count": args.Count}).Debug()

	round, err := srv.getRound(args.Round, convoRoundClosed)
	if err != nil {
		return err
	}

	nonce := BackwardNonce(args.Round)
	outgoingOnionSize := srv.PKI.OutgoingOnionOverhead(
		srv.ServerName,
		round.route) + SizeEncryptedMessage

	result.Onions = make([][]byte, args.Count)
	for k := range result.Onions {
		i := args.Offset + k

		if v := round.incomingIndex[i]; v > -1 {
			reply := round.replies[v]
			onion := box.SealAfterPrecomputation(nil, reply, nonce, round.sharedKeys[i])
			result.Onions[k] = onion
		}
		if len(result.Onions[k]) != outgoingOnionSize {
			onion := make([]byte, outgoingOnionSize)
			rand.Read(onion)
			result.Onions[k] = onion
		}
	}

	return nil
}

func (srv *ConvoService) Delete(Round uint32, _ *struct{}) error {
	log.WithFields(log.Fields{"service": "convo", "rpc": "Delete", "round": Round}).Info()

	srv.roundsMu.Lock()
	delete(srv.rounds, Round)
	srv.roundsMu.Unlock()
	return nil
}

type ConvoNewRoundArgs struct {
	Round       uint32
	// TODO: Can be optimized by using server id
	Route       []string
}
// RPC: ConvoService.NewRound
func NewConvoRound(client *vrpc.Client, round uint32, route []string) error {
	newRoundArgs := &ConvoNewRoundArgs{
		Round: round,
		Route: route,
	}
	return client.Call("ConvoService.NewRound", newRoundArgs, nil)
}
// Ask the next server to run convo round
func RunConvoRound(client *vrpc.Client, round uint32, onions [][]byte) ([][]byte, error) {
	openArgs := &ConvoOpenArgs{
		Round:       round,
		NumIncoming: len(onions),
	}
	// First Call RPC Open
	if err := client.Call("ConvoService.Open", openArgs, nil); err != nil {
		return nil, fmt.Errorf("Open: %s", err)
	}

	// Handle onions concurrently
	spans := concurrency.Spans(len(onions), 4000)
	calls := make([]*vrpc.Call, len(spans))

	// Then Call RPC Add
	concurrency.ParallelFor(len(calls), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			span := spans[i]
			calls[i] = &vrpc.Call{
				Method: "ConvoService.Add",
				Args: &ConvoAddArgs{
					Round:  round,
					Offset: span.Start,
					Onions: onions[span.Start : span.Start+span.Count],
				},
				Reply: nil,
			}
		}
	})

	// TODO: What is calls?
	if err := client.CallMany(calls); err != nil {
		return nil, fmt.Errorf("Add: %s", err)
	}

	// Call RPC Close
	if err := client.Call("ConvoService.Close", round, nil); err != nil {
		return nil, fmt.Errorf("Close: %s", err)
	}
	

	// Call RPC Get
	concurrency.ParallelFor(len(calls), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			span := spans[i]
			calls[i] = &vrpc.Call{
				Method: "ConvoService.Get",
				Args: &ConvoGetArgs{
					Round:  round,
					Offset: span.Start,
					Count:  span.Count,
				},
				Reply: new(ConvoGetResult),
			}
		}
	})

	if err := client.CallMany(calls); err != nil {
		return nil, fmt.Errorf("Get: %s", err)
	}

	replies := make([][]byte, len(onions))
	concurrency.ParallelFor(len(calls), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			span := spans[i]
			copy(replies[span.Start:span.Start+span.Count], calls[i].Reply.(*ConvoGetResult).Onions)
		}
	})

	if err := client.Call("ConvoService.Delete", round, nil); err != nil {
		return nil, fmt.Errorf("Delete: %s", err)
	}

	return replies, nil
}
