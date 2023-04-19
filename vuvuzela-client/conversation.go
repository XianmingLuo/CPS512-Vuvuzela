package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/crypto/onionbox"
	. "vuvuzela.io/vuvuzela"
)

type Conversation struct {
	sync.RWMutex

	// Represents a valid route
	route         []string

	pki           *PKI
	peerName      string
	peerPublicKey *BoxKey
	myPublicKey   *BoxKey
	myPrivateKey  *BoxKey
	gui           *GuiClient

	outQueue      chan []byte
	pendingRounds map[uint32]*pendingRound

	lastPeerResponding bool
	lastLatency        time.Duration
	lastRound          uint32
}

func (c *Conversation) Init() {
	c.Lock()
	c.outQueue = make(chan []byte, 64)
	c.pendingRounds = make(map[uint32]*pendingRound)
	c.lastPeerResponding = false
	c.Unlock()
}

type pendingRound struct {
	onionSharedKeys []*[32]byte
	sentMessage     [SizeEncryptedMessage]byte
}

type ConvoMessage struct {
	Body interface{}
	// seq/ack numbers can go here
}

type TextMessage struct {
	Timestamp time.Time
	Message []byte
}

type TimestampMessage struct {
	Timestamp time.Time
}

func (cm *ConvoMessage) Marshal() (msg [SizeMessage]byte) {
	switch v := cm.Body.(type) {
	case *TimestampMessage:
		binary.LittleEndian.PutUint64(msg[1:], uint64(v.Timestamp.UnixMicro()))
		msg[0] = 0
	case *TextMessage:
		binary.LittleEndian.PutUint64(msg[1:], uint64(v.Timestamp.UnixMicro()))
		msg[0] = 1
		copy(msg[9:], v.Message)
	}
	return
}

func (cm *ConvoMessage) Unmarshal(msg []byte) error {
	ts := int64(binary.LittleEndian.Uint64(msg[1:]))
	switch msg[0] {
	case 0:
		cm.Body = &TimestampMessage{
			Timestamp: time.UnixMicro(ts),
		}
	case 1:
		cm.Body = &TextMessage{time.UnixMicro(ts), msg[9:]}
	default:
		return fmt.Errorf("unexpected message type: %d", msg[0])
	}
	return nil
}

func (c *Conversation) QueueTextMessage(msg []byte) {
	c.outQueue <- msg
}

func (c *Conversation) NextConvoRequest(round uint32) *ConvoRequest {
	c.Lock()
	c.lastRound = round
	c.Unlock()
	go c.gui.redraw()

	var body interface{}

	select {
	// m is plaintext
	case m := <-c.outQueue:
		body = &TextMessage{Message: m}
	default:
		// Is timestampmessage distinguishable?
		body = &TimestampMessage{
			Timestamp: time.Now(),
		}
	}
	msg := &ConvoMessage{
		Body: body,
	}
	msgdata := msg.Marshal()

	var encmsg [SizeEncryptedMessage]byte
	ctxt := c.Seal(msgdata[:], round, c.myRole())
	copy(encmsg[:], ctxt)

	// Conversation Package to put in the last server
	// deadDrop is pre-computed
	exchange := &ConvoExchange{
		DeadDrop:         c.deadDrop(round),
		EncryptedMessage: encmsg,
	}

	// TODO: Use onion to transimit?
	onion, sharedKeys := onionbox.Seal(exchange.Marshal(), ForwardNonce(round), c.pki.ServerKeys(c.route).Keys())

	pr := &pendingRound{
		onionSharedKeys: sharedKeys,
		sentMessage:     encmsg,
	}
	c.Lock()
	// What is pendingRounds used for?
	c.pendingRounds[round] = pr
	c.Unlock()

	return &ConvoRequest{
		Round: round,
		Onion: onion,
	}
}

func (c *Conversation) HandleConvoResponse(r *ConvoResponse) {
	rlog := log.WithFields(log.Fields{"round": r.Round})

	var responding bool
	defer func() {
		c.Lock()
		c.lastPeerResponding = responding
		c.Unlock()
		c.gui.redraw()
	}()

	c.Lock()
	pr, ok := c.pendingRounds[r.Round]
	delete(c.pendingRounds, r.Round)
	c.Unlock()
	if !ok {
		rlog.Error("round not found")
		return
	}

	encmsg, ok := onionbox.Open(r.Onion, BackwardNonce(r.Round), pr.onionSharedKeys)
	if !ok {
		rlog.Error("decrypting onion failed", len(pr.onionSharedKeys))
		return
	}

	if bytes.Compare(encmsg, pr.sentMessage[:]) == 0 && !c.Solo() {
		return
	}

	msgdata, ok := c.Open(encmsg, r.Round, c.theirRole())
	if !ok {
		rlog.Error("decrypting peer message failed")
		return
	}

	msg := new(ConvoMessage)
	if err := msg.Unmarshal(msgdata); err != nil {
		rlog.Error("unmarshaling peer message failed")
		return
	}

	responding = true

	switch m := msg.Body.(type) {
	case *TextMessage:
		s := strings.TrimRight(string(m.Message), "\x00")
		// fmt.Println(time.Since(m.Timestamp))
		// c.gui.Printf("%f", time.Since(m.Timestamp))
		c.gui.Printf("<%s> %s\n", c.peerName, s)
	case *TimestampMessage:
		latency := time.Since(m.Timestamp)
		c.Lock()
		c.lastLatency = latency
		c.gui.Printf("%f\n", float64(latency)/float64(1e9))
		c.gui.logLatency(latency)
		c.Unlock()
	}
}
// Assume Convo Error only represents server chain broken so far
// Let client decided router or entry server?
// Entry Server for now
func (c *Conversation) HandleConvoError(e *ConvoError) {
	c.gui.Printf("Middle Server Fault: Please rephrase and enter\n")
	c.gui.Printf("server chain broken: %s\n", e.Err)
	c.gui.Printf("Removing %s\n", e.Err)
	failedServerName := e.Err
	for i, s := range c.route {
		if s == failedServerName {
			c.route = append(
				c.route[:i],
				c.route[i+1:]...
			)
		}
	}
	c.gui.Printf("Updating route to %s\n", c.route)
	c.gui.logRecov()
	return
}

type Status struct {
	PeerResponding bool
	Round          uint32
	Latency        float64
}

func (c *Conversation) Status() *Status {
	c.RLock()
	status := &Status{
		PeerResponding: c.lastPeerResponding,
		Round:          c.lastRound,
		Latency:        float64(c.lastLatency) / float64(time.Second),
	}
	c.RUnlock()
	return status
}

func (c *Conversation) Solo() bool {
	return bytes.Compare(c.myPublicKey[:], c.peerPublicKey[:]) == 0
}

// Roles ensure that messages to the peer and messages from
// the peer have distinct nonces.
func (c *Conversation) myRole() byte {
	if bytes.Compare(c.myPublicKey[:], c.peerPublicKey[:]) < 0 {
		return 0
	} else {
		return 1
	}
}

func (c *Conversation) theirRole() byte {
	if bytes.Compare(c.peerPublicKey[:], c.myPublicKey[:]) < 0 {
		return 0
	} else {
		return 1
	}
}

func (c *Conversation) Seal(message []byte, round uint32, role byte) []byte {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[:], round)
	nonce[23] = role

	ctxt := box.Seal(nil, message, &nonce, c.peerPublicKey.Key(), c.myPrivateKey.Key())
	return ctxt
}

func (c *Conversation) Open(ctxt []byte, round uint32, role byte) ([]byte, bool) {
	var nonce [24]byte
	binary.BigEndian.PutUint32(nonce[:], round)
	nonce[23] = role

	return box.Open(nil, ctxt, &nonce, c.peerPublicKey.Key(), c.myPrivateKey.Key())
}

// Derive deadDrop id based on key and round number
func (c *Conversation) deadDrop(round uint32) (id DeadDrop) {
	if c.Solo() {
		rand.Read(id[:])
	} else {
		var sharedKey [32]byte
		box.Precompute(&sharedKey, c.peerPublicKey.Key(), c.myPrivateKey.Key())

		h := hmac.New(sha256.New, sharedKey[:])
		binary.Write(h, binary.BigEndian, round)
		r := h.Sum(nil)
		copy(id[:], r)
	}
	return
}
