package main

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/gorilla/websocket"

	. "vuvuzela.io/vuvuzela"
)

type Client struct {
	sync.Mutex

	//currentRoute []string

	EntryServer string
	MyPublicKey *BoxKey

	ws *websocket.Conn

	roundHandlers map[uint32]ConvoHandler
	convoHandler  ConvoHandler
	dialHandler   DialHandler
}

type ConvoHandler interface {
	NextConvoRequest(round uint32) *ConvoRequest
	HandleConvoResponse(response *ConvoResponse)
	HandleConvoError(error *ConvoError)
}

type DialHandler interface {
	NextDialRequest(round uint32, buckets uint32) *DialRequest
	HandleDialBucket(db *DialBucket)
}

func NewClient(entryServer string, publicKey *BoxKey) *Client {
	c := &Client{
		EntryServer: entryServer,
		MyPublicKey: publicKey,

		roundHandlers: make(map[uint32]ConvoHandler),
	}
	return c
}

func (c *Client) SetConvoHandler(convo ConvoHandler) {
	c.Lock()
	c.convoHandler = convo
	c.Unlock()
}

func (c *Client) SetDialHandler(dialer DialHandler) {
	c.Lock()
	c.dialHandler = dialer
	c.Unlock()
}

func (c *Client) Connect() error {
	// TODO check if already connected
	if c.convoHandler == nil {
		return fmt.Errorf("no convo handler")
	}
	if c.dialHandler == nil {
		return fmt.Errorf("no dial handler")
	}

	wsaddr := fmt.Sprintf("%s/ws?publickey=%s", c.EntryServer, c.MyPublicKey.String())
	dialer := &websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}
	ws, _, err := dialer.Dial(wsaddr, nil)
	if err != nil {
		return err
	}
	c.ws = ws
	go c.readLoop()
	return nil
}

func (c *Client) Close() {
	c.ws.Close()
}
// Send using JSON
func (c *Client) Send(v interface{}) {
	const writeWait = 10 * time.Second

	e, err := Envelop(v)
	if err != nil {
		log.WithFields(log.Fields{"bug": true, "call": "Envelop"}).Error(err)
		return
	}

	c.Lock()
	c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.ws.WriteJSON(e); err != nil {
		log.WithFields(log.Fields{"call": "WriteJSON"}).Debug(err)
		c.Unlock()
		c.Close()
		return
	}
	c.Unlock()
}

func (c *Client) readLoop() {
	for {
		var e Envelope
		if err := c.ws.ReadJSON(&e); err != nil {
			log.WithFields(log.Fields{"call": "ReadJSON"}).Debug(err)
			c.Close()
			break
		}

		v, err := e.Open()
		if err != nil {
			log.WithFields(log.Fields{"call": "Envelope.Open"}).Error(err)
			continue
		}
		go c.handleResponse(v)
	}
}

func (c *Client) handleResponse(v interface{}) {
	switch v := v.(type) {
	// TODO: Use existing error or new error to indicate need of resending
	case *BadRequestError:
		log.Printf("bad request error: %s", v.Error())
	case *AnnounceConvoRound:
		// As long as the client is connected to the entry server
		// It will send ConvoRequest, no matter fake or authentic
		c.Send(c.nextConvoRequest(v.Round))
	case *AnnounceDialRound:
		c.Send(c.dialHandler.NextDialRequest(v.Round, v.Buckets))
	case *ConvoResponse:
		c.deliverConvoResponse(v)
	case *DialBucket:
		c.dialHandler.HandleDialBucket(v)
	// TODO: Error Message can be more detailed
	case *ConvoError:
		c.handleConvoError(v)
		
	}
}

func (c *Client) nextConvoRequest(round uint32) *ConvoRequest {
	// TODO: Why lock is needed here?
	c.Lock()
	c.roundHandlers[round] = c.convoHandler
	c.Unlock()
	return c.convoHandler.NextConvoRequest(round)
}

func (c *Client) deliverConvoResponse(r *ConvoResponse) {
	c.Lock()
	convo, ok := c.roundHandlers[r.Round]
	delete(c.roundHandlers, r.Round)
	c.Unlock()
	if !ok {
		log.WithFields(log.Fields{"round": r.Round}).Error("round not found")
		return
	}

	convo.HandleConvoResponse(r)
}
func (c *Client) handleConvoError(e *ConvoError) {
	c.Lock()
	convo, ok := c.roundHandlers[e.Round]
	delete(c.roundHandlers, e.Round)
	c.Unlock()
	if !ok {
		log.WithFields(log.Fields{"round": e.Round}).Error("round not found")
		return
	}
	convo.HandleConvoError(e)
}
