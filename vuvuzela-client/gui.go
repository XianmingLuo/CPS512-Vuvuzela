package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/jroimartin/gocui"

	. "vuvuzela.io/vuvuzela"
	. "vuvuzela.io/vuvuzela/internal"
)

type GuiClient struct {
	sync.Mutex

	pki          *PKI
	myName       string
	myPublicKey  *BoxKey
	myPrivateKey *BoxKey

	gui    *gocui.Gui
	client *Client

	selectedConvo *Conversation
	conversations map[string]*Conversation
	dialer        *Dialer
	
	

	
}
func (gc *GuiClient) logLatency(latency time.Duration) {
	filename := "../results/" + gc.myName + ".lat"
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)		
		return
	}
	to_write := fmt.Sprintf("%f\n", float64(latency)/float64(1e9))
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

func (gc *GuiClient) switchConversation(peer string) {
	var convo *Conversation

	convo, ok := gc.conversations[peer]
	if !ok {
		peerPublicKey, ok := gc.pki.People[peer]
		if !ok {
			// Temporary hack
			if peer == gc.myName {
				peerPublicKey = gc.myPublicKey
			} else {
				gc.Warnf("unknown user: %s", peer)
				return	
			}
		}
		convo = &Conversation{
			route:         gc.pki.ServerOrder,
			pki:           gc.pki,
			peerName:      peer,
			peerPublicKey: peerPublicKey,
			myPublicKey:   gc.myPublicKey,
			myPrivateKey:  gc.myPrivateKey,
			gui:           gc,
		}
		convo.Init()
		gc.conversations[peer] = convo
	}

	gc.selectedConvo = convo
	gc.activateConvo(convo)
	gc.Warnf("Now talking to %s\n", peer)
}

func (gc *GuiClient) activateConvo(convo *Conversation) {
	if gc.client != nil {
		convo.Lock()
		convo.lastPeerResponding = false
		convo.lastLatency = 0
		convo.Unlock()
		gc.client.SetConvoHandler(convo)
	}
}

func (gc *GuiClient) handleLine(line string) error {
	switch {
	case line == "/quit":
		return gocui.ErrQuit
	case strings.HasPrefix(line, "/talk "):
		peer := line[6:]
		gc.switchConversation(peer)
	case strings.HasPrefix(line, "/dial "):
		peer := line[6:]
		pk, ok := gc.pki.People[peer]
		if !ok {
			gc.Warnf("Unknown user: %q (see %s)\n", peer, *pkiPath)
			return nil
		}
		gc.Warnf("Dialing user: %s\n", peer)
		gc.dialer.QueueRequest(pk)
	default:
		// Message
		msg := strings.TrimSpace(line)
		gc.selectedConvo.QueueTextMessage([]byte(msg))
		gc.Printf("<%s> %s\n", gc.myName, msg)
	}
	return nil
}

func (gc *GuiClient) readLine(_ *gocui.Gui, v *gocui.View) error {
	// HACK: pressing enter on startup causes panic
	line := strings.TrimRight(v.Buffer(), "\n")
	if line == "" {
		return nil
	}
	v.EditNewLine()
	v.MoveCursor(0, -1, true)
	v.Clear()
	return gc.handleLine(line)
}

func (gc *GuiClient) redraw() {
	
	/*
	gc.gui.Update(func(gui *gocui.Gui) error {
		return nil
	})*/
}


func (gc *GuiClient) Warnf(format string, v ...interface{}) {
	fmt.Printf("-!- "+format, v...)
	/*
	gc.gui.Update(func(gui *gocui.Gui) error {
		mv, err := gui.View("main")
		if err != nil {
			return err
		}
		fmt.Fprintf(mv, "-!- "+format, v...)
		return nil
	})*/
}

func (gc *GuiClient) Printf(format string, v ...interface{}) {
	fmt.Printf(format, v...)
	/*
	gc.gui.Update(func(gui *gocui.Gui) error {
		mv, err := gui.View("main")
		if err != nil {
			return err
		}
		fmt.Fprintf(mv, format, v...)
		return nil
	})*/
}

func (gc *GuiClient) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if v, err := g.SetView("main", 0, -1, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Autoscroll = true
		v.Wrap = true
		v.Frame = false
		log.AddHook(gc)
		log.SetOutput(ioutil.Discard)
		log.SetFormatter(&GuiFormatter{})
	}
	sv, err := g.SetView("status", -1, maxY-3, maxX, maxY-1)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		sv.Wrap = false
		sv.Frame = false
		sv.BgColor = gocui.ColorBlue
		sv.FgColor = gocui.ColorWhite
	}
	sv.Clear()

	st := gc.selectedConvo.Status()
	latency := fmt.Sprintf("%.2fs", st.Latency)
	if st.Latency == 0.0 {
		latency = "-"
	}
	round := fmt.Sprintf("%d", st.Round)
	if st.Round == 0 {
		round = "-"
	}
	fmt.Fprintf(sv, " [%s]  [round: %s]  [latency: %s]", gc.myName, round, latency)

	partner := "(no partner)"
	if !gc.selectedConvo.Solo() {
		partner = gc.selectedConvo.peerName
	}

	pv, err := g.SetView("partner", -1, maxY-2, len(partner)+1, maxY)
	if err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		pv.Wrap = false
		pv.Frame = false
	}
	pv.Clear()

	if st.PeerResponding {
		pv.FgColor = gocui.ColorGreen
	} else {
		pv.FgColor = gocui.ColorRed
	}
	fmt.Fprintf(pv, "%s>", partner)

	if v, err := g.SetView("input", len(partner)+1, maxY-2, maxX, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Editable = true
		v.Wrap = false
		v.Frame = false
		if _, err := g.SetCurrentView("input"); err != nil {
			return err
		}
	}

	return nil
}

func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func (gc *GuiClient) Connect() error {
	if gc.client == nil {
		gc.client = NewClient(gc.pki.EntryServer, gc.myPublicKey)
		gc.client.SetDialHandler(gc.dialer)
	}
	gc.activateConvo(gc.selectedConvo)
	return gc.client.Connect()
}

func (gc *GuiClient) Run() {
	/*
	gui, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		log.Panicln(err)
	}
	defer gui.Close()
	gc.gui = gui

	gui.SetManagerFunc(gc.layout)

	if err := gui.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		log.Panicln(err)
	}
	if err := gui.SetKeybinding("input", gocui.KeyEnter, gocui.ModNone, gc.readLine); err != nil {
		log.Panicln(err)
	}
	gui.Cursor = true
	gui.BgColor = gocui.ColorDefault
	gui.FgColor = gocui.ColorDefault
	
	*/
	gc.conversations = make(map[string]*Conversation)
	gc.switchConversation(gc.myName)

	
	gc.dialer = &Dialer{
		gui:          gc,
		pki:          gc.pki,
		myPublicKey:  gc.myPublicKey,
		myPrivateKey: gc.myPrivateKey,
	}
	gc.dialer.Init()

	go func() {
		time.Sleep(500 * time.Millisecond)
		if err := gc.Connect(); err != nil {
			gc.Warnf("Failed to connect: %s\n", err)
		}
		gc.Warnf("Connected: %s\n", gc.pki.EntryServer)
	}()

	for {}
	/*
	err = gui.MainLoop()
	if err != nil && err != gocui.ErrQuit {
		log.Panicln(err)
	}*/
}

func (gc *GuiClient) Fire(entry *log.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}

	gc.Warnf(line)
	return nil
}

func (gc *GuiClient) Levels() []log.Level {
	return []log.Level{
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
		log.InfoLevel,
		log.DebugLevel,
	}
}
