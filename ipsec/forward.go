// Package ipsec contains a IPSEC packet forwarder.
package ipsec

import (
	"log"
	"net"
	"sync"
	"time"
)

const bufferSize = 4096

type connection struct {
	available  chan struct{}
	rConn      *net.UDPConn
	lastActive time.Time
}

// Forwarder represents a IPSEC packet forwarder.
type Forwarder struct {
	raddr        *net.UDPAddr
	listenerConn *net.UDPConn

	clients          sync.Map

	connectCallback    func(addr string)
	disconnectCallback func(addr string)

	timeout time.Duration

	closed bool
}

// DefaultTimeout is the default timeout period of inactivity for convenience
// sake. It is equivelant to 5 minutes.
const DefaultTimeout = time.Minute * 5

// Forward forwards IPSEC packets from the laddr address to the raddr address, with a
// timeout to "disconnect" clients after the timeout period of inactivity. It
// implements a reverse NAT and thus supports multiple seperate users. Forward
// is also asynchronous.
func Forward(src, dst string, timeout time.Duration) (*Forwarder, error) {
	forwarder := new(Forwarder)
	forwarder.connectCallback = func(addr string) {}
	forwarder.disconnectCallback = func(addr string) {}
	forwarder.clients = sync.Map{}
	forwarder.timeout = timeout

	listenAddr, err := net.ResolveUDPAddr("udp", src)
	if err != nil {
		return nil, err
	}

	forwarder.raddr, err = net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return nil, err
	}

	forwarder.listenerConn, err = net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, err
	}

	go forwarder.janitor()
	go forwarder.run()

	return forwarder, nil
}

func (f *Forwarder) run() {
	for {
		buf := make([]byte, bufferSize)
		oob := make([]byte, bufferSize)
		n, _, _, addr, err := f.listenerConn.ReadMsgUDP(buf, oob)
		if err != nil {
			log.Println("forward: failed to read, terminating:", err)
			return
		}
		go f.handle(buf[:n], addr)
	}
}

func (f *Forwarder) janitor() {
	for !f.closed {
		time.Sleep(f.timeout)
		var keysToDelete []interface{}

		f.clients.Range(func(key, value interface{}) bool {
			client := value.(*connection)
			if client.lastActive.Before(time.Now().Add(-f.timeout)) {
				keysToDelete = append(keysToDelete, key)
			}
			return true
		})

		for _, key := range keysToDelete {
			if value, loaded := f.clients.LoadAndDelete(key); loaded {
				value.(*connection).rConn.Close()
			}
		}

		for _, key := range keysToDelete {
			f.disconnectCallback(key.(string))
		}
	}
}

func (f *Forwarder) handle(data []byte, addr *net.UDPAddr) {
	cliAddr := addr.String()
	value, loaded := f.clients.Load(cliAddr)
	if !loaded {
		value = &connection{
			available:  make(chan struct{}),
			rConn:      nil,
			lastActive: time.Now(),
		}
		f.clients.Store(cliAddr, value)
	}
	client := value.(*connection)

	if !loaded {
		var rconn *net.UDPConn
		var err error
		if f.raddr.IP.To4()[0] == 127 {
			// log.Println("using local listener")
			laddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:")
			rconn, err = net.DialUDP("udp", laddr, f.raddr)
		} else {
			rconn, err = net.DialUDP("udp", nil, f.raddr)
		}
		if err != nil {
			log.Println("failed to dial:", err)
			f.clients.Delete(cliAddr)
			return
		}

		client.rConn = rconn
		client.lastActive = time.Now()
		close(client.available)

		f.connectCallback(cliAddr)

		_, _, err = client.rConn.WriteMsgUDP(data, nil, nil)
		if err != nil {
			log.Println("error sending initial packet to client", err)
		}

		for {
			// log.Println("in loop to read from NAT connection to servers")
			buf := make([]byte, bufferSize)
			oob := make([]byte, bufferSize)
			n, _, _, _, err := client.rConn.ReadMsgUDP(buf, oob)
			if err != nil {
				client.rConn.Close()
				f.clients.Delete(cliAddr)
				f.disconnectCallback(cliAddr)
				log.Println("abnormal read, closing:", err)
				return
			}

			// log.Println("sent packet to client")
			_, _, err = f.listenerConn.WriteMsgUDP(buf[:n], nil, addr)
			if err != nil {
				log.Println("error sending packet to client:", err)
			}
		}

		// unreachable
	}

	<-client.available

	// log.Println("sent packet to server", client.rConn.RemoteAddr())
	_, _, err := client.rConn.WriteMsgUDP(data, nil, nil)
	if err != nil {
		log.Println("error sending packet to server:", err)
	}

	if value, loaded := f.clients.Load(cliAddr); loaded {
		client := value.(*connection)
		// If should change time
		if client.lastActive.Before(time.Now().Add(f.timeout / 4)) {
			client.lastActive = time.Now()
		}
	}
}

// Close stops the forwarder.
func (f *Forwarder) Close() {
	f.closed = true
	f.clients.Range(func(key, value interface{}) bool {
		value.(*connection).rConn.Close()
		return true
	})
	f.listenerConn.Close()
}

// OnConnect can be called with a callback function to be called whenever a
// new client connects.
func (f *Forwarder) OnConnect(callback func(addr string)) {
	f.connectCallback = callback
}

// OnDisconnect can be called with a callback function to be called whenever a
// new client disconnects (after 5 minutes of inactivity).
func (f *Forwarder) OnDisconnect(callback func(addr string)) {
	f.disconnectCallback = callback
}

// Connected returns the list of connected clients in IP:port form.
func (f *Forwarder) Connected() []string {
	var results []string
	f.clients.Range(func(key, value interface{}) bool {
		results = append(results, key.(string))
		return true
	})
	return results
}
