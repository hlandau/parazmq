package socket
import "container/list"
import "net/url"
import "errors"
import "net"
import dnet "github.com/hlandau/degoutils/net"
import "time"
import "sync"

type SocketType byte
const (
  ST_REQ    SocketType = 1+iota
  ST_REP
  ST_DEALER
  ST_ROUTER
  ST_PUB
  ST_SUB
  ST_PUSH
  ST_PULL
  ST_PAIR
  ST_STREAM
)

type Socket interface {
  Close() error

  Connect(addr string) error
  Disconnect(addr string) error

  Bind(addr string) error
  Unbind(addr string) error

  Write(m Message) error
  Read() (Message, error)
}

type Message interface {
  Parts() [][]byte
}

type message struct {
  parts [][]byte
}

func (m *message) Parts() [][]byte {
  return m.parts
}

func NewMessage(parts [][]byte) Message {
  m := &message {
    parts: parts,
  }
  return m
}

type socket struct {
  socketType SocketType
  connects   list.List // []connect
  binds      list.List // []bind
  peers      list.List // []peer
  rxChan     chan Message
  txChan     chan Message
}

func New(socketType SocketType) (Socket, error) {
  s := &socket {
    socketType: socketType,
    rxChan: make(chan Message, 10),
    txChan: make(chan Message, 10),
  }

  return s, nil
}

func (s *socket) isServer() bool {
  return false
}

func (s *socket) desiredMechanism() string {
  return "NULL"
}

func (s *socket) Close() error {
  // TODO
  return nil
}

func (s *socket) Connect(addr string) error {
  c := &connect {
    s:         s,
    endpoint:  addr,
  }

  err := c.start()
  if err != nil {
    return err
  }

  s.connects.PushBack(c)
  return nil
}

func (s *socket) Bind(addr string) error {
  b := &bind {
    s:        s,
    endpoint: addr,
  }

  err := b.start()
  if err != nil {
    return err
  }

  s.binds.PushBack(b)
  return nil
}

func (s *socket) Disconnect(addr string) error {
  for e := s.connects.Front(); e != nil; e = e.Next() {
    ec := e.Value.(*connect)
    if ec.endpoint != addr {
      continue
    }

    err := ec.stop()
    if err != nil {
      return err
    }

    s.connects.Remove(e)
    return nil
  }

  return errors.New("No such endpoint.")
}

func (s *socket) Unbind(addr string) error {
  for e := s.binds.Front(); e != nil; e = e.Next() {
    ec := e.Value.(*bind)
    if ec.endpoint != addr {
      continue
    }

    err := ec.stop()
    if err != nil {
      return err
    }

    s.binds.Remove(e)
    return nil
  }

  return errors.New("No such endpoint.")
}

func (s *socket) Read() (Message, error) {
  m := <-s.rxChan
  return m, nil
}

func (s *socket) Write(m Message) error {
  s.txChan <- m
  return nil
}

type bind struct {
  s        *socket
  endpoint string
  listener net.Listener
}

type empty struct{}

type connect struct {
  s        *socket
  endpoint string
  conn     net.Conn
  stopChan chan empty
  retryConfig dnet.RetryConfig
}

func (c *connect) loop() {
  u, err := url.Parse(c.endpoint)
  if err != nil {
    panic("bad endpoint?")
  }

  for {
    conn, err := net.Dial("tcp", u.Host)
    if err != nil {
      c.evChan <- connectEvent{ceConnected, conn}
      c.retryConfig.Reset()
      newPeer(conn, c.s)
      // this loop will be restarted if the connection fails
      return
    }
    a := time.After(time.Duration(c.retryConfig.GetStepDelay())*time.Millisecond)
    select {
      case cmd := <-c.ctrlChan:
        return
      case <-a:
    }
  }
}

func (c *connect) disconnected() {
  go c.connectLoop()
}

func (c *connect) start() error {
  u, err := url.Parse(c.endpoint)
  if err != nil {
    return err
  }

  switch u.Scheme {
    case "tcp":
      _, _, err := net.SplitHostPort(u.Host)
      if err != nil {
        return err
      }

      c.stopChan = make(chan empty)

      go c.connectLoop()

      return nil

    default:
      return errors.New("unsupported scheme")
  }
}

func (c *connect) stop() error {
  close(c.stopChan)
  return nil
}

func (b *bind) listenLoop() {
  for {
    conn, err := b.listener.Accept()
    if err != nil {
      return
    }

    newPeer(conn, b.s)
  }
}

func (b *bind) start() error {
  u, err := url.Parse(b.endpoint)
  if err != nil {
    return err
  }

  switch u.Scheme {
    case "tcp":
      _, _, err := net.SplitHostPort(u.Host)
      if err != nil {
        return err
      }

      l, err := net.Listen("tcp", u.Host)
      if err != nil {
        return err
      }

      b.listener = l
      go self.listenLoop()
      return nil

    default:
      return errors.New("unsupported scheme")
  }
}

func (b *bind) stop() error {
  b.listener.Close() // ignore error

  return nil
}

type msg struct {
  parts   [][]byte
  command bool
}

type peer struct {
  s      *socket
  conn   net.Conn
  raw    rawzmtp.RawZMTP
  rxChan   chan msg
  txChan   chan msg
  stopChan chan empty
}

func (p *peer) writeLoop() {
  for {
    select {
      case <-p.stopChan:
        return
      case m := <-p.txChan:
        err := p.raw.Write(m.parts, m.command)
        if err != nil {
          return
        }
    }
  }
}

func (p *peer) loopInner() error {
  r, err := negotiate.GreetZMTP(p.conn, p.s.desiredMechanism(), p.s.isServer())
  if err != nil {
    return err
  }

  p.raw = r
  defer p.raw.Close()

  go self.writeLoop()

  for {
    select {
      case <-p.stopChan:
        return
      default:
    }

    parts, command, err := p.raw.Read()
    if err != nil {
      return err
    }

    p.rxChan <- msg { parts, command }
  }
}

func (p *peer) loop() {
  err := p.loopInner()
  if err != nil {
    // ...
  }
}

func (p *peer) stop() {
  close(p.stopChan)
}

func newPeer(conn net.Conn, s *socket) {
  p := &peer {
    s: s,
    conn: conn,
    rxChan: make(chan msg, 10),
    txChan: make(chan msg, 10),
    stopChan: make(chan empty),
  }

  s.peers.PushBack(p)

  go p.loop()
}
