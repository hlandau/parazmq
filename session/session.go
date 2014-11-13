package parazmq
import "io"
import "strings"
import "net"
import "net/url"
import "fmt"
import "github.com/hlandau/parazmq/abstract"
import "github.com/hlandau/parazmq/rawsession"
import "github.com/hlandau/parazmq/nullsession"
import "github.com/hlandau/parazmq/plainsession"
import "github.com/hlandau/parazmq/curvesession"

type SessionConfig struct {
  SessionType string
  AuthMechanism string
  AuthIsServer bool
  Identity string

  AuthPlainUsername string
  AuthPlainPassword string
  AuthPlainServerValidateFunc func(username, password string) bool

  AuthCurvek [32]byte
  AuthCurveS [32]byte

  Dialer net.Dialer

  SubscribeFunc func(name string) error
  CancelFunc func(name string) error
}

type Session interface {
  Close() error
  Write(msg [][]byte) error
  Read() (msg [][]byte, err error)
}

type session struct {
  fc abstract.FrameConn
  rs *rawsession.RawSession
  conn net.Conn

  cfg SessionConfig
  closed bool
  remoteIsServer bool
}

// Connect to an URL and establish a ZMTP session.
func Connect(URL string, cfg SessionConfig) (si Session, err error) {
  u, err := url.Parse(URL)
  if err != nil {
    return
  }

  if u.Scheme != "tcp" {
    err = fmt.Errorf("unsupported scheme")
    return
  }

  c, err := cfg.Dialer.Dial("tcp", u.Host)
  if err != nil {
    return
  }

  return New(c, cfg)
}

// Create a ZMTP session on an existing socket.
func New(c net.Conn, cfg SessionConfig) (si Session, err error) {
  s := session{}

  s.cfg = cfg
  s.conn = c

  if !validSessionType(s.cfg.SessionType) {
    err = fmt.Errorf("invalid session type")
    return
  }

  if !validMechanism(s.cfg.AuthMechanism) {
    err = fmt.Errorf("invalid mechanism")
    return
  }

  err = s.greeting()
  if err != nil {
    s.conn.Close()
    return
  }

  s.rs, err = rawsession.New(s.conn, abstract.ZMTP3_0)
  if err != nil {
    return
  }

  err = s.handshake()
  if err != nil {
    s.rs.Close()
    return
  }

  si = &s
  return
}

func validSessionType(st string) bool {
  switch st {
    case "REQ","REP","ROUTER","DEALER","PUB","SUB","XPUB","XSUB","PUSH","PULL","PAIR":
      return true
    default:
      return false
  }
}

func validMechanism(m string) bool {
  switch m {
    case "NULL", "PLAIN", "CURVE":
      return true
    default:
      return false
  }
}

func (s *session) Close() error {
  if s.closed {
    return nil
  }

  err := s.fc.Close()
  if err != nil {
    return err
  }

  s.closed = true
  return nil
}

func (s *session) Write(msg [][]byte) error {
  for i := range msg {
    f := abstract.ZF_None
    if i < len(msg)-1 {
      f |= abstract.ZF_More
    }

    err := s.fc.SendFrame(msg[i], f)
    if err != nil {
      return err
    }
  }
  return nil
}

func (s *session) Read() (data [][]byte, err error) {
  for {
    var fdata  []byte
    var fflags abstract.ZMTPFlags
    fdata, fflags, err = s.fc.ReceiveFrame()
    if err != nil {
      data = make([][]byte, 0)
      return
    }

    if (fflags & abstract.ZF_Command) != 0 {
      err = s.processIncomingCommand(fdata)
      if err != nil {
        return
      }
      continue
    }

    data = append(data, fdata)
    if (fflags & abstract.ZF_More) == 0 {
      break
    }
  }
  return
}

func (s *session) greeting() error {
  err := s.sendGreeting()
  if err != nil {
    return err
  }

  err = s.receiveGreeting()
  if err != nil {
    return err
  }

  return nil
}

func (s *session) sendGreeting() error {
  if len(s.cfg.AuthMechanism) > 20 {
    panic("oversized mechanim name")
  }

  asServer := byte(0)
  if s.cfg.AuthIsServer {
    asServer = 1
  }

  greeting    := make([]byte, 64)
  greeting[0]  = 0xFF
  greeting[9]  = 0x7F
  greeting[10] = 0x03
  greeting[11] = 0x00
  copy(greeting[12:], []byte(s.cfg.AuthMechanism))
  greeting[32] = asServer
  // rest of greeting is all zeroes

  _, err := s.conn.Write(greeting)
  if err != nil {
    s.conn.Close()
    return err
  }

  return nil
}

func (s *session) receiveGreeting() error {
  greeting  := make([]byte, 64)

  _, err := io.ReadFull(s.conn, greeting)
  if err != nil {
    s.conn.Close()
    return err
  }

  if greeting[0] != 0xFF || greeting[9] != 0x7F || greeting[10] < 0x03 {
    s.conn.Close()
    return fmt.Errorf("Received malformed greeting.")
  }

  s.remoteIsServer = ((greeting[32] & 1) != 0)
  remoteMechanism := strings.TrimRight(string(greeting[12:31]), "\x00")

  if remoteMechanism != s.cfg.AuthMechanism {
    //s.sendErrorCommand("Mechanism mismatch")
    s.conn.Close()
    return fmt.Errorf("Remote peer specified different mechanism: %s", remoteMechanism)
  }

  return nil
}

func (s *session) handshake() error {
  switch s.cfg.AuthMechanism {
    case "NULL":
      return s.handshakeNULL()
    case "PLAIN":
      return s.handshakePLAIN()
    case "CURVE":
      return s.handshakeCURVE()
    default:
      return fmt.Errorf("Unsupported mechanism: %s", s.cfg.AuthMechanism)
  }
}

func (s *session) handshakeNULL() error {
  cfg := nullsession.NullConfig{}
  cfg.IsServer = s.cfg.AuthIsServer
  cfg.Metadata = s.getOutgoingMetadata()

  fc, err := nullsession.New(s.rs, cfg)
  if err != nil {
    return err
  }

  s.fc = fc
  return nil
}

func (s *session) handshakePLAIN() error {
  cfg := plainsession.PlainConfig{}
  cfg.IsServer = s.cfg.AuthIsServer
  cfg.Metadata = s.getOutgoingMetadata()
  cfg.Username = s.cfg.AuthPlainUsername
  cfg.Password = s.cfg.AuthPlainPassword
  cfg.ServerValidateFunc = s.cfg.AuthPlainServerValidateFunc

  fc, err := plainsession.New(s.rs, cfg)
  if err != nil {
    return err
  }

  s.fc = fc
  return nil
}

func (s *session) handshakeCURVE() error {
  cfg := curvesession.CurveConfig{}
  cfg.IsServer = s.cfg.AuthIsServer
  cfg.Metadata = s.getOutgoingMetadata()
  cfg.Curvek = s.cfg.AuthCurvek
  cfg.CurveS = s.cfg.AuthCurveS

  fc, err := curvesession.New(s.rs, cfg)
  if err != nil {
    return err
  }

  s.fc = fc
  return nil
}

func (s *session) getOutgoingMetadata() (md map[string]string) {
  md = map[string]string {}

  md["Socket-Type"] = s.cfg.SessionType

  if s.cfg.Identity != "" {
    md["Identity"]    = s.cfg.Identity
  }

  return
}

func (s *session) processIncomingCommand(data []byte) error {
  cmdName, cmdData, err := abstract.DeserializeCommand(data)
  if err != nil {
    return err
  }

  switch cmdName {
    case "SUBSCRIBE":
      return s.processIncomingSubscribe(cmdData)
    case "CANCEL":
      return s.processIncomingCancel(cmdData)
    case "PING":
      return s.processIncomingPing(cmdData)
    case "PONG":
      return s.processIncomingPong(cmdData)
    default:
      return fmt.Errorf("Received unexpected command: \"%s\"", cmdName)
  }

  return nil
}

func (s *session) processIncomingSubscribe(cmdData []byte) error {
  if !s.isPub() {
    return fmt.Errorf("Got SUBSCRIBE command on non-PUB/XSUB session.")
  }

  if s.cfg.SubscribeFunc == nil {
    return fmt.Errorf("Got SUBSCRIBE command but no callback specified.")
  }

  subName := string(cmdData)
  return s.cfg.SubscribeFunc(subName)
}

func (s *session) processIncomingCancel(cmdData []byte) error {
  if !s.isPub() {
    return fmt.Errorf("Got CANCEL command on non-PUB/XPUB session.")
  }

  if s.cfg.CancelFunc == nil {
    return fmt.Errorf("Got CANCEL command but no callback specified.")
  }

  subName := string(cmdData)
  return s.cfg.CancelFunc(subName)
}

func (s *session) processIncomingPing(cmdData []byte) error {
  if len(cmdData) < 2 {
    return fmt.Errorf("received malformed PING command")
  }

  return abstract.FCSendCommand(s.fc, "PONG", cmdData[2:])
}

func (s *session) processIncomingPong(cmdData []byte) error {
  // We ignore this because ANY incoming data results in a touch.
  // For this reason there's no point matching on the context value.

  //self.touch()
  return nil
}

func (s *session) isPub() bool {
  return s.cfg.SessionType == "PUB" || s.cfg.SessionType == "XPUB"
}
