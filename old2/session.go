package parazmq
import "net"
import "net/url"
import "errors"
import "fmt"
import "encoding/binary"
import "time"
import "io"
import "strings"
import "code.google.com/p/go.crypto/nacl/box"
import "code.google.com/p/go.crypto/curve25519"
import "crypto/rand"
import "bytes"
import "github.com/hlandau/parazmq/rawsession"

type Socket interface {

}

type socket struct {
  socketType string
}


type Session interface {
  Close() error
  Write(msg [][]byte) error
  Read() (msg [][]byte, err error)
}

type session struct {
  conn net.Conn
  mechanism string

  remoteIsServer bool
  remoteIdentity string
  remoteSessionType string

  maxRead uint64
  identity string
  sessionType string
  authIsServer bool

  plainUsername string
  plainPassword string

  sentPingContext string

  closed bool
  lastTouch time.Time

  rs *rawsession.RawSession
}

type SessionConfig struct {
  AuthMechanism string
  AuthIsServer  bool
  SessionType   string
  Identity      string
  MaxRead       uint64
  Dialer        net.Dialer

  AuthPlainUsername string
  AuthPlainPassword string

  AuthCurvek [32]byte // own private key
  AuthCurveS [32]byte // server's public key (required only if we are a client)
}

func Connect(URL string, cfg SessionConfig) (si Session, err error) {
  s := session{}

  // tcp://hostname:port
  // tcp://hostname:port/resource
  // ...

  u, err := url.Parse(URL)
  if err != nil {
    return
  }

  if u.Scheme != "tcp" {
    err = errors.New("unsupported scheme")
    return
  }

  if !validSessionType(cfg.SessionType) {
    err = errors.New("invalid session type")
    return
  }

  if !validMechanism(cfg.AuthMechanism) {
    err = errors.New("invalid mechanism")
    return
  }

  s.mechanism = cfg.AuthMechanism
  s.sessionType = cfg.SessionType
  s.authIsServer = cfg.AuthIsServer
  s.identity = cfg.Identity
  s.maxRead = cfg.MaxRead
  s.plainUsername = cfg.AuthPlainUsername
  s.plainPassword = cfg.AuthPlainPassword

  c, err := cfg.Dialer.Dial("tcp", u.Host)
  if err != nil {
    return
  }
  s.conn = c

  err = s.greeting()
  if err != nil {
    s.conn.Close()
    return
  }

  s.rs, err = rawsession.New(c, rawsession.ZMTP3_0)
  if err != nil {
    return
  }

  err = s.handshake()
  if err != nil {
    s.conn.Close()
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

func (self *session) Close() error {
  if self.closed {
    return nil
  }

  err := self.conn.Close()
  if err != nil {
    return err
  }

  self.closed = true
  return nil
}

func (self *session) Write(msg [][]byte) error {
  for i := range msg {
    f := zmtpFlags(0)
    if i < len(msg)-1 {
      f |= zf_More
    }

    err := self.sendRawFrame(msg[i], f)
    if err != nil {
      return err
    }
  }
  return nil
}

func (self *session) Read() (data [][]byte, err error) {
  for {
    var fdata  []byte
    var fflags zmtpFlags
    fdata, fflags, err = self.receiveRawFrame()
    if err != nil {
      data = make([][]byte, 0)
      return
    }

    if (fflags & zf_Command) != 0 {
      err = self.processIncomingCommand(fdata)
      if err != nil {
        return
      }
      continue
    }

    data = append(data, fdata)
    if (fflags & zf_More) == 0 {
      break
    }
  }
  return
}

func (self *session) greeting() error {
  err := self.sendGreeting()
  if err != nil {
    return err
  }

  err = self.receiveGreeting()
  if err != nil {
    return err
  }

  return nil
}

func (self *session) sendGreeting() error {
  if len(self.mechanism) > 20 {
    panic("oversized mechanism name")
  }

  asServer := byte(0)
  if self.authIsServer {
    asServer = 1
  }

  greeting     := make([]byte, 64)
  greeting[ 0]  = 0xFF
  greeting[ 9]  = 0x7F
  greeting[10]  = 0x03
  greeting[11]  = 0x00
  copy(greeting[12:], []byte(self.mechanism))
  greeting[32]  = asServer
  // rest of greeting is all zeroes

  _, err := self.conn.Write(greeting)
  if err != nil {
    self.conn.Close()
    return err
  }

  return nil
}

func (self *session) receiveGreeting() error {
  greeting   := make([]byte, 64)

  _, err := io.ReadFull(self.conn, greeting)
  if err != nil {
    self.conn.Close()
    return err
  }

  if greeting[0] != 0xFF || greeting[9] != 0x7F || greeting[10] < 0x03 {
    self.conn.Close()
    return errors.New("Received malformed greeting.")
  }

  self.remoteIsServer = ((greeting[32] & 1) != 0)
  remoteMechanism := strings.TrimRight(string(greeting[12:31]), "\x00")

  if remoteMechanism != self.mechanism {
    self.sendErrorCommand("Mechanism mismatch")
    self.conn.Close()
    return fmt.Errorf("Remote peer specified different mechanism: %s", remoteMechanism)
  }

  return nil
}

// This processes incoming commands after the handshake is complete. Incoming
// commands received during authentication are processed separately in the
// handshake methods.
func (self *session) processIncomingCommand(data []byte) error {
  cmdName, cmdData, err := self.parseCommand(data)
  if err != nil {
    return err
  }

  switch cmdName {
    case "SUBSCRIBE":
      return self.processIncomingSubscribe(cmdData)
    case "CANCEL":
      return self.processIncomingCancel(cmdData)
    case "PING":
      return self.processIncomingPing(cmdData)
    case "PONG":
      return self.processIncomingPong(cmdData)
    default:
      return fmt.Errorf("Received unexpected command: \"%s\"", cmdName)
  }

  return nil
}

func (self *session) isPub() bool {
  return self.sessionType == "PUB" || self.sessionType == "XPUB"
}

func (self *session) processIncomingSubscribe(cmdData []byte) error {
  if !self.isPub() {
    return fmt.Errorf("Got SUBSCRIBE command on non-PUB/XPUB session.")
  }

  // TODO
  //subName = string(cmdData)
  return nil
}

func (self *session) processIncomingCancel(cmdData []byte) error {
  if !self.isPub() {
    return fmt.Errorf("Got CANCEL command on non-PUB/XPUB session.")
  }

  // TODO
  //subName = string(cmdData)
  return nil
}

func (self *session) processIncomingPing(cmdData []byte) error {
  if len(cmdData) < 2 {
    return fmt.Errorf("received malformed PING command")
  }

  return self.sendCommand("PONG", cmdData[2:])
}

func (self *session) processIncomingPong(cmdData []byte) error {
  // We ignore this because ANY incoming data results in a touch.
  // For this reason there's no point matching on the context value.

  //self.touch()
  return nil
}

func (self *session) touch() {
  self.lastTouch = time.Now()
}

func (self *session) sendRawFrameLL(data []byte, flags zmtpFlags) error {
  return self.rs.SendFrame(data, flags)
}

func (self *session) receiveRawFrameLL() ([]byte, zmtpFlags, error) {
  return self.rs.ReceiveFrame()
}

func (self *session) sendRawFrame(data []byte, flags zmtpFlags) error {
  if self.curveEngaged {
    return self.sendRawFrameCurve(data, flags)
  } else {
    return self.sendRawFrameLL(data, flags)
  }
}

func (self *session) receiveRawFrame() (data []byte, flags zmtpFlags, err error) {
  data, flags, err = self.receiveRawFrameLL()
  if err != nil {
    return
  }

  if self.curveEngaged {
    if (flags & zf_Command) != 0 {
      if bytes.Equal(data[0:8], curveMessagePrefix) {
        return self.receiveRawFrameCurve(data[8:])
      } else {
        // non-MESSAGE command, pass through (UNAUTHENTICATED)
      }
    } else {
      err = fmt.Errorf("Got non-command message while CurveZMQ is engaged")
    }
  }
  return
}

func (self *session) handshake() error {
  switch self.mechanism {
    case "NULL":
      return self.handshakeNULL()
    case "PLAIN":
      return self.handshakePLAIN()
    case "CURVE":
      return self.handshakeCURVE()
    default:
      return fmt.Errorf("Unsupported mechanism: %s", self.mechanism)
  }
}

func (self *session) handshakeWaitForMetadata(inCmdName string) error {
  cmdName, cmdData, err := self.receiveCommand()
  if err != nil {
    return err
  }

  switch cmdName {
    case inCmdName:
      md, err := deserializeMetadata(cmdData)
      if err != nil {
        return err
      }

      err = self.processIncomingMetadata(md)
      if err != nil {
        return err
      }

      // OK

    case "ERROR":
      return fmt.Errorf("Got error from remote peer: \"%s\"", deserializeError(cmdData))

    default:
      return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
  }

  return nil
}

func (self *session) handshakeAsClientFinalStretch(outCmdName, inCmdName string) error {
  err := self.sendCommand(outCmdName, serializeMetadata(self.getOutgoingMetadata()))
  if err != nil {
    return err
  }

  err = self.handshakeWaitForMetadata(inCmdName)
  if err != nil {
    return err
  }

  return nil
}

func (self *session) handshakeAsServerFinalStretch(inCmdName, outCmdName string) error {
  err := self.handshakeWaitForMetadata(inCmdName)
  if err != nil {
    return err
  }

  err = self.sendCommand(outCmdName, serializeMetadata(self.getOutgoingMetadata()))
  if err != nil {
    return err
  }

  return nil
}

func (self *session) handshakeNULL() error {
  return self.handshakeAsClientFinalStretch("READY", "READY")
}

func (self *session) handshakePLAIN() error {
  if self.authIsServer {
    return self.handshakePLAINAsServer()
  } else {
    return self.handshakePLAINAsClient()
  }
}

func (self *session) handshakePLAINAsClient() error {
  if len(self.plainUsername) > 0xFF || len(self.plainPassword) > 0xFF {
    panic("Username or password is too long.")
  }

  buf := make([]byte, 2+len(self.plainUsername)+len(self.plainPassword))
  buf[0] = byte(len(self.plainUsername))
  copy(buf[1:], []byte(self.plainUsername))
  buf[1+len(self.plainUsername)] = byte(len(self.plainPassword))
  copy(buf[1+len(self.plainUsername)+1:], []byte(self.plainPassword))

  err := self.sendCommand("HELLO", buf)
  if err != nil {
    return err
  }

  cmdName, cmdData, err := self.receiveCommand()
  switch cmdName {
    case "WELCOME":
      // OK
    case "ERROR":
      return fmt.Errorf("Got error from remote peer: \"%s\"", deserializeError(cmdData))
    default:
      return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
  }

  // Now we send our metadata in INITIATE.
  return self.handshakeAsClientFinalStretch("INITIATE", "READY")
}

func (self *session) handshakePLAINAsServer() error {
  cmdName, cmdData, err := self.receiveCommand()
  switch cmdName {
    case "HELLO":
      if len(cmdData) < 2 {
        return fmt.Errorf("Malformed HELLO command received from remote peer.")
      }

      usernameLen := int(cmdData[0])
      if len(cmdData) < 2+usernameLen {
        return fmt.Errorf("Malformed HELLO command received from remote peer.")
      }

      username := string(cmdData[1:1+usernameLen])
      passwordLen := int(cmdData[1+usernameLen])
      if len(cmdData) < 2+usernameLen+passwordLen {
        return fmt.Errorf("Malformed HELLO command received from remote peer.")
      }

      password := string(cmdData[2+usernameLen:2+usernameLen+passwordLen])

      ok := self.validatePLAIN(username,password)

      if ok {
        err = self.sendCommand("WELCOME", []byte{})
        if err != nil {
          return err
        }
      } else {
        err = self.sendErrorCommand("Invalid username or password.")
        if err != nil {
          return err
        }
        return fmt.Errorf("Invalid username or password.") // XXX
      }

      // Wait for INITIATE
      err = self.handshakeAsServerFinalStretch("INITIATE", "READY")
      if err != nil {
        return err
      }

      return nil
    default:
      return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
  }
}

func (self *session) validatePLAIN(username, password string) bool {
  // XXX TODO
  return true
}

func deserializeError(cmdData []byte) string {
  if len(cmdData) == 0 {
    return "(malformed ERROR command)"
  }

  errMsgLen := int(cmdData[0])
  if errMsgLen+1 > len(cmdData) {
    return "(malformed ERROR command)"
  }

  return string(cmdData[1:1+errMsgLen])
}

func (self *session) getOutgoingMetadata() (md map[string]string) {
  md = map[string]string {}

  md["Socket-Type"] = self.sessionType

  if self.identity != "" {
    md["Identity"] = self.identity
  }

  // md["Resource"]

  return
}

func (self *session) processIncomingMetadata(md map[string]string) error {
  fmt.Printf("md: %+v\n", md)
  if ident, ok := md["Identity"]; ok {
    self.remoteIdentity = ident
  }

  if sockType, ok := md["Socket-Type"]; ok {
    self.remoteSessionType = sockType
  } else {
    return fmt.Errorf("Peer did not specify a socket type.")
  }

  if !sessionTypesCompatible(self.sessionType, self.remoteSessionType) {
    return fmt.Errorf("Session types are not compatible: %s, %s", self.sessionType, self.remoteSessionType)
  }

  // md["Resource"]

  return nil
}

func sessionTypesCompatible(localType string, remoteType string) bool {
  /*
       | REQ | REP | DEALER | ROUTER | PUB | XPUB | SUB | XSUB | PUSH | PULL | PAIR |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
REQ    |     |  *  |        |   *    |     |      |     |      |      |      |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
REP    |  *  |     |   *    |        |     |      |     |      |      |      |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
DEALER |     |  *  |   *    |   *    |     |      |     |      |      |      |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
ROUTER |  *  |     |   *    |   *    |     |      |     |      |      |      |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
PUB    |     |     |        |        |     |      |  *  |  *   |      |      |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
XPUB   |     |     |        |        |     |      |  *  |  *   |      |      |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
SUB    |     |     |        |        |  *  |  *   |     |      |      |      |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
XSUB   |     |     |        |        |  *  |  *   |     |      |      |      |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
PUSH   |     |     |        |        |     |      |     |      |      |  *   |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
PULL   |     |     |        |        |     |      |     |      |  *   |      |      |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+
PAIR   |     |     |        |        |     |      |     |      |      |      |  *   |
-------+-----+-----+--------+--------+-----+------+-----+------+------+------+------+*/
  t := localType + "/" + remoteType
  switch t {
    case
      "REQ/REP",    "REQ/ROUTER",    "REP/REQ",       "REP/DEALER",
      "DEALER/REP", "DEALER/DEALER", "DEALER/ROUTER",
      "ROUTER/REQ", "ROUTER/DEALER", "ROUTER/ROUTER",
      "PUB/SUB",    "PUB/XSUB",
      "XPUB/SUB",   "XPUB/XSUB",
      "SUB/PUB",    "SUB/XPUB",
      "XSUB/PUB",   "XSUB/XPUB",
      "PUSH/PULL",
      "PULL/PUSH",
      "PAIR/PAIR":
      return true
    default:
      return false
  }
}
