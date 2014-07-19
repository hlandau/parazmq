package parazmq
import "net"
import "net/url"
import "errors"
import "fmt"
import "encoding/binary"
import "time"
import "io"
import "strings"

type Socket interface {
  Close() error
  Write(msg [][]byte) error
  Read() (msg [][]byte, err error)
}

type socket struct {
  conn net.Conn
  mechanism string

  remoteIsServer bool
  remoteIdentity string
  remoteSocketType string

  maxRead uint64
  identity string
  socketType string
  authIsServer bool

  plainUsername string
  plainPassword string

  sentPingContext string

  closed bool
  lastTouch time.Time
}

func Connect(socketType string, URL string) (si Socket, err error) {
  s := socket{}

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

  if !validSocketType(socketType) {
    err = errors.New("invalid socket type")
    return
  }

  c, err := net.Dial("tcp", u.Host)
  if err != nil {
    return
  }

  s.conn = c
  s.mechanism = "NULL"
  s.socketType = socketType

  err = s.greeting()
  if err != nil {
    s.conn.Close()
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

func validSocketType(st string) bool {
  switch st {
    case "REQ","REP","ROUTER","DEALER","PUB","SUB","XPUB","XSUB","PUSH","PULL","PAIR":
      return true
    default:
      return false
  }
}

func (self *socket) Close() error {
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

func (self *socket) Write(msg [][]byte) error {
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

func (self *socket) Read() (data [][]byte, err error) {
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

func (self *socket) greeting() error {
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

func (self *socket) sendGreeting() error {
  if len(self.mechanism) > 20 {
    panic("oversize mechanism name")
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

func (self *socket) receiveGreeting() error {
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

type zmtpFlags byte
const (
  zf_More     zmtpFlags = 1<<0
  zf_Long               = 1<<1
  zf_Command            = 1<<2
)

func (self *socket) sendErrorCommand(errMsg string) error {
  if len(errMsg) > 255 {
    panic("error message too long")
  }

  buf    := make([]byte, 1+len(errMsg))
  buf[0]  = byte(len(errMsg))
  copy(buf[1:], []byte(errMsg))
  return self.sendCommand("ERROR", buf)
}

func (self *socket) sendCommand(cmdName string, cmdData []byte) error {
  if len(cmdName) > 255 {
    panic("command name too long")
  }

  buf := make([]byte, 1+len(cmdName)+len(cmdData))
  buf[0] = byte(len(cmdName))
  copy(buf[1:], []byte(cmdName))
  copy(buf[1+len(cmdName):], cmdData)

  return self.sendRawFrame(buf, zf_Command)
}

// This processes incoming commands after the handshake is complete. Incoming
// commands received during authentication are processed separately in the
// handshake methods.
func (self *socket) processIncomingCommand(data []byte) error {
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

func (self *socket) isPub() bool {
  return self.socketType == "PUB" || self.socketType == "XPUB"
}

func (self *socket) processIncomingSubscribe(cmdData []byte) error {
  if !self.isPub() {
    return fmt.Errorf("Got SUBSCRIBE command on non-PUB/XPUB socket.")
  }

  // TODO
  //subName = string(cmdData)
  return nil
}

func (self *socket) processIncomingCancel(cmdData []byte) error {
  if !self.isPub() {
    return fmt.Errorf("Got CANCEL command on non-PUB/XPUB socket.")
  }

  // TODO
  //subName = string(cmdData)
  return nil
}

func (self *socket) processIncomingPing(cmdData []byte) error {
  if len(cmdData) < 2 {
    return fmt.Errorf("received malformed PING command")
  }

  return self.sendCommand("PONG", cmdData[2:])
}

func (self *socket) processIncomingPong(cmdData []byte) error {
  // We ignore this because ANY incoming data results in a touch.
  // For this reason there's no point matching on the context value.

  //self.touch()
  return nil
}

func (self *socket) touch() {
  self.lastTouch = time.Now()
}

func (self *socket) receiveCommand() (cmdName string, cmdData []byte, err error) {
  d, flags, err := self.receiveRawFrame()
  if err != nil {
    return
  }

  if (flags & zf_Command) == 0 {
    err = fmt.Errorf("Expected to receive command frame, but got data frame.")
    return
  }

  return self.parseCommand(d)
}

func (self *socket) parseCommand(d []byte) (cmdName string, cmdData []byte, err error) {
  if len(d) == 0 {
    err = fmt.Errorf("Received a zero-length command frame.")
    return
  }

  cmdNameLen := int(d[0])
  if cmdNameLen+1 > len(d) {
    err = fmt.Errorf("Received a malformed command frame.")
    return
  }

  cmdName = string(d[1:1+cmdNameLen])
  cmdData = d[1+cmdNameLen:]
  return
}

func validFlags(flags zmtpFlags) bool {
  if ((flags & zf_Command) != 0) {
    return ((flags & zf_More) == 0)
  }
  return true
}

func (self *socket) sendRawFrame(data []byte, flags zmtpFlags) error {
  if !validFlags(flags) {
    panic(fmt.Sprintf("invalid flags specified: %d", flags))
  }

  hdr := make([]byte, 9)
  if len(data) > 0xFF {
    flags |= zf_Long
    binary.BigEndian.PutUint64(hdr[1:], uint64(len(data)))
  } else {
    hdr[1] = byte(len(data))
    hdr = hdr[0:2]
  }
  hdr[0] = byte(flags)

  _, err := self.conn.Write(hdr)
  if err != nil {
    return err
  }

  _, err = self.conn.Write(data)
  if err != nil {
    return err
  }

  return nil
}

func (self *socket) receiveRawFrame() (data []byte, flags zmtpFlags, err error) {
  var L uint64
  hdr := make([]byte, 9)

  _, err = io.ReadFull(self.conn, hdr[0:2])
  if err != nil {
    return
  }

  flags = zmtpFlags(hdr[0])
  if !validFlags(flags) {
    err = fmt.Errorf("Received malformed frame.")
    return
  }

  if (flags & zf_Long) != 0 {
    _, err = io.ReadFull(self.conn, hdr[2:9])
    if err != nil {
      return
    }

    L = binary.BigEndian.Uint64(hdr[1:])
  } else {
    L = uint64(hdr[1])
  }

  flags = flags & (zf_Long^zmtpFlags(0xFF))

  if self.maxRead != 0 && L > self.maxRead {
    // TODO FAULT MODE
    err = fmt.Errorf("Received frame in excess of the max read size.")
    return
  }

  data = make([]byte, L)
  _, err = io.ReadFull(self.conn, data)

  self.touch()

  return
}

func (self *socket) handshake() error {
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

func (self *socket) handshakeWaitForMetadata(inCmdName string) error {
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

func (self *socket) handshakeAsClientFinalStretch(outCmdName, inCmdName string) error {
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

func (self *socket) handshakeAsServerFinalStretch(inCmdName, outCmdName string) error {
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

func (self *socket) handshakeNULL() error {
  return self.handshakeAsClientFinalStretch("READY", "READY")
}

func (self *socket) handshakePLAIN() error {
  if self.authIsServer {
    return self.handshakePLAINAsServer()
  } else {
    return self.handshakePLAINAsClient()
  }
}

func (self *socket) handshakePLAINAsClient() error {
  if len(self.plainUsername) > 0xFF || len(self.plainPassword) > 0xFF {
    panic("Username or password is too long.")
  }

  buf := make([]byte, 2+len(self.plainUsername)+len(self.plainPassword))
  buf[0] = byte(len(self.plainUsername))
  copy(buf[1:], []byte(self.plainUsername))
  buf[1+len(self.plainUsername)] = byte(len(self.plainPassword))
  copy(buf[1+len(self.plainPassword)+1:], []byte(self.plainPassword))

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

func (self *socket) handshakePLAINAsServer() error {
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

func (self *socket) validatePLAIN(username, password string) bool {
  // XXX TODO
  return true
}

func (self *socket) handshakeCURVE() error {
  return fmt.Errorf("CURVE not supported")
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

func (self *socket) getOutgoingMetadata() (md map[string]string) {
  md = map[string]string {}

  md["Socket-Type"] = self.socketType

  if self.identity != "" {
    md["Identity"] = self.identity
  }

  // md["Resource"]

  return
}

func (self *socket) processIncomingMetadata(md map[string]string) error {
  if ident, ok := md["Identity"]; ok {
    self.remoteIdentity = ident
  }

  if sockType, ok := md["Socket-Type"]; ok {
    self.remoteSocketType = sockType
  } else {
    return fmt.Errorf("Peer did not specify a socket type.")
  }

  if !socketTypesCompatible(self.socketType, self.remoteSocketType) {
    return fmt.Errorf("Socket types are not compatible: %s, %s", self.socketType, self.remoteSocketType)
  }

  // md["Resource"]

  return nil
}

func socketTypesCompatible(localType string, remoteType string) bool {
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

func serializeMetadata(md map[string]string) []byte {
  L := 0
  for k,v := range md {
    L += 5+len(k)+len(v)
  }

  buf := make([]byte, L)
  i   := 0
  for k,v := range md {
    buf[i] = byte(len(k))
    copy(buf[i+1:], []byte(k))
    binary.BigEndian.PutUint32(buf[i+1+len(k):], uint32(len(v)))
    copy(buf[i+5+len(k):], []byte(v))
    i += 5+len(k)+len(v)
  }

  return buf
}

func deserializeMetadata(mdBuf []byte) (md map[string]string, err error) {
  md = map[string]string {}
  for len(mdBuf) > 0 {
    if len(mdBuf) < 5 {
      err = fmt.Errorf("Malformed metadata")
      return
    }

    kLen := uint32(mdBuf[0])
    if uint32(len(mdBuf)) < kLen+5 {
      err = fmt.Errorf("Malformed metadata")
      return
    }

    k := mdBuf[1:1+kLen]
    vLen := binary.BigEndian.Uint32(mdBuf[1+kLen:])
    if uint32(len(mdBuf)) < kLen+5+vLen {
      err = fmt.Errorf("Malformed metadata")
      return
    }

    v    := mdBuf[5+kLen:5+kLen+vLen]
    md[string(k)] = string(v)
    mdBuf = mdBuf[5+kLen+vLen:]
  }
  return
}
