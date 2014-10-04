package session
import "net"
import "errors"
import "github.com/hlandau/parazmq/rawzmtp"
import "io"
import "strings"
import "fmt"
import "encoding/binary"

type Session interface {
  Close() error
  Read() (m Message, err error)
  Write(m Message)  error
}

type empty struct {}

type session struct {
  rxChan chan Message     // messages received from network
  txChan chan Message     // messages to transmit to network
  stopChan chan empty     // used to stop the TX loop
  canStopChan chan empty  // Closed when session can safely be stopped

  raw    rawzmtp.RawZMTP  // RX loop stops when this is closed
  conn   net.Conn         // connection underlying raw
  closed bool
  config SessionConfig
}

type SessionConfig struct {
  SocketType string
  Identity   string
}

func newSession(conn net.Conn, sc SessionConfig) (Session, error) {
  s := &session{
    rxChan: make(chan Message, 10),
    txChan: make(chan Message, 10),
    stopChan: make(chan empty),
    canStopChan: make(chan empty),
    conn: conn,
    config: sc,
  }

  go self.loop()

  return s, nil
}

func (s *session) Read() (Message, error) {
  m := <-s.rxChan
  return m, nil
}

func (s *session) Write(m Message) error {
  s.txChan <- m
  return nil
}

func (s *session) Close() error {
  if !s.closed {
    s.closed = true
    s.stop()
  }

  return nil
}

func (s *session) stop() {
  <-s.canStopChan
  s.raw.Close()
  close(s.stopChan)
}

func (s *session) loop() {
  err := s.loopInner()
  if err != nil {
    s.closed = true
    if s.raw != nil {
      s.raw.Close()
    }
    // log...
  }
}

func (s *session) loopInner() error {
  r, err := greetingZMTP(s.conn, "NULL", false)
  if err != nil {
    return err
  }

  s.raw = r
  defer s.raw.Close()
  close(s.canStopChan)

  err = s.handshake()
  if err != nil {
    return err
  }

  errCh := make(chan error)
  go func() {
    err := self.txLoop()
    errCh <- err
  }()

  err := self.rxLoop()
  if err != nil {
    return err
  }

  return <-errCh
}

func (s *session) handshake() error {
  err := s.raw.SendReadyCommand(s.getOutgoingMetadata())
  if err != nil {
    return err
  }

  for {
    parts, command, err := s.raw.Read()
    if err != nil {
      return err
    }

    if !command {
      return errors.New("handshake not properly completed")
    }

    
  }

  return nil
}

func (s *session) txLoop() error {
  for {
    select {
      case m := <-s.txChan:
        err = s.raw.Write(m.parts, m.command)
        if err != nil {
          return err
        }
      case <-s.stopChan:
        return nil
    }
  }
}

func (s *session) getOutgoingMetadata() (md map[string]string) {
  md = map[string]string {}
  md["Socket-Type"] = s.config.SocketType
  if s.config.Identity != "" {
    md["Identity"]    = s.config.Identity
  }
  return
}

func (s *session) rxLoop() error {
  for {
    parts, command, err := s.raw.Read()
    if err != nil {
      return err
    }

    if command {
      err = s.handleIncomingCommand(parts)
    } else {
      err = s.handleIncomingData(parts)
    }

    if err != nil {
      return err
    }
  }
}

func (s *session) handleIncomingCommand(parts [][]byte) error {
  if len(parts) != 1 {
    panic("multipart command. RawZMTP shouldn't have given us this")
  }

  part := parts[0]

  if len(part) < 1 {
    // invalid command
    return errors.New("malformed command frame")
  }

  cmdNameLen := part[0]
  if len(part) < (cmdNameLen+1) {
    // invalid command
    return errors.New("malformed command frame")
  }

  cmdName := part[1:1+cmdNameLen]
  cmdData := part[1+cmdNameLen:]

  return s.handleIncomingCommandByName(cmdName, cmdData)
}

func (s *session) handleIncomingCommandByName(cmdName string, cmdData []byte) error {
  switch cmdName {
    case "READY":
      kv, err := s.decodeMetadata(cmdData)
      if err != nil {
        return err
      }
      err = s.handleIncomingCommand_READY(kv)
      if err != nil {
        return err
      }

    case "ERROR":
      if len(cmdData) < 1 {
        return errors.New("malformed error command")
      }

      errMsgLen := cmdData[0]
      if len(cmdData) < 1+errMsgLen {
        return errors.New("malformed error command")
      }

      errMsg := string(cmdData[1:1+errMsgLen])
      err = s.handleIncomingCommand_ERROR(errMsg)
      if err != nil {
        return err
      }

    default:
      // ???
  }
}

func (s *session) decodeMetadata(buf []byte) (m map[string]string, err error) {
  m = map[string]string{}
  for len(buf) > 0 {
    if len(buf) < 5 {
      // Nonzero contents of buffer, but not enough for a value. Error.
      err = errors.New("malformed metadata")
      return
    }

    kLen := buf[0]
    if len(buf) < kLen+5 {
      err = errors.New("malformed metadata")
      return
    }

    k    := buf[1:1+kLen]

    vLen := binary.BigEndian.Uint32(buf[1+kLen:])
    if len(buf) < kLen+5+vLen {
      err = errors.New("malformed metadata")
      return
    }

    v    := buf[5+kLen:5+kLen+vLen]

    m[string(k)]  = string(v)

    buf   = buf[5+kLen+vLen:]
  }
  return
}

func (s *session) handleIncomingCommand_READY(md map[string]string) error {
  return nil
}

func (s *session) handleIncomingCommand_ERROR(errMsg string) error {
  return nil
}

func (s *session) handleIncomingData(parts [][]byte) {
  s.rxChan <- msg { parts, command }
}

