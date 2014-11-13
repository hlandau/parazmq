package curvesession
import "fmt"
import "bytes"
import "crypto/rand"
import "crypto/subtle"
import "encoding/binary"
import "github.com/hlandau/parazmq/abstract"
import "github.com/hlandau/parazmq/metadata"
import "code.google.com/p/go.crypto/nacl/box"
import "code.google.com/p/go.crypto/nacl/secretbox"
import "code.google.com/p/go.crypto/curve25519"

type CurveSession struct {
  abstract.FrameConn
  fc abstract.FrameConn

  isServer bool

                   //                        Known by
                   //                            C  S
  curveC  [32]byte // Client Permanent Public    *  *
  curvec  [32]byte // Client Permanent Private   *
  curveCt [32]byte // Client Transient Public    *  *
  curvect [32]byte // Client Transient Private   *
  curveS  [32]byte // Server Permanent Public    *  *
  curves  [32]byte // Server Permanent Private      *
  curveSt [32]byte // Server Transient Public    *  *
  curvest [32]byte // Server Transient Private      *

  curvemk  [32]byte // Precomputed Message Encryption Key

  curveck  [32]byte    // Server cookie key
  cookieNonce [16]byte // Server cookie nonce

  curveEngaged bool
  curveTxNonceCounter uint64
  curveRxNonceCounter uint64

  metadata map[string]string
  remoteMetadata map[string]string
}

type CurveConfig struct {
  IsServer bool   // determines which role is taken in the handshake.
  Curvek [32]byte // own private key
  CurveS [32]byte // server's public key (required only if we are a client)
  Metadata map[string]string // metadata to send to server
}

// Creates a new FrameConn implementing CurveZMQ.
//
// Calling this function will cause the CurveZMQ handshake to be performed over the
// provided underlying FrameConn.
//
// Takes ownership of the underlying FrameConn and closes it when the returned FrameConn
// is closed.
//
// Do not call methods on the underlying FrameConn after calling this.
func New(fc abstract.FrameConn, cfg CurveConfig) (cs *CurveSession, err error) {
  s := &CurveSession{}
  s.fc = fc
  s.isServer = cfg.IsServer
  s.metadata = cfg.Metadata

  if s.isServer {
    s.curves = cfg.Curvek
    curve25519.ScalarBaseMult(&s.curveS, &s.curves)
  } else {
    s.curvec = cfg.Curvek
    curve25519.ScalarBaseMult(&s.curveC, &s.curvec)

    s.curveS = cfg.CurveS
  }

  // nonce
  var nonce [8]byte
  _, err = rand.Read(nonce[:])
  if err != nil {
    return
  }

  // Add extra nonce entropy by picking a random point to start at. Mask off the MSB
  // thereby ensuring we have a stream lifespan of 8 EiB, which should be entirely
  // adequate.
  s.curveTxNonceCounter = binary.BigEndian.Uint64(nonce[:]) & 0x7FFFFFFFFFFFFFFF

  //
  err = s.handshake()
  if err != nil {
    return
  }

  cs = s
  return
}

func (s *CurveSession) handshake() error {
  if s.isServer {
    return s.handshakeAsServer()
  } else {
    return s.handshakeAsClient()
  }
}

func (s *CurveSession) handshakeAsServer() error {
  if keyIsZero(s.curves) {
    return fmt.Errorf("Server private key not specified.")
  }

  // Generate our transient private key s' and our corresponding public key S'.
  St, st, err := box.GenerateKey(rand.Reader)
  if err != nil {
    return err
  }

  s.curveSt = *St
  s.curvest = *st

  cmdName, cmdData, err := abstract.FCReceiveCommand(s.fc)
  if err != nil {
    return err
  }

  switch cmdName {
    case "HELLO":
      err := s.decodeHELLO(cmdData)
      if err != nil {
        return err
      }

      welcomeBuf, err := s.encodeWELCOME()
      if err != nil {
        return err
      }

      err = abstract.FCSendCommand(s.fc, "WELCOME", welcomeBuf)
      if err != nil {
        return err
      }

    case "ERROR":
      return fmt.Errorf("Received error from remote peer")
    default:
      return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
  }

  cmdName, cmdData, err = abstract.FCReceiveCommand(s.fc)
  if err != nil {
    return err
  }

  switch cmdName {
    case "INITIATE":
      err := s.decodeINITIATE(cmdData)
      if err != nil {
        return err
      }

      readyBuf, err := s.encodeREADY()
      if err != nil {
        return err
      }

      err = abstract.FCSendCommand(s.fc, "READY", readyBuf)
      if err != nil {
        return err
      }

    case "ERROR":
      return fmt.Errorf("Received error from remote peer")
    default:
      return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
  }

  return nil
}

func keyIsZero(k [32]byte) bool {
  return bytes.Equal(k[:], make([]byte,32))
}

func (s *CurveSession) handshakeAsClient() error {
  if keyIsZero(s.curvec) {
    return fmt.Errorf("Client private key not specified.")
  }

  if keyIsZero(s.curveS) {
    return fmt.Errorf("Server public key not specified.")
  }

  // Get our public key from the private key.
  curve25519.ScalarBaseMult(&s.curveC, &s.curvec)

  // Generate our transient private key c' and our corresponding public key C'.
  Ct, ct, err := box.GenerateKey(rand.Reader)
  if err != nil {
    return err
  }

  s.curveCt = *Ct
  s.curvect = *ct

  helloBuf, err := s.encodeHELLO()
  if err != nil {
    return err
  }

  err = abstract.FCSendCommand(s.fc, "HELLO", helloBuf)
  if err != nil {
    return err
  }

  cmdName, cmdData, err := abstract.FCReceiveCommand(s.fc)
  if err != nil {
    return err
  }

  switch cmdName {
    case "WELCOME":
      cookie, err := s.decodeWELCOME(cmdData)
      if err != nil {
        return err
      }

      initiateBuf, err := s.encodeINITIATE(cookie, s.metadata)
      if err != nil {
        return err
      }

      err = abstract.FCSendCommand(s.fc, "INITIATE", initiateBuf)
      if err != nil {
        return err
      }

    case "ERROR":
      return fmt.Errorf("Received error from remote peer")
    default:
      return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
  }

  cmdName, cmdData, err = abstract.FCReceiveCommand(s.fc)
  if err != nil {
    return err
  }

  switch cmdName {
    case "READY":
      md, err := s.decodeREADY(cmdData)
      if err != nil {
        return err
      }

      s.remoteMetadata = md
      box.Precompute(&s.curvemk, &s.curveSt, &s.curvect)

    case "ERROR":
      return fmt.Errorf("Received error from remote peer")
    default:
      return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
  }

  return nil
}

var z64 = make([]byte, 64)

func (s *CurveSession) encodeHELLO() (buf []byte, err error) {
  // Nonce. 8 bytes with implicit prefix: "CurveZMQHELLO---"
  nonce := [24]byte{67,117,114,118,101,90,77,81,72,69,76,76,79,45,45,45,0,0,0,0,0,0,0,0}
  s.curveTxNonceCounter++
  binary.BigEndian.PutUint64(nonce[16:24], s.curveTxNonceCounter)

  buf    = make([]byte, 114)
  buf[0] = 1 // v1.0
  buf[1] = 0
  copy(buf[74:106], s.curveCt[:])
  copy(buf[106:114], nonce[16:])

  buf = box.Seal(buf, z64, &nonce, &s.curveS, &s.curvect)
  if len(buf) != 194 {
    panic("x")
  }
  return
}

func (s *CurveSession) decodeHELLO(buf []byte) error {
  if len(buf) != 194 {
    return fmt.Errorf("Malformed HELLO command")
  }

  if buf[0] != 1 {
    return fmt.Errorf("Unsupported CurveZMQ version")
  }

  Ct := [32]byte{}
  copy(Ct[:], buf[74:106])

  nonce := [24]byte{67,117,114,118,101,90,77,81,72,69,76,76,79,45,45,45,0,0,0,0,0,0,0,0}
  copy(nonce[16:24], buf[106:114])
  out, ok := box.Open(make([]byte,0), buf[114:194], &nonce, &Ct, &s.curves)
  if !ok {
    return fmt.Errorf("Malformed box in HELLO command")
  }

  if subtle.ConstantTimeCompare(out, z64) != 1 {
    return fmt.Errorf("Nonzero box contents in HELLO command")
  }

  s.curveCt = Ct

  return nil
}

func (s *CurveSession) decodeWELCOME(buf []byte) (cookie []byte, err error) {
  if len(buf) != 160 {
    err = fmt.Errorf("malformed curve WELCOME received")
    return
  }

  // prefixed with "WELCOME-"
  nonce := [24]byte{87,69,76,67,79,77,69,45, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
  copy(nonce[8:24], buf[0:16])
  s.curveRxNonceCounter = binary.BigEndian.Uint64(nonce[16:24])

  boxBuf  := buf[16:]
  boxData := make([]byte, 0)
  boxData, ok := box.Open(boxData, boxBuf, &nonce, &s.curveS, &s.curvect)
  if !ok {
    err = fmt.Errorf("Opening of WELCOME box failed.")
    return
  }

  copy(s.curveSt[:], boxData[0:32])
  cookie = boxData[32:]

  return
}

func (s *CurveSession) encodeWELCOME() (buf []byte, err error) {
  cookie, err := s.encodeCookie()
  if err != nil {
    return
  }

  // prefixed with "WELCOME-"
  nonce := [24]byte{87,69,76,67,79,77,69,45, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

  _, err = rand.Read(nonce[8:24])
  if err != nil {
    return
  }
  nonce[8] = nonce[8] & 0x7f

  boxData := make([]byte, 128)
  copy(boxData[0:32], s.curveSt[:])
  copy(boxData[32:128], cookie)

  // ...
  buf = make([]byte, 16, 160)
  copy(buf[0:16], nonce[8:24])

  buf = box.Seal(buf, boxData, &nonce, &s.curveCt, &s.curves)
  return
}

func (s *CurveSession) encodeCookie() (buf []byte, err error) {
  // prefixed with "COOKIE--"
  nonce := [24]byte{67,79,79,75,73,69,45,45, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

  _, err = rand.Read(nonce[8:24])
  if err != nil {
    return
  }

  buf = make([]byte, 16, 96)
  copy(buf[8:24], nonce[:])

  _, err = rand.Read(s.curveck[:])
  if err != nil {
    return
  }

  boxData := make([]byte, 64)
  copy(boxData[0:32], s.curveCt[:])
  copy(boxData[32:64], s.curvest[:])

  buf = secretbox.Seal(buf, boxData, &nonce, &s.curveck)
  return
}

func (s *CurveSession) verifyCookie(cookie []byte) error {
  // prefixed with "COOKIE--"
  nonce := [24]byte{67,79,79,75,73,69,45,45, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
  copy(nonce[8:24], cookie[0:16])

  boxData, ok := secretbox.Open(make([]byte,0), cookie[16:], &nonce, &s.curveck)
  if !ok {
    return fmt.Errorf("bad cookie")
  }

  correctBoxData := make([]byte, 64)
  copy(correctBoxData[0:32], s.curveCt[:])
  copy(correctBoxData[32:64], s.curvest[:])

  if subtle.ConstantTimeCompare(boxData, correctBoxData) != 1 {
    return fmt.Errorf("bad cookie box contents")
  }

  return nil
}

func (s *CurveSession) encodeINITIATE(cookie []byte, md map[string]string) (buf []byte, err error) {
  if len(cookie) != 96 {
    err = fmt.Errorf("invalid cookie specified")
    return
  }

  nonce := [24]byte{67,117,114,118,101,90,77,81,73,78,73,84,73,65,84,69,0,0,0,0,0,0,0,0} // CurveZMQINITIATE
  s.curveTxNonceCounter++
  binary.BigEndian.PutUint64(nonce[16:24], s.curveTxNonceCounter)

  vouch, err := s.encodeVouch()
  if err != nil {
    return
  }

  mdBuf := metadata.Serialize(md)
  boxData := make([]byte, 128+len(mdBuf))
  copy(boxData[0:32], s.curveC[:])
  copy(boxData[32:128], vouch)
  copy(boxData[128:], mdBuf)

  buf = make([]byte, 104) //248+len(mdBuf)
  copy(buf[0:96], cookie)
  copy(buf[96:104], nonce[16:24])
  buf = box.Seal(buf, boxData, &nonce, &s.curveSt, &s.curvect)

  return
}

func (s *CurveSession) decodeINITIATE(buf []byte) error {
  if len(buf) < 248 {
    return fmt.Errorf("Malformed INITIATE command")
  }

  cookie := buf[0:96] // cookie
  // Is the cookie even necessary? ...
  err := s.verifyCookie(cookie)
  if err != nil {
    return err
  }

  s.curveck = [32]byte{}

  nonce := [24]byte{67,117,114,118,101,90,77,81,73,78,73,84,73,65,84,69,0,0,0,0,0,0,0,0} // CurveZMQINITIATE
  copy(nonce[16:24], buf[96:104])

  boxData, ok := box.Open(make([]byte,0), buf[104:], &nonce, &s.curveCt, &s.curvest)
  if !ok {
    return fmt.Errorf("Malformed INITIATE box")
  }

  copy(s.curveC[:], boxData[0:32])
  vouch := boxData[32:128]
  mdBuf := boxData[128:]

  err = s.decodeVouch(vouch)
  if err != nil {
    return err
  }

  md, err := metadata.Deserialize(mdBuf)
  if err != nil {
    return err
  }

  s.remoteMetadata = md

  return nil
}

func (s *CurveSession) encodeVouch() (buf []byte, err error) {
  buf = make([]byte, 16)

  nonce := [24]byte{86,79,85,67,72,45,45,45,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
  s.curveTxNonceCounter++
  binary.BigEndian.PutUint64(nonce[16:24], s.curveTxNonceCounter)

  copy(buf[0:16], nonce[8:24])

  boxData := make([]byte, 64)
  copy(boxData[0:32], s.curveCt[:])
  copy(boxData[32:64], s.curveS[:])
  buf = box.Seal(buf, boxData, &nonce, &s.curveSt, &s.curvec)
  return
}

func (s *CurveSession) decodeVouch(vouch []byte) error {
  nonce := [24]byte{86,79,85,67,72,45,45,45,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
  copy(nonce[8:24], vouch[0:16])

  vbox := vouch[16:]
  boxData, ok := box.Open(make([]byte,0), vbox, &nonce, &s.curveC, &s.curvest)
  if !ok {
    return fmt.Errorf("Malformed vouch box")
  }

  correctBoxData := make([]byte, 64)
  copy(correctBoxData[0:32], s.curveCt[:])
  copy(correctBoxData[32:64], s.curveS[:])

  if subtle.ConstantTimeCompare(boxData, correctBoxData) != 1 {
    return fmt.Errorf("Vouch box contains wrong keys")
  }

  return nil
}

func (s *CurveSession) decodeREADY(buf []byte) (md map[string]string, err error) {
  if len(buf) < 24 {
    err = fmt.Errorf("malformed READY command received")
    return
  }

  // "CurveZMQREADY---"
  nonce := [24]byte{67,117,114,118,101,90,77,81,82,69,65,68,89,45,45,45,0,0,0,0,0,0,0,0}
  copy(nonce[16:24], buf[0:8])
  s.curveRxNonceCounter = binary.BigEndian.Uint64(nonce[16:24])

  boxBuf  := buf[8:]
  boxData := make([]byte, 0) //len(buf)-24

  boxData, ok := box.Open(boxData, boxBuf, &nonce, &s.curveSt, &s.curvect)
  if !ok {
    err = fmt.Errorf("Failed to open READY box")
    return
  }

  md, err = metadata.Deserialize(boxData)
  if err != nil {
    return
  }

  s.remoteMetadata = md

  return
}

func (s *CurveSession) encodeREADY() (buf []byte, err error) {
  // "CurveZMQREADY---"
  nonce := [24]byte{67,117,114,118,101,90,77,81,82,69,65,68,89,45,45,45,0,0,0,0,0,0,0,0}
  s.curveTxNonceCounter++
  binary.BigEndian.PutUint64(nonce[16:24], s.curveTxNonceCounter)

  buf = make([]byte, 8)
  copy(buf[0:8], nonce[16:24])

  boxData := metadata.Serialize(s.metadata)
  buf = box.Seal(buf, boxData, &nonce, &s.curveCt, &s.curvest)

  return
}

// Get the metadata sent by the remote party, if any.
func (s *CurveSession) RemoteMetadata() map[string]string {
  return s.remoteMetadata
}

func (s *CurveSession) Close() error {
  if s.fc == nil {
    return nil
  }
  
  err := s.fc.Close()
  if err != nil {
    return err
  }

  s.curveC  = [32]byte{}
  s.curvec  = [32]byte{}
  s.curveCt = [32]byte{}
  s.curvect = [32]byte{}
  s.curveS  = [32]byte{}
  s.curves  = [32]byte{}
  s.curveSt = [32]byte{}
  s.curvest = [32]byte{}
  s.curvemk = [32]byte{}
  s.curveTxNonceCounter = 0
  s.curveRxNonceCounter = 0

  s.fc = nil
  return nil
}

var curveMessagePrefix []byte = []byte{ 7,77,69,83,83,65,71,69} // "\x07MESSAGE"

func (s *CurveSession) SendFrame(data []byte, flags abstract.ZMTPFlags) error {
  if (flags & abstract.ZF_Command) != 0 {
    return s.fc.SendFrame(data, flags)
  }

  buf := make([]byte, 16, len(data)+33)
  copy(buf[0:8], curveMessagePrefix)

  // CurveZMQMESSAGE?
  nonce := [24]byte{67,117,114,118,101,90,77,81,77,69,83,83,65,71,69,63,0,0,0,0,0,0,0,0}
  if s.isServer {
    // CurveZMQMESSAGES
    nonce[15] = 83
  } else {
    // CurveZMQMESSAGEC
    nonce[15] = 67
  }

  // Counter limit reached, kill the stream.
  // This should happen, you'd have to send at least 8*1024^6-1 frames.
  if s.curveTxNonceCounter >= 0xFFFFFFFFFFFFFFFF {
    s.Close()
    return fmt.Errorf("stream counter reached limit")
  }

  s.curveTxNonceCounter++
  binary.BigEndian.PutUint64(nonce[16:24], s.curveTxNonceCounter)

  // Amusing fact: I originally forgot this line and spent ages trying to figure out why
  // received messages were blank. ... Yeah, who cares about the ACTUAL DATA?
  copy(buf[8:16], nonce[16:24])

  boxData := make([]byte, len(data)+1)
  if (flags & abstract.ZF_More) != 0 {
    boxData[0] |= byte(abstract.ZF_More)
  }

  copy(boxData[1:], data)

  buf = box.SealAfterPrecomputation(buf, boxData, &nonce, &s.curvemk)

  // libzmq sends without the Command flag.
  return s.fc.SendFrame(buf, abstract.ZF_None)
}

func (s *CurveSession) ReceiveFrame() (data []byte, flags abstract.ZMTPFlags, err error) {
  cdata, cflags, err := s.fc.ReceiveFrame()
  if err != nil {
    return
  }

  if (flags & abstract.ZF_Command) == 0 {
    // Only commands should be received once CurveZMQ is engaged.
    // XXX: it looks like libzmq sends without the command bit set, and the CurveZMQ specification
    // is ambiguous. ???

    //err = fmt.Errorf("Got non-command message while CurveZMQ is engaged")
    //return
  }

  if !bytes.Equal(cdata[0:8], curveMessagePrefix) {
    // non-MESSAGE command, pass through (UNAUTHENTICATED)
    data = cdata
    flags = cflags
    return
  }

  body := cdata[8:]
  if len(body) < 25 {
    err = fmt.Errorf("Received malformed MESSAGE command")
    return
  }

  // CurveZMQMESSAGE?
  nonce := [24]byte{67,117,114,118,101,90,77,81,77,69,83,83,65,71,69,63,0,0,0,0,0,0,0,0}
  copy(nonce[16:24], body[0:8])

  out := make([]byte, 0, len(body)-8)

  ok := false
  if !s.isServer {
    // CurveZMQMESSAGES
    nonce[15] = 83
  } else {
    // CurveZMQMESSAGEC
    nonce[15] = 67
  }
  out, ok = box.OpenAfterPrecomputation(out, body[8:], &nonce, &s.curvemk)

  if !ok {
    err = fmt.Errorf("Decryption of received MESSAGE command failed.")
    return
  }

  flags = abstract.ZMTPFlags(out[0])
  data = out[1:]
  return
}
