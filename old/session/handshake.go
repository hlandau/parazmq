package session
import "net"
import "github.com/hlandau/parazmq/rawzmtp"

var ErrInvalidMechanism = errors.New("invalid mechanism string")
var ErrRoleConflict     = errors.New("both sides attempted to assume the same role")

// Performs ZMTP 3.0 negotiation over a bidirectional reliable ordered bytestream such as
// TCP. This function should be called over a connection which has just been
// opened but has not had anything sent over it. It completes the pre-framing
// negotiation phase and returns RawZMTP. After calling this,
// mechanism-specific negotiation must be performed.
//
// Prior versions of ZMTP are not currently supported.
func greetingZMTP(c net.Conn, mechanism string, isServer bool) (rawzmp.RawZMTP, error) {
  if len(mechanism) > 20 {
    c.Close()
    return nil, ErrInvalidMechanism
  }

  // SEND GREETING
  asServer    := byte(0)
  if isServer {
    asServer = 1
  }

  greeting    := make([]byte, 64)
  greeting[0]  = 0xFF
  greeting[9]  = 0x7F
  greeting[10] = 0x03
  greeting[11] = 0x00
  for i := range mechanism {
    greeting[12+i] = mechanism[i]
  }
  greeting[32] = asServer
  // rest of greeting is all zeroes

  _, err := c.Write(greeting)
  if err != nil {
    c.Close()
    return nil, err
  }

  // RECEIVE GREETING
  _, err = io.ReadAll(c, greeting)
  if err != nil {
    c.Close()
    return nil, err
  }

  if greeting[0] != 0xFF || greeting[9] != 0x7F || greeting[10] < 0x03 {
    c.Close()
    return nil, errors.New("Received malformed greeting")
  }

  remoteIsServer  := ((greeting[32] & 1) != 0)
  remoteMechanism := strings.TrimRight(greeting[12:31], "\x00")

  r := rawzmtp.New(c)
  if r == nil {
    c.Close()
    return nil, errors.New("nil RawZMTP?")
  }


  if remoteMechanism != mechanism {
    r.SendErrorCommand("Bad mechanism")
    r.Close()
    return nil, fmt.Errorf("Remote side specified different mechanism: %s", remoteMechanism)
  }

  if remoteIsServer && remoteIsServer == isServer { // XXX
    r.SendErrorCommand("Server role conflict")
    r.Close()
    return nil, ErrRoleConflict
  }

  // DONE
  return r, nil
}
