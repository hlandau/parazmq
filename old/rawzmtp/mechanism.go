package rawzmtp

type AuthRequest struct {
  RequestID string
  Domain    string
  RemoteAddress ...
  Identity  string
  Mechanism string
  Credentials interface{}
}

type AuthResponse struct {
  StatusCode int
  StatusText string

  UserID    string
  Metadata  map[string]string
}

type AuthHandler func(req *AuthRequest) (AuthResponse, error)

func RunAuthNULL(r *RawZMTP, h AuthHandler) error {
  r.SendPLAINHelloCommand("username", "password")
  r.SendPLAINInitiateCommand(md)
  r.SendPLAINWelcomeCommand()
  r.SendReadyCommand(md2)
}

func RunAuthPLAIN(r *RawZMTP, h AuthHandler) error {

}

// A Mechanism advances a ZMTP connection by engaging in an authentication
// process.
type Mechanism interface {
  NextHandshakeCommand() ([]byte, error)
  ProcessHandshakeCommand(cmd []byte) error
}

const (
  stateINITIAL = 0
)

type null struct {
  state int
}

func (self *null) NextHandshakeCommand() (b []byte, err error) {
  switch self.state {
    case stateINITIAL:

  }
}
