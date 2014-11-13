package plainsession

import "fmt"
import "github.com/hlandau/parazmq/abstract"
import "github.com/hlandau/parazmq/metadata"

type PlainSession struct {
	abstract.FrameConn
	fc abstract.FrameConn

	cfg            PlainConfig
	remoteMetadata map[string]string
}

type PlainConfig struct {
	IsServer bool
	Metadata map[string]string

	Username string
	Password string

	ServerValidateFunc func(username, password string) bool
}

func New(fc abstract.FrameConn, cfg PlainConfig) (ps abstract.FrameConn, err error) {
	s := &PlainSession{}
	s.fc = fc
	s.cfg = cfg

	err = s.handshake()
	if err != nil {
		return
	}

	ps = s
	return
}

func (s *PlainSession) handshake() error {
	if s.cfg.IsServer {
		return s.handshakeAsServer()
	} else {
		return s.handshakeAsClient()
	}
}

func (s *PlainSession) handshakeAsServer() error {
	cmdName, cmdData, err := abstract.FCReceiveCommand(s.fc)
	switch cmdName {
	case "HELLO":
		if len(cmdData) < 2 {
			return fmt.Errorf("Malformed HELLO command received from remote peer.")
		}

		usernameLen := int(cmdData[0])
		if len(cmdData) < 2+usernameLen {
			return fmt.Errorf("Malformed HELLO command received from remote peer.")
		}

		username := string(cmdData[1 : 1+usernameLen])
		passwordLen := int(cmdData[1+usernameLen])
		if len(cmdData) < 2+usernameLen+passwordLen {
			return fmt.Errorf("Malformed HELLO command received from remote peer.")
		}

		password := string(cmdData[2+usernameLen : 2+usernameLen+passwordLen])

		ok := s.validate(username, password)

		if ok {
			err = abstract.FCSendCommand(s.fc, "WELCOME", []byte{})
			if err != nil {
				return err
			}
		} else {
			err = abstract.FCSendErrorCommand(s.fc, "Invalid username or password.")
			if err != nil {
				return err
			}
			return fmt.Errorf("Invalid username or password.") // XXX
		}

		// Wait for INITIATE
		err = s.handshakeAsServerFinal("INITIATE", "READY")
		if err != nil {
			return err
		}

		return nil
	default:
		return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
	}
}

func (s *PlainSession) validate(username, password string) bool {
	if s.cfg.ServerValidateFunc == nil {
		return false
	}

	return s.cfg.ServerValidateFunc(username, password)
}

func (s *PlainSession) handshakeAsClient() error {
	if len(s.cfg.Username) > 0xFF || len(s.cfg.Password) > 0xFF {
		panic("Username or password is too long.")
	}

	buf := make([]byte, 2+len(s.cfg.Username)+len(s.cfg.Password))
	buf[0] = byte(len(s.cfg.Username))
	copy(buf[1:], []byte(s.cfg.Username))
	buf[1+len(s.cfg.Username)] = byte(len(s.cfg.Password))
	copy(buf[1+len(s.cfg.Username)+1:], []byte(s.cfg.Password))

	err := abstract.FCSendCommand(s.fc, "HELLO", buf)
	if err != nil {
		return err
	}

	cmdName, cmdData, err := abstract.FCReceiveCommand(s.fc)
	switch cmdName {
	case "WELCOME":
		// OK
	case "ERROR":
		return fmt.Errorf("Got error from remote peer: \"%s\"", abstract.DeserializeError(cmdData))
	default:
		return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
	}

	// Now we send our metadata in INITIATE.
	return s.handshakeAsClientFinal("INITIATE", "READY")
}

func (s *PlainSession) handshakeAsClientFinal(outCmdName string, inCmdName string) error {
	err := abstract.FCSendCommand(s.fc, outCmdName, metadata.Serialize(s.cfg.Metadata))
	if err != nil {
		return err
	}

	err = s.handshakeWaitForMetadata(inCmdName)
	if err != nil {
		return err
	}

	return nil
}

func (s *PlainSession) handshakeAsServerFinal(inCmdName, outCmdName string) error {
	err := s.handshakeWaitForMetadata(inCmdName)
	if err != nil {
		return err
	}

	err = abstract.FCSendCommand(s.fc, outCmdName, metadata.Serialize(s.cfg.Metadata))
	if err != nil {
		return err
	}

	return nil
}

func (s *PlainSession) handshakeWaitForMetadata(inCmdName string) error {
	cmdName, cmdData, err := abstract.FCReceiveCommand(s.fc)
	if err != nil {
		return err
	}

	switch cmdName {
	case inCmdName:
		s.remoteMetadata, err = metadata.Deserialize(cmdData)
		if err != nil {
			return err
		}

	case "ERROR":
		return fmt.Errorf("Got error from remote peer: \"%s\"", abstract.DeserializeError(cmdData))
	default:
		return fmt.Errorf("Unexpected command from remote peer: \"%s\"", cmdName)
	}

	return nil
}

func (s *PlainSession) Close() error {
	return s.fc.Close()
}

func (s *PlainSession) SendFrame(data []byte, flags abstract.ZMTPFlags) error {
	return s.fc.SendFrame(data, flags)
}

func (s *PlainSession) ReceiveFrame() ([]byte, abstract.ZMTPFlags, error) {
	return s.fc.ReceiveFrame()
}

func (s *PlainSession) RemoteMetadata() map[string]string {
	return s.remoteMetadata
}
