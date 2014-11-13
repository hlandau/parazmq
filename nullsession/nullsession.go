package nullsession

import "fmt"
import "github.com/hlandau/parazmq/abstract"
import "github.com/hlandau/parazmq/metadata"

type NullSession struct {
	abstract.FrameConn
	fc abstract.FrameConn

	isServer bool

	metadata       map[string]string
	remoteMetadata map[string]string
}

type NullConfig struct {
	IsServer bool
	Metadata map[string]string
}

func New(fc abstract.FrameConn, cfg NullConfig) (ns abstract.FrameConn, err error) {
	s := &NullSession{}
	s.fc = fc
	s.isServer = cfg.IsServer
	s.metadata = cfg.Metadata

	err = s.handshake()
	if err != nil {
		return
	}

	ns = s
	return
}

func (s *NullSession) handshake() error {
	err := abstract.FCSendCommand(s.fc, "READY", metadata.Serialize(s.metadata))
	if err != nil {
		return err
	}

	err = s.handshakeWaitForMetadata("READY")
	if err != nil {
		return err
	}

	return nil
}

func (s *NullSession) handshakeWaitForMetadata(inCmdName string) error {
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

func (s *NullSession) Close() error {
	return s.fc.Close()
}

func (s *NullSession) SendFrame(data []byte, flags abstract.ZMTPFlags) error {
	return s.fc.SendFrame(data, flags)
}

func (s *NullSession) ReceiveFrame() ([]byte, abstract.ZMTPFlags, error) {
	return s.fc.ReceiveFrame()
}

func (s *NullSession) RemoteMetadata() map[string]string {
	return s.remoteMetadata
}
