package abstract

import "fmt"

// Version

type ZMTPVersion uint

const (
	ZMTP3_0 ZMTPVersion = 0x0300
	ZMTP3_1             = 0x0301
)

// Flags

type ZMTPFlags byte

const (
	ZF_None    ZMTPFlags = 0
	ZF_More              = 1 << 0
	zf_Long              = 1 << 1
	ZF_Command           = 1 << 2
)

// Are the flags valid?
func (flags ZMTPFlags) Valid() bool {
	if (flags & ZF_Command) != 0 {
		return ((flags & ZF_More) == 0)
	}

	return true
}

// Are the flags valid for an outgoing frame?
func (flags ZMTPFlags) SendValid() bool {
	return flags.Valid() && (flags&zf_Long) == 0
}

// FrameConn

type FrameConn interface {
	// Closes the FrameConn. If this FrameConn has an underlying FrameConn,
	// it shall be considered to own that FrameConn and so will close it as well.
	Close() error

	// Send a ZMTP frame across the underlying connection or FrameConn.
	SendFrame(data []byte, flags ZMTPFlags) error

	// Receive a ZMTP frame from the underlying connection or FrameConn.
	ReceiveFrame() ([]byte, ZMTPFlags, error)

	// Gets the remote metadata, if any.
	RemoteMetadata() map[string]string
}

// Message Helpers

func FCSendMessage(rs FrameConn, msg [][]byte) error {
	for i := range msg {
		f := ZF_None
		if i < len(msg)-1 {
			f |= ZF_More
		}

		err := rs.SendFrame(msg[i], f)
		if err != nil {
			return err
		}
	}
	return nil
}

// Command Helpers

// Helper function to send a command over a FrameConn.
func FCSendCommand(rs FrameConn, cmdName string, cmdData []byte) error {
	buf := SerializeCommand(cmdName, cmdData)

	return rs.SendFrame(buf, ZF_Command)
}

// Helper function to send an ERROR command over a FrameConn.
func FCSendErrorCommand(rs FrameConn, errMsg string) error {
	if len(errMsg) > 255 {
		panic("error message too long")
	}

	buf := make([]byte, 1+len(errMsg))
	buf[0] = byte(len(errMsg))
	copy(buf[1:], []byte(errMsg))
	return FCSendCommand(rs, "ERROR", buf)
}

// Helper function to receive a command from a FrameConn.
//
// If the next frame received is not a command, an error occurs.
func FCReceiveCommand(rs FrameConn) (cmdName string, cmdData []byte, err error) {
	d, flags, err := rs.ReceiveFrame()
	if err != nil {
		return
	}

	if (flags & ZF_Command) == 0 {
		err = fmt.Errorf("Expected to receive command frame, but got data frame.")
		return
	}

	return DeserializeCommand(d)
}

// Serialize a command.
func SerializeCommand(cmdName string, cmdData []byte) []byte {
	if len(cmdName) > 255 {
		panic("command name too long")
	}

	buf := make([]byte, 1+len(cmdName)+len(cmdData))
	buf[0] = byte(len(cmdName))
	copy(buf[1:], []byte(cmdName))
	copy(buf[1+len(cmdName):], cmdData)

	return buf
}

// Parse a command.
func DeserializeCommand(d []byte) (cmdName string, cmdData []byte, err error) {
	if len(d) == 0 {
		err = fmt.Errorf("Received a zero-length command frame.")
		return
	}

	cmdNameLen := int(d[0])
	if cmdNameLen+1 > len(d) {
		err = fmt.Errorf("Received a malformed command frame.")
		return
	}

	cmdName = string(d[1 : 1+cmdNameLen])
	cmdData = d[1+cmdNameLen:]
	return
}

func DeserializeError(cmdData []byte) string {
	if len(cmdData) == 0 {
		return "(malformed ERROR command)"
	}

	errMsgLen := int(cmdData[0])
	if errMsgLen+1 > len(cmdData) {
		return "(malformed ERROR command)"
	}

	return string(cmdData[1 : 1+errMsgLen])
}
