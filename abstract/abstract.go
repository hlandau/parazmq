package abstract

import "fmt"

// Version

type ZMTPVersion uint

const (
	ZMTP3_0 ZMTPVersion = 0x0300
	ZMTP3_1             = 0x0301
)


// Flags used by the ZMTP framing protocol.
type ZMTPFlags byte

const (
	ZF_None    ZMTPFlags = 0
	ZF_More              = 1 << 0  // Set if the frame is not the last frame in the message.
	zf_Long              = 1 << 1
	ZF_Command           = 1 << 2  // Set if the frame is a command.
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

// An ordered bidirectional reliable frame stream. A frame is a sequence of
// zero or more bytes plus the two metadata bits 'More' and 'Command'.
type FrameConn interface {
	// Closes the FrameConn. If this FrameConn has an underlying FrameConn,
	// it shall be considered to own that FrameConn and so will close it as well.
	Close() error

	// Send a ZMTP frame across the connection.
	SendFrame(data []byte, flags ZMTPFlags) error

	// Receive a ZMTP frame from the connection.
	ReceiveFrame() ([]byte, ZMTPFlags, error)

	// Gets the remote metadata, if any.
	RemoteMetadata() map[string]string
}

// Message Helpers

// Sends a message. A message is either a sequence of one or more frames, none
// of which have the command bit set, or exactly one frame with the command bit
// set. This function is used to send a non-command message. A message may not
// consist of zero frames. If zero frames are passed, this function does
// nothing.
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

// Sends a command message. A command message is a single frame with the
// command bit set, with the frame data being the serialization of the tuple
// (cmdName, cmdData) as defined in the ZMTP specification. cmdName shall be a
// string between 1 and 255 bytes in length inclusive. cmdData shall be a
// sequence of zero or more bytes.
func FCSendCommand(rs FrameConn, cmdName string, cmdData []byte) error {
	buf := SerializeCommand(cmdName, cmdData)

	return rs.SendFrame(buf, ZF_Command)
}

// Sends an error message. An error message is a command message with a command
// name of "ERROR" and command data encoding an error message string as
// specified in the ZMTP specification.
func FCSendErrorCommand(rs FrameConn, errMsg string) error {
	if len(errMsg) > 255 {
		panic("error message too long")
	}

	buf := make([]byte, 1+len(errMsg))
	buf[0] = byte(len(errMsg))
	copy(buf[1:], []byte(errMsg))
	return FCSendCommand(rs, "ERROR", buf)
}

// Receives a command message from a FrameConn. The command message is
// deserialized and the command name and command data are returned.
//
// If the next frame received from the FrameConn is not a command, an error
// occurs.
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

// Serializes the (cmdName, cmdData) tuple as specified by the ZMTP specification.
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

// Deserializes command message data into the command name and command data.
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

// Deserializes error message data into the error message string.
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
