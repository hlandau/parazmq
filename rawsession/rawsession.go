package rawsession

import "net"
import "io"
import "encoding/binary"
import "fmt"
import "github.com/hlandau/parazmq/abstract"

type RawSession struct {
	abstract.FrameConn

	conn    net.Conn
	maxRead uint64
	closed  bool
	version abstract.ZMTPVersion
}

// Creates a FrameConn which sends and receives ZMTP/3 frames over a net.Conn.
// The underlying connection must have already completed any greeting and handshake phases.
func New(conn net.Conn, version abstract.ZMTPVersion) (rs *RawSession, err error) {
	if version < abstract.ZMTP3_0 || version > abstract.ZMTP3_1 {
		err = fmt.Errorf("unsupported version")
		return
	}

	rs = &RawSession{}
	rs.conn = conn
	rs.version = version
	return
}

func (rs *RawSession) Close() error {
	if rs.closed {
		return nil
	}

	err := rs.conn.Close()
	if err != nil {
		return err
	}

	rs.closed = true
	return nil
}

const (
	zf_Long abstract.ZMTPFlags = 1 << 1
)

func (rs *RawSession) SendFrame(data []byte, flags abstract.ZMTPFlags) error {
	if !flags.SendValid() {
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

	_, err := rs.conn.Write(hdr)
	if err != nil {
		return err
	}

	_, err = rs.conn.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func (rs *RawSession) ReceiveFrame() (data []byte, flags abstract.ZMTPFlags, err error) {
	var L uint64
	hdr := make([]byte, 9)

	_, err = io.ReadFull(rs.conn, hdr[0:2])
	if err != nil {
		return
	}

	flags = abstract.ZMTPFlags(hdr[0])
	if !flags.Valid() {
		err = fmt.Errorf("Received malformed frame.")
		return
	}

	if (flags & zf_Long) != 0 {
		_, err = io.ReadFull(rs.conn, hdr[2:9])
		if err != nil {
			return
		}

		L = binary.BigEndian.Uint64(hdr[1:])
	} else {
		L = uint64(hdr[1])
	}

	flags = flags & (zf_Long ^ abstract.ZMTPFlags(0xFF))

	if rs.maxRead != 0 && L > rs.maxRead {
		// TODO FAULT MODE
		err = fmt.Errorf("Received frame in excess of the max read size.")
		return
	}

	data = make([]byte, L)
	_, err = io.ReadFull(rs.conn, data)

	// rs.touch()

	return
}

func (rs *RawSession) RemoteMetadata() map[string]string {
	return nil
}
