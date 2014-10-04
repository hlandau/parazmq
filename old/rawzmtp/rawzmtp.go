// The rawzmtp package is responsible for sending and receiving
// post-negotiation ZMTP frames.  This package does not handle handshake
// sequences, it sends and receives only frames.
package rawzmtp

// op/zenio: protocol/zmtp   Apache 2 License

import "net"
import "io"
import "sync"
import "encoding/binary"
import "errors"

// Type Byte:
//   0000 0CLM
//   M: More
//   L: Long
//   C: Command
//   M=0 if C=1

type zmtpFlags byte

const (
  // Indicates that another frame follows which is part of the same logical
  // message. This cannot be set if ZF_Command is set.
  zf_More    zmtpFlags = 1<<0

  zf_Long              = 1<<1

  // Indicates that this frame is intended for the control plane rather than
  // the data plane. This command can only be set if ZF_More is not set.
  zf_Command           = 1<<2
)

type RawZMTP interface {
  // Read a single ZMTP 3.0 message.
  //
  // If an incoming frame size exceeds the MaxReadSize, ErrMaxReadExceeded is
  // returned and the connection is closed. All further calls return ErrClosed.
  //
  // If a malformed frame header is received, ErrMalformedFrame is returned and
  // the connection is closed. All further calls return ErrClosed.
  Read() (data [][]byte, command bool, err error)

  // Write a single ZMTP 3.0 message.
  // It is illegal to specify both ZF_More and ZF_Command.
  Write(data [][]byte, command bool) error

  // Close the RawZMTP interface. This also closes the underlying connection.
  // Any further Read/Write operations on the connection result in ErrClosed.
  Close() error

  // Sets the maximum payload size of an incoming frame.
  // If this size is exceeded by an incoming frame, an error is returned from
  // Read and the underlying connection is closed. 0 means no limit (default).
  SetMaxReadSize(sz uint)
}

type rawZMTP struct {
  conn *net.Conn
  rm, wm sync.Mutex
  maxRead uint
  closed bool
}

// Create a new RawZMTP bidirectional frame stream on top of a reliable,
// ordered byte stream such as TCP. RawZMTP takes ownership of the connection
// and will close it when it is closed.
func New(c net.Conn) RawZMTP {
  return &rawZMTP {
    conn: c,
  }
}

func (self *rawZMTP) SetMaxRead(sz uint) {
  self.maxRead = sz
}

var ErrMaxReadExceeded = errors.New("rawzmtp: max read exceeded")
var ErrClosed          = errors.New("rawzmtp: has been closed")
var ErrInvalidFlags    = errors.New("rawzmtp: invalid flags combination")
var ErrMalformedFrame  = errors.New("rawzmtp: malformed frame received")

func (self *rawZMTP) Close() error {
  // Lock to ensure no message write is in progress; we ensure that we only
  // close the stream when we are not in the middle of writing a message.
  // Once wm is obtained by Write() the write must complete before we can close
  // the connection.
  self.wm.Lock()
  defer self.wm.Unlock()

  self.closed = true

  // This will interrupt any Read in progress, which we can get away with by
  // pretending the read never began. Hmm...
  return self.conn.Close()
}

func (self *rawZMTP) readFrame() (data []byte, flags zmtpFlags, err error) {
  var L uint64
  hdr = make([]byte, 9)

  if self.closed {
    err = ErrClosed
    return
  }

  self.rm.Lock()
  defer self.rm.Unlock()

  // The data to be read must be at least two bytes (type and length).
  _, err = io.ReadFull(sel.conn, hdr[0:2])
  if err != nil {
    return
  }

  flags = zmtpFlags(hdr[0])

  if !flagsValid(flags) {
    err = ErrMalformedFrame
    return
  }

  if flags & zf_Long {
    _, err = io.ReadFull(self.conn, hdr[2:9])
    if err != nil {
      return
    }

    L = binary.BigEndian.Uint64(hdr[1:])
  } else {
    L = uint64(hdr[1])
  }

  flags = flags & (zf_Long^0xFF)

  if self.maxRead != 0 && L > self.maxRead {
    self.Close()
    err = ErrMaxReadExceeded
    return
  }

  data = make([]byte, L)
  _, err = io.ReadFull(self.conn, data)

  return
}

func (self *rawZMTP) Read() (data [][]byte, command bool, err error) {
  for {
    var fdata  []byte
    var fflags zmtpFlags
    fdata, fflags, err = self.readFrame()
    if err != nil {
      data = make([][]byte, 0)
      return
    }
    data = append(data, fdata)
    if (fflags & zf_More) == 0 {
      command = ((fflags & zf_Command) != 0)
      break
    }
  }
  return
}

func flagsValid(flags zmtpFlags) bool {
  return (flags & ZF_Command) != 0 && (flags & ZF_More) != 0
}

func (self *rawZMTP) writeFrame(data []byte, flags zmtpFlags) error {
  if self.closed {
    return ErrClosed
  }

  if !flagsValid(flags) {
    err = ErrInvalidFlags
    return
  }

  hdr := make([]byte, 9)

  if len(data) > 0xFF {
    flags |= zf_Long
  }

  if len(data) > 0xFF {
    flags |= zf_Long
    binary.BigEndian.PutUint64(hdr[1:], len(data))
  } else {
    hdr[1] = byte(len(data))
    hdr = hdr[0:2]
  }
  hdr[0] = byte(flags)

  self.wm.Lock()
  defer self.wm.Unlock()

  err := self.conn.Write(hdr)
  if err != nil {
    return err
  }

  err  = self.conn.Write(data)
  if err != nil {
    return err
  }

  return nil
}

func (self *rawZMTP) Write(data [][]byte, command bool) error {
  for i := range data {
    flags := zmtpFlags(0)
    if command {
      flags |= zf_Command
    }
    if i < len(data)-1 {
      flags |= zf_More
    }

    err := self.writeFrame(data[i], flags)
    if err != nil {
      return err
    }
  }
  return nil
}
