package util
import "fmt"
import "crypto/rand"
import "io"

var decoder [96]byte = [96]byte{
  0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00,
  0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4A, 0x47,
  0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
  0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
  0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
  0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00,
  0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
  0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00,
}

func DecodeZ85(ks string) (k []byte, err error) {
  if len(ks) % 5 != 0 {
    err = fmt.Errorf("malformed key")
    return
  }

  dsz := len(ks)*4/5
  k = make([]byte, dsz)

  b := 0
  c := 0
  var v uint
  for c < len(ks) {
    v = v * 85 + uint(decoder[uint8(ks[c]) - uint8(32)])
    c++
    if c % 5 == 0 {
      d := uint(256*256*256)
      for d != 0 {
        k[b] = uint8(v / d % 256)
        b++
        d /= 256
      }
      v = 0
    }
  }

  return
}

func DecodeZ85Key(ks string) (k [32]byte, err error) {
  if len(ks) != 40 {
    err = fmt.Errorf("malformed key")
    return
  }

  kk, err := DecodeZ85(ks)
  if err != nil {
    return
  }

  copy(k[0:32], kk[0:32])
  return
}

func GeneratePrivateKey() (k [32]byte, err error) {
  _, err = io.ReadFull(rand.Reader, k[:])
  if err != nil {
    return
  }

  return
}