package metadata

import "fmt"
import "encoding/binary"

func Serialize(md map[string]string) []byte {
	L := 0
	for k, v := range md {
		L += 5 + len(k) + len(v)
	}

	buf := make([]byte, L)
	i := 0
	for k, v := range md {
		buf[i] = byte(len(k))
		copy(buf[i+1:], []byte(k))
		binary.BigEndian.PutUint32(buf[i+1+len(k):], uint32(len(v)))
		copy(buf[i+5+len(k):], []byte(v))
		i += 5 + len(k) + len(v)
	}

	return buf
}

func Deserialize(mdBuf []byte) (md map[string]string, err error) {
	md = map[string]string{}
	for len(mdBuf) > 0 {
		if len(mdBuf) < 5 {
			err = fmt.Errorf("Malformed metadata")
			return
		}

		kLen := uint32(mdBuf[0])
		if uint32(len(mdBuf)) < kLen+5 {
			err = fmt.Errorf("Malformed metadata")
			return
		}

		k := mdBuf[1 : 1+kLen]
		vLen := binary.BigEndian.Uint32(mdBuf[1+kLen:])
		if uint32(len(mdBuf)) < kLen+5+vLen {
			err = fmt.Errorf("Malformed metadata")
			return
		}

		v := mdBuf[5+kLen : 5+kLen+vLen]
		md[string(k)] = string(v)
		mdBuf = mdBuf[5+kLen+vLen:]
	}
	return
}
