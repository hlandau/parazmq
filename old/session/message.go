package session

type Message interface {
  Parts() [][]byte
  // ...
}

type message struct {
  parts [][]byte
}

func NewMessage(parts [][]byte) Message {
  m := &message {
    parts: parts,
  }
  return m
}

