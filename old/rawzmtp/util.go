package rawzmtp

// Marshals a command name and command body and sends it using a RawZMTP
// interface.
func (r *RawZMTP) SendCommand(cmdName string, cmdData []byte) error {
  if len(cmdName) > 255 {
    panic("command name too long")
  }

  buf := make([]byte, 1+len(cmdName)+len(cmdData))
  buf[0] = byte(len(cmdName))
  copy(buf[1+i:], []byte(cmdName))
  copy(buf[1+i+len(cmdName):], cmdData)

  return r.Write(buf, true)
}

// Sends an ERROR command with the given error message over a RawZMTP
// interface.
func (r *RawZMTP) SendErrorCommand(errorMsg string) error {
  if len(errorMsg) > 255 {
    panic("error message too long")
  }

  buf := make([]byte, 1+len(errorMsg))
  buf[0] = byte(len(errorMsg))
  copy(buf[1:], []byte(errorMsg))

  return r.SendCommand("ERROR", buf)
}

func serializeMetadata(md map[string]string) (b []byte) {
  vl := make([]byte, 4)
  for k, v := range md {
    b = append(b, []byte{byte(len(k))})
    b = append(b, []byte(k)...)
    binary.BigEndian.PutUint32(vl, len(v))
    b = append(b, []byte(v)...)
  }
  return
}

// Sends a READY command with the given metadata map over a RawZMTP interface.
func (r *RawZMTP) SendReadyCommand(md map[string]string) error {
  return r.SendCommand("READY", serializeMetadata(md))
}

// Sends a HELLO command (used by the PLAIN authentication method) using the
// given username and password.
func (r *RawZMTP) SendPLAINHelloCommand(username string, password string) error {
  if len(username) > 255 || len(password) > 255 {
    panic("username or password too long")
  }

  buf := make([]byte, 2+len(username)+len(password))

  buf[0] = byte(len(username))
  copy(buf[1:], []byte(username))

  i := len(username)+1
  buf[i] = byte(len(password))
  copy(buf[i+1:], []byte(password))

  return r.SendCommand("HELLO", buf)
}

func (r *RawZMTP) SendPLAINWelcomeCommand() error {
  return r.SendCommand("WELCOME", []byte{})
}

func (r *RawZMTP) SendPLAINInitiateCommand(md map[string]string) error {
  return r.SendCommand("INITIATE", serializeMetadata(md))
}
