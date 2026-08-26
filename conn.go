// Package spice implements a client for the SPICE remote desktop protocol
// This file implements the core connection handling and protocol-level operations
package spice

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// SpiceConn represents a connection to a specific SPICE channel
// It handles the protocol-level communication including message framing,
// authentication, and capability negotiation
type SpiceConn struct {
	client *Client                       // Reference to the parent client
	conn   net.Conn                      // Underlying network connection
	serial uint64                        // Serial counter for outgoing messages
	wLock  sync.Mutex                    // Lock for writing to conn
	hndlr  func(typ uint16, data []byte) // Message handler callback
	pub    *rsa.PublicKey                // Server's public key for authentication
	typ    Channel                       // Channel type (main, display, inputs, etc.)
	id     uint8                         // Channel ID

	// Negotiated protocol version
	major uint32 // Major version
	minor uint32 // Minor version

	// Capability negotiation
	commonCaps  []uint32 // Common capabilities from server
	channelCaps []uint32 // Channel-specific capabilities from server
	validCaps   []uint32 // Negotiated capabilities (intersection)

	miniHeaders bool // Whether to use mini-headers (optimization)

	// Message acknowledgment
	ackW uint32     // Ack window: send acknowledgment every "window" messages
	ackP uint32     // Ack position: when it reaches ackW, send ack
	ackL sync.Mutex // Lock for acknowledgment variables

	// bytesRead is a running total of message-payload bytes consumed
	// by this channel. Compared against Client.MaxSessionBytes on
	// every frame — a hostile server sending millions of near-cap
	// messages otherwise allocates faster than GC can keep up.
	// Atomic access; 64-bit is intentional (uint32 rolls over at 4 GiB).
	bytesRead uint64
}

// ReadLoop continuously reads and processes incoming messages from the SPICE server
// It handles message acknowledgment according to the server's requirements
// and dispatches messages to the appropriate handlers.
//
// A hostile server can send an unbounded number of near-10MB messages
// (the per-frame cap in ReadData); we don't cap the session's aggregate
// but the readloop is single-threaded so the pace is bounded by the
// downstream `process` handler. Callers who need a hard rate cap should
// wrap the underlying net.Conn with a bandwidth limiter.
func (c *SpiceConn) ReadLoop() {
	// Read packets until an error occurs (typically connection closed)
	for {
		err := c.ReadData(func(typ uint16, data []byte) error {
			// Handle acknowledgment according to the ack window
			doAck := false
			c.ackL.Lock()
			if c.ackW > 0 {
				c.ackP += 1
				if c.ackP >= c.ackW {
					c.ackP = 0
					doAck = true
				}
			}
			c.ackL.Unlock()

			if doAck {
				// Send acknowledgment message
				c.WriteMessage(SPICE_MSGC_ACK)
			}

			// Process the received message
			return c.process(typ, data)
		})
		if err != nil {
			log.Printf("spice: %s read failed: %s", c.String(), err)
			// Notify caller that the channel died so it can clean up
			// downstream state instead of silently orphaning goroutines.
			if c.client != nil {
				c.client.onChannelClosed(c.typ, c.id, err)
			}
			return
		}
	}
}

// sessionCap returns the per-session read-byte cap, or 0 for
// unlimited. Reads through to the parent Client if attached so a
// runtime bump on Client.MaxSessionBytes propagates without needing
// to restart the connection.
func (c *SpiceConn) sessionCap() uint64 {
	if c == nil || c.client == nil {
		return 0
	}
	return atomic.LoadUint64(&c.client.MaxSessionBytes)
}

// debugLog routes through client.Debug when set, mirroring how
// ch-cursor.go and a few other files already log. Everywhere else in
// the package uses the top-level `log` unconditionally, defeating the
// point of the Debug logger. New code and progressively-refactored
// call sites should prefer this helper.
func (c *SpiceConn) debugLog(format string, args ...interface{}) {
	if c == nil || c.client == nil || c.client.Debug == nil {
		return
	}
	c.client.Debug.Printf("spice: "+format, args...)
}

func (c *SpiceConn) String() string {
	return fmt.Sprintf("%s[%d]", c.typ.String(), c.id)
}

func (c *SpiceConn) process(typ uint16, data []byte) error {
	// process message
	switch typ {
	case SPICE_MSG_SET_ACK:
		c.ackL.Lock()
		defer c.ackL.Unlock()

		if len(data) < 8 {
			// not enough data
			return nil
		}

		gen := binary.LittleEndian.Uint32(data[:4])
		c.ackW = binary.LittleEndian.Uint32(data[4:8])
		c.ackP = 0

		log.Printf("spice: %s connection ack window set to %d (gen=%d)", c.String(), c.ackW, gen)

		// send ack_sync response
		c.WriteMessage(SPICE_MSGC_ACK_SYNC, gen)
	case SPICE_MSG_PING:
		//log.Printf("spice: %s Ping? Pong. Data len=%d", c.String(), len(m.Data))
		if len(data) > 12 {
			data = data[:12]
		}
		// send pong
		c.WriteMessage(SPICE_MSGC_PONG, data)
	case SPICE_MSG_NOTIFY:
		buf := bytes.NewReader(data)
		var ts uint64
		var severity, visibility, what, ln uint32

		binary.Read(buf, binary.LittleEndian, &ts)
		binary.Read(buf, binary.LittleEndian, &severity)
		binary.Read(buf, binary.LittleEndian, &visibility)
		binary.Read(buf, binary.LittleEndian, &what)
		binary.Read(buf, binary.LittleEndian, &ln)

		msg := make([]byte, ln)
		io.ReadFull(buf, msg)

		// example: severity=1 visibility=2 what=0 keyboard channel is insecure
		// severity: INFO|WARN|ERROR
		// visibility: LOW|MEDIUM|HIGH
		// what: error_code/warn_code/info_code

		log.Printf("spice: %s says ts=%d severity=%d visibility=%d what=%d: %s", c.String(), ts, severity, visibility, what, msg)
	case SPICE_MSG_WAIT_FOR_CHANNELS:
		// TODO
		log.Printf("spice: %s got SPICE_MSG_WAIT_FOR_CHANNELS, ignored", c.String())
	case SPICE_MSG_DISCONNECTING:
		log.Printf("spice: %s got SPICE_MSG_DISCONNECTING", c.String())
	default:
		if c.hndlr != nil {
			c.hndlr(typ, data)
		}
	}
	return nil
}

func (c *SpiceConn) Write(buf []byte) (int, error) {
	return c.conn.Write(buf)
}

func (c *SpiceConn) Read(buf []byte) (int, error) {
	return c.conn.Read(buf)
}

func (c *SpiceConn) ReadFull(buf []byte) error {
	_, err := io.ReadFull(c.conn, buf)
	return err
}

func (c *SpiceConn) ReadError() error {
	buf := make([]byte, 4)
	err := c.ReadFull(buf)
	if err != nil {
		return err
	}
	err = SpiceError(binary.LittleEndian.Uint32(buf))
	if err == ErrSpiceLinkOk {
		return nil
	}
	return err
}

func (c *SpiceConn) ReadData(cb func(typ uint16, data []byte) error) error {
	// checkQuota enforces the per-session read cap (if any). Returns
	// an error the caller propagates so the readloop terminates
	// cleanly rather than the goroutine spinning on bad frames.
	checkQuota := func(size uint32) error {
		cap := c.sessionCap()
		if cap == 0 {
			return nil
		}
		total := atomic.AddUint64(&c.bytesRead, uint64(size))
		if total > cap {
			return fmt.Errorf("spice: %s session byte cap %d exceeded (%d read)", c.String(), cap, total)
		}
		return nil
	}

	if c.miniHeaders {
		// only type & size
		var typ uint16
		var size uint32
		err := binary.Read(c.conn, binary.LittleEndian, &typ)
		if err != nil {
			return err
		}
		err = binary.Read(c.conn, binary.LittleEndian, &size)
		if err != nil {
			return err
		}

		if size > 10*1024*1024 {
			return errors.New("size too large, limited to 10MB")
		}
		if err := checkQuota(size); err != nil {
			return err
		}

		buf := make([]byte, size)
		if err = c.ReadFull(buf); err != nil {
			return err
		}
		return cb(typ, buf)
	}

	var size, subList uint32
	var typ uint16
	var serial uint64

	err := binary.Read(c.conn, binary.LittleEndian, &serial)
	if err != nil {
		return err
	}
	binary.Read(c.conn, binary.LittleEndian, &typ)
	binary.Read(c.conn, binary.LittleEndian, &size)
	binary.Read(c.conn, binary.LittleEndian, &subList)

	//log.Printf("spice: read data serial=%d type=%d size=%d subList=%d", d.Serial, d.Message.Type, size, subList)

	if size > 10*1024*1024 {
		return errors.New("size too large, limited to 10MB")
	}
	if err := checkQuota(size); err != nil {
		return err
	}

	buf := make([]byte, size)
	if err := c.ReadFull(buf); err != nil {
		return err
	}

	if subList == 0 {
		// simple
		return cb(typ, buf)
	}

	// Sub-list path. Every offset below is server-supplied — a hostile
	// SPICE server can otherwise trivially panic the client with a
	// crafted subList/subCnt/offt/size. Guard every slice against the
	// declared size.
	bufLen := uint32(len(buf))
	if subList > bufLen || subList+2 > bufLen {
		return fmt.Errorf("spice: sublist offset %d out of bounds (buf=%d)", subList, bufLen)
	}
	mainBuf := buf[:subList]

	subCnt := binary.LittleEndian.Uint16(buf[subList : subList+2])
	// Header uses 4 bytes per sub-entry offset. Reject before we even
	// touch the loop so we don't do partial delivery on a bad frame.
	if uint32(subCnt)*4+subList+2 > bufLen {
		return fmt.Errorf("spice: subCnt %d does not fit in buffer of %d", subCnt, bufLen)
	}
	for i := uint16(0); i < subCnt; i++ {
		offtPos := subList + 2 + (uint32(i) * 4)
		if offtPos+4 > bufLen {
			return fmt.Errorf("spice: sub-entry %d header offset out of bounds", i)
		}
		offt := binary.LittleEndian.Uint32(buf[offtPos : offtPos+4])
		// A sub-entry needs 2 bytes for type + 4 bytes for size before
		// any payload; verify that much is inside the buffer.
		if offt+6 > bufLen || offt+6 < offt {
			return fmt.Errorf("spice: sub-entry %d header extends past buffer", i)
		}

		size := binary.LittleEndian.Uint32(buf[offt+2 : offt+6])
		end := offt + 6 + size
		if end < offt+6 || end > bufLen {
			return fmt.Errorf("spice: sub-entry %d payload (size %d at %d) out of bounds", i, size, offt+6)
		}

		subTyp := binary.LittleEndian.Uint16(buf[offt : offt+2])
		subDat := buf[offt+6 : end]

		if err := cb(subTyp, subDat); err != nil {
			return err
		}
	}
	return cb(typ, mainBuf)
}

func (c *SpiceConn) WriteMessage(typ uint16, data ...interface{}) error {
	var buf []byte

	for _, subdata := range data {
		switch v := subdata.(type) {
		case []byte:
			if buf == nil {
				buf = v
			} else {
				buf = append(buf, v...)
			}
		default:
			w := &bytes.Buffer{}
			err := binary.Write(w, binary.LittleEndian, subdata)
			if err != nil {
				return err
			}
			if buf == nil {
				buf = w.Bytes()
			} else {
				buf = append(buf, w.Bytes()...)
			}
		}
	}
	c.wLock.Lock()
	defer c.wLock.Unlock()

	if c.miniHeaders {
		binary.Write(c.conn, binary.LittleEndian, typ)
		binary.Write(c.conn, binary.LittleEndian, uint32(len(buf)))
		_, err := c.conn.Write(buf)
		return err
	}

	// easy
	hdr := &bytes.Buffer{}
	serial := atomic.AddUint64(&c.serial, 1)

	binary.Write(hdr, binary.LittleEndian, serial)
	binary.Write(hdr, binary.LittleEndian, typ)
	binary.Write(hdr, binary.LittleEndian, uint32(len(buf)))
	binary.Write(hdr, binary.LittleEndian, uint32(len(buf)))

	_, err := c.Write(hdr.Bytes())
	if err != nil {
		return err
	}
	_, err = c.Write(buf)
	return err
}

func (c *SpiceConn) handshake(typ Channel, chId uint8, channelCaps []uint32) error {
	c.typ = typ
	c.id = chId
	err := c.sendSpiceLinkMess(typ, chId, channelCaps)
	if err != nil {
		return err
	}
	err = c.readSpiceLinkReply()
	if err != nil {
		return err
	}

	cnt := len(c.channelCaps)
	if cnt2 := len(channelCaps); cnt2 < cnt {
		cnt = cnt2
	}

	if cnt > 0 {
		c.validCaps = make([]uint32, cnt)
		for i := 0; i < cnt; i++ {
			c.validCaps[i] = channelCaps[i] & c.channelCaps[i]
		}
	}
	log.Printf("spice: %s channel req_caps=%v caps=%v valid_caps=%v", c.String(), channelCaps, c.channelCaps, c.validCaps)

	// encrypt password
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, c.pub, []byte(c.client.password), nil)
	if err != nil {
		return err
	}

	// Propagate write errors instead of blindly waiting for a reply.
	// Historically a short write here (e.g. TLS mid-handshake, closed
	// socket) would silently proceed into ReadError, where the peer
	// hang mimicked a server-side auth reject.
	if _, err := c.Write(ciphertext); err != nil {
		return fmt.Errorf("spice: write auth ciphertext: %w", err)
	}
	return c.ReadError()
}

func (c *SpiceConn) sendSpiceLinkMess(typ Channel, chId uint8, channelCaps []uint32) error {
	// generate a SpiceLinkMess packet and send
	pkt := &bytes.Buffer{}

	commonCaps := caps(SPICE_COMMON_CAP_MINI_HEADER)

	binary.Write(pkt, binary.LittleEndian, c.client.session)
	binary.Write(pkt, binary.LittleEndian, typ)
	binary.Write(pkt, binary.LittleEndian, chId)
	binary.Write(pkt, binary.LittleEndian, uint32(len(commonCaps)))  // num_common_caps
	binary.Write(pkt, binary.LittleEndian, uint32(len(channelCaps))) // num_channel_caps
	binary.Write(pkt, binary.LittleEndian, uint32(18))               // caps_offset

	for _, c := range commonCaps {
		binary.Write(pkt, binary.LittleEndian, c)
	}
	for _, c := range channelCaps {
		binary.Write(pkt, binary.LittleEndian, c)
	}

	buf := pkt.Bytes()

	pkt = &bytes.Buffer{}

	pkt.Write([]byte(SPICE_MAGIC))
	binary.Write(pkt, binary.LittleEndian, uint32(SPICE_VERSION_MAJOR))
	binary.Write(pkt, binary.LittleEndian, uint32(SPICE_VERSION_MINOR))
	binary.Write(pkt, binary.LittleEndian, uint32(len(buf)))
	pkt.Write(buf)

	// write
	_, err := pkt.WriteTo(c.conn)
	return err
}

func (c *SpiceConn) readSpiceLinkReply() error {
	hdr := make([]byte, 16)
	_, err := io.ReadFull(c.conn, hdr)
	if err != nil {
		return err
	}

	// hdr = magic + major_version + minor_version + size
	if string(hdr[:4]) != SPICE_MAGIC {
		return errors.New("invalid magic")
	}

	c.major = binary.LittleEndian.Uint32(hdr[4:8])
	c.minor = binary.LittleEndian.Uint32(hdr[8:12])
	size := binary.LittleEndian.Uint32(hdr[12:16])

	if size > 512 {
		return errors.New("SpiceLinkReply packet too large")
	}

	//log.Printf("spice: connected to server running Spice protocol version %d.%d", c.major, c.minor)

	pkt := make([]byte, size)
	_, err = io.ReadFull(c.conn, pkt)
	if err != nil {
		return err
	}

	//log.Printf("received data=\n%s", hex.Dump(pkt))

	r := bytes.NewReader(pkt)
	var spiceErr SpiceError
	binary.Read(r, binary.LittleEndian, &spiceErr)

	if spiceErr != ErrSpiceLinkOk {
		return fmt.Errorf("error in SpiceLinkReply packet: %w", spiceErr)
	}

	// 1024 bit RSA public key in X.509 SubjectPublicKeyInfo format
	pubKey := make([]byte, SPICE_TICKET_PUBKEY_BYTES)
	_, err = io.ReadFull(r, pubKey)
	if err != nil {
		return err
	}

	pk, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return err
	}
	if pk2, ok := pk.(*rsa.PublicKey); ok {
		c.pub = pk2
	} else {
		return errors.New("invalid public key")
	}

	var commonCaps, channelCaps, capsOffset uint32
	binary.Read(r, binary.LittleEndian, &commonCaps)
	binary.Read(r, binary.LittleEndian, &channelCaps)
	binary.Read(r, binary.LittleEndian, &capsOffset)

	_ = capsOffset

	for i := uint32(0); i < commonCaps; i++ {
		var v uint32
		binary.Read(r, binary.LittleEndian, &v)
		c.commonCaps = append(c.commonCaps, v)
	}
	for i := uint32(0); i < channelCaps; i++ {
		var v uint32
		binary.Read(r, binary.LittleEndian, &v)
		c.channelCaps = append(c.channelCaps, v)
	}

	if len(c.commonCaps) > 0 && c.commonCaps[0]&(1<<SPICE_COMMON_CAP_MINI_HEADER) == (1<<SPICE_COMMON_CAP_MINI_HEADER) {
		c.miniHeaders = true
	}

	// common caps= 0xb, channel caps=0x9 ... ... ???

	return nil
}

func (c *SpiceConn) Close() error {
	return c.conn.Close()
}
