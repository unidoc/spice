package spice

import (
	"encoding/binary"
	"log"
	"sync"
	"time"
)

const (
	SPICE_MSGC_INPUTS_KEY_DOWN      = 101
	SPICE_MSGC_INPUTS_KEY_UP        = 102
	SPICE_MSGC_INPUTS_KEY_MODIFIERS = 103

	SPICE_MSGC_INPUTS_MOUSE_MOTION   = 111
	SPICE_MSGC_INPUTS_MOUSE_POSITION = 112
	SPICE_MSGC_INPUTS_MOUSE_PRESS    = 113
	SPICE_MSGC_INPUTS_MOUSE_RELEASE  = 114

	SPICE_MSG_INPUTS_INIT          = 101
	SPICE_MSG_INPUTS_KEY_MODIFIERS = 102

	SPICE_MSG_INPUTS_MOUSE_MOTION_ACK = 111

	// Keyboard led bits
	SPICE_SCROLL_LOCK_MODIFIER = 1
	SPICE_NUM_LOCK_MODIFIER    = 2
	SPICE_CAPS_LOCK_MODIFIER   = 4

	SPICE_INPUTS_CAP_KEY_SCANCODE = 0
)

type ChInputs struct {
	cl   *Client
	conn *SpiceConn

	// btn state
	btn uint16

	// Mouse-position coalescing. Fyne (and most GUI toolkits) fire
	// 60-90 MouseMoved events per second while the pointer is
	// moving; each turns into a MOUSE_POSITION WriteMessage over the
	// wire. Over VPN that's serialised latency plus wasted bandwidth
	// for intermediate positions the guest never renders. Coalesce
	// into ~60 fps peak: send the first event immediately, then hold
	// subsequent ones in `mousePending` until a single timer flushes
	// the latest position.
	mouseLk      sync.Mutex
	mouseLast    time.Time
	mouseTimer   *time.Timer
	mousePending struct {
		x, y  uint32
		valid bool
	}
}

// mouseMinInterval bounds outbound MOUSE_POSITION messages. 16 ms ≈ 60
// fps, which matches typical guest OS pointer rendering. Lower than
// this only adds VPN chatter without visible improvement.
const mouseMinInterval = 16 * time.Millisecond

func (cl *Client) setupInputs(id uint8) (*ChInputs, error) {
	conn, err := cl.conn(ChannelInputs, id, nil) //caps(SPICE_INPUTS_CAP_KEY_SCANCODE))
	if err != nil {
		return nil, err
	}

	input := &ChInputs{cl: cl, conn: conn}
	conn.hndlr = input.handle
	go conn.ReadLoop()

	// reset keyboard leds
	input.conn.WriteMessage(SPICE_MSGC_INPUTS_KEY_MODIFIERS, uint16(0))

	cl.driver.SetEventsTarget(input)

	return input, nil
}

func (input *ChInputs) handle(typ uint16, data []byte) {
	switch typ {
	case SPICE_MSG_INPUTS_INIT:
		// Note: spice documentation is wrong, this is 16bits and not 32bits
		keyMod := binary.LittleEndian.Uint16(data)
		log.Printf("spice/inputs: got key modifier status from server, value = %d (initial)", keyMod)
	case SPICE_MSG_INPUTS_KEY_MODIFIERS:
		keyMod := binary.LittleEndian.Uint16(data)
		log.Printf("spice/inputs: got key modifier status from server, value = %d", keyMod)
	case SPICE_MSG_INPUTS_MOUSE_MOTION_ACK:
		// do nothing
	default:
		log.Printf("spice/inputs: got message type=%d", typ)
	}
}

func (input *ChInputs) OnKeyDown(k []byte) {
	if len(k) == 0 {
		return
	}
	scancode := make([]byte, 4)
	copy(scancode, k)

	input.conn.WriteMessage(SPICE_MSGC_INPUTS_KEY_DOWN, scancode)
}

func (input *ChInputs) OnKeyUp(k []byte) {
	// An empty scancode used to panic on `scancode[ln-1]` (ln=0). At
	// least one Fyne key event (Fn-lock on some laptops) delivers a
	// zero-byte scancode. Drop rather than crash. Also cap to 4 —
	// scancodes are per-message max 4 bytes; anything longer would be
	// silently truncated by the copy which is misleading.
	ln := len(k)
	if ln == 0 {
		return
	}
	if ln > 4 {
		ln = 4
	}
	scancode := make([]byte, 4)
	copy(scancode, k[:ln])

	// AT scancode: insert 0xF0 before last byte
	// XT scancode: set top bit of last part
	scancode[ln-1] |= 0x80

	input.conn.WriteMessage(SPICE_MSGC_INPUTS_KEY_UP, scancode)
}

func (input *ChInputs) MousePosition(x, y uint32) {
	input.mouseLk.Lock()
	now := time.Now()
	if now.Sub(input.mouseLast) >= mouseMinInterval {
		// Cold path — enough time has elapsed, send now.
		input.mouseLast = now
		input.mousePending.valid = false
		input.mouseLk.Unlock()
		input.sendMousePosition(x, y)
		return
	}
	// Hot path — coalesce. Overwrite any pending position; the guest
	// only cares about the final one.
	input.mousePending.x = x
	input.mousePending.y = y
	input.mousePending.valid = true
	if input.mouseTimer == nil {
		delay := mouseMinInterval - now.Sub(input.mouseLast)
		input.mouseTimer = time.AfterFunc(delay, input.flushMousePosition)
	}
	input.mouseLk.Unlock()
}

// flushMousePosition is invoked by the coalescing timer to send the
// most recent buffered position. Runs on its own goroutine (the
// AfterFunc callback runs in a fresh goroutine, per time.AfterFunc
// semantics) so we take the lock and read pending state safely.
func (input *ChInputs) flushMousePosition() {
	input.mouseLk.Lock()
	input.mouseTimer = nil
	if !input.mousePending.valid {
		input.mouseLk.Unlock()
		return
	}
	x, y := input.mousePending.x, input.mousePending.y
	input.mousePending.valid = false
	input.mouseLast = time.Now()
	input.mouseLk.Unlock()
	input.sendMousePosition(x, y)
}

func (input *ChInputs) sendMousePosition(x, y uint32) {
	var displayID uint8
	err := input.conn.WriteMessage(SPICE_MSGC_INPUTS_MOUSE_POSITION, x, y, input.btn, displayID)
	if err != nil {
		log.Printf("Failed to send mouse position: %s", err)
	}
}

// SPICE protocol splits button identifiers in two conventions in the same
// message: `button` is 1-based (LEFT=1, MIDDLE=2, RIGHT=3, WHEEL_UP=4,
// WHEEL_DOWN=5), but `buttons_state` is a bitmask where bit N is button
// N+1 (bit 0=LEFT, bit 1=MIDDLE, bit 2=RIGHT). The original `1 << btn`
// was off-by-one — for a left click (btn=1) it set the MIDDLE bit, so the
// guest OS saw "middle button pressed" and ignored real left clicks.
func (input *ChInputs) MouseDown(btn uint8, x, y uint32) {
	state := uint16(1) << (btn - 1)

	if input.btn&state == state {
		log.Printf("ignoring btn down %d", btn)
		return // already pressed
	}

	input.btn |= state

	input.conn.WriteMessage(SPICE_MSGC_INPUTS_MOUSE_PRESS, btn, input.btn)
}

func (input *ChInputs) MouseUp(btn uint8, x, y uint32) {
	state := uint16(1) << (btn - 1)

	if input.btn&state == 0 {
		log.Printf("ignoring btn up %d", btn)
		return // already released
	}

	input.btn &= ^state

	input.conn.WriteMessage(SPICE_MSGC_INPUTS_MOUSE_RELEASE, btn, input.btn)
}
