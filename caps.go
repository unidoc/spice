package spice

// SPICE capability negotiation. Caps are packed into a []uint32 where
// bit N of word W represents capability N + 32*W. Historically the
// helpers here treated caps as a single word — anything with N >= 32
// silently vanished (in the caps() builder) or was misread (in
// testCap). Display already has caps > 31 (CAP_CODEC_H265=14 fits in
// word 0 but future additions will not), and the protocol reserves the
// second word for exactly this reason.

// caps builds a bit-packed capability array from a list of capability
// indices. Any capability with index >= 32 is placed in the correct
// word; missing words in between are zero-filled.
func caps(c ...uint32) []uint32 {
	if len(c) == 0 {
		return []uint32{0}
	}
	// Find the highest word we need.
	max := uint32(0)
	for _, n := range c {
		if n/32 > max {
			max = n / 32
		}
	}
	out := make([]uint32, max+1)
	for _, n := range c {
		out[n/32] |= 1 << (n % 32)
	}
	return out
}

// testCap reports whether capability `value` is set in the single-word
// caps `b`. Kept for backwards compatibility with existing call sites
// that pass `conn.validCaps[0]`.
func testCap(b, value uint32) bool {
	if value >= 32 {
		return false
	}
	return (b & (1 << value)) != 0
}

// testCapMulti reports whether capability `value` is set in the
// multi-word caps slice. New call sites should prefer this — a caps
// array shorter than the word `value` falls into is treated as
// "capability absent" rather than panicking.
func testCapMulti(caps []uint32, value uint32) bool {
	word := int(value / 32)
	if word >= len(caps) {
		return false
	}
	return (caps[word] & (1 << (value % 32))) != 0
}
