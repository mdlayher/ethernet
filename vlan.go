package ethernet

import (
	"encoding/binary"
	"io"
)

// A VLAN is an IEEE 802.1Q Virtual LAN (VLAN) tag.  A VLAN contains
// information regarding traffic priority and a VLAN identifier for
// a given Frame.
type VLAN struct {
	// Priority specifies a IEEE 802.1p priority level.
	Priority uint8

	// DropEligible indicates if a Frame is eligible to be dropped in the
	// presence of network congestion.
	DropEligible bool

	// ID specifies the VLAN ID for a Frame.  If ID is 0, no VLAN is
	// specified, and the other fields simply indicate a Frame's priority.
	ID uint16
}

// MarshalBinary allocates a byte slice and marshals a VLAN into binary form.
//
// MarshalBinary never returns an error.
func (v *VLAN) MarshalBinary() ([]byte, error) {
	// 3 bits: priority
	ub := uint16(v.Priority) << 13

	// 1 bit: drop eligible
	var drop uint16
	if v.DropEligible {
		drop = 1
	}
	ub |= drop << 12

	// 12 bits: VLAN ID
	ub |= v.ID

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, ub)

	return b, nil
}

// UnmarshalBinary unmarshals a byte slice into a Frame.
//
// If the byte slice does not contain exactly 2 bytes of data,
// io.ErrUnexpectedEOF is returned.
func (v *VLAN) UnmarshalBinary(b []byte) error {
	// VLAN tag is always 2 bytes
	if len(b) != 2 {
		return io.ErrUnexpectedEOF
	}

	//  3 bits: priority
	//  1 bit : drop eligible
	// 12 bits: VLAN ID
	ub := binary.BigEndian.Uint16(b[0:2])
	v.Priority = uint8(ub >> 13)
	v.DropEligible = ub&0x1000 != 0
	v.ID = ub & 0x0fff

	return nil
}
