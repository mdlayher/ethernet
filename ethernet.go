// Package ethernet implements marshaling and unmarshaling of IEEE 802.3
// Ethernet II frames and IEEE 802.1Q VLAN tags.
package ethernet

import (
	"encoding/binary"
	"io"
	"net"
)

//go:generate stringer -output=string.go -type=EtherType

var (
	// Broadcast is a special MAC address which indicates a Frame should be
	// sent to every device on a given LAN segment.
	Broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

// An EtherType is a value used to identify an upper layer protocol
// encapsulated in a Frame.
//
// A list of IANA-assigned EtherType values may be found here:
// http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml.
type EtherType uint16

// Common EtherType values frequently used in a Frame.
const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeVLAN EtherType = 0x8100
	EtherTypeIPv6 EtherType = 0x86DD
)

// A Frame is an IEEE 802.3 Ethernet II frame.  A Frame contains information
// such as source and destination MAC addresses, zero or more optional 802.1Q
// VLAN tags, an EtherType, and payload data.
type Frame struct {
	// DestinationMAC specifies the destination MAC address for this Frame.
	// If this address is set to Broadcast, the Frame will be sent to every
	// device on a given LAN segment.
	DestinationMAC net.HardwareAddr

	// SourceMAC specifies the source MAC address for this Frame.  Typically,
	// this MAC address is the address of the network interface used to send
	// this Frame.
	SourceMAC net.HardwareAddr

	// VLAN specifies one or more optional 802.1Q VLAN tags, which may or may
	// not be present in a Frame.  It is important to note that the operating
	// system may automatically strip VLAN tags before they can be parsed.
	//
	// If no VLAN tags are present, this length of the slice will be 0.
	VLAN []*VLAN

	// EtherType is a value used to identify an upper layer protocol
	// encapsulated in this Frame.
	EtherType EtherType

	// Payload is a variable length data payload encapsulated by this Frame.
	Payload []byte
}

// MarshalBinary allocates a byte slice and marshals a Frame into binary form.
//
// If one or more VLANs are set and their priority values are too large
// (greater than 7), or their IDs are too large (greater than 4094),
// ErrInvalidVLAN is returned.
func (f *Frame) MarshalBinary() ([]byte, error) {
	// 6 bytes: destination MAC
	// 6 bytes: source MAC
	// N bytes: 4 * N VLAN tags
	// 2 bytes: EtherType
	// N bytes: payload length
	//
	// We let the operating system handle the checksum and the interpacket gap
	b := make([]byte, 6+6+(4*len(f.VLAN))+2+len(f.Payload))

	copy(b[0:6], f.DestinationMAC)
	copy(b[6:12], f.SourceMAC)

	// Marshal each VLAN tag into bytes, inserting a VLAN EtherType value
	// before each, so devices know that one or more VLANs are present.
	n := 12
	for _, v := range f.VLAN {
		// If VLAN contains any invalid values, an error will be returned here
		vb, err := v.MarshalBinary()
		if err != nil {
			return nil, err
		}

		// Add VLAN EtherType and VLAN bytes
		binary.BigEndian.PutUint16(b[n:n+2], uint16(EtherTypeVLAN))
		copy(b[n+2:n+4], vb)
		n += 4
	}

	// Marshal actual EtherType after any VLANs, copy payload into
	// output bytes.
	binary.BigEndian.PutUint16(b[n:n+2], uint16(f.EtherType))
	copy(b[n+2:], f.Payload)

	return b, nil
}

// UnmarshalBinary unmarshals a byte slice into a Frame.
//
// If the byte slice does not contain enough data to unmarshal a valid Frame,
// io.ErrUnexpectedEOF is returned.
//
// If one or more VLANs are detected and their IDs are too large (greater than
// 4094), ErrInvalidVLAN is returned.
func (f *Frame) UnmarshalBinary(b []byte) error {
	// Verify that both MAC addresses and a single EtherType are present
	if len(b) < 14 {
		return io.ErrUnexpectedEOF
	}

	dst := make(net.HardwareAddr, 6)
	copy(dst, b[0:6])
	f.DestinationMAC = dst

	src := make(net.HardwareAddr, 6)
	copy(src, b[6:12])
	f.SourceMAC = src

	// Track offset in packet for writing data
	n := 14

	// Continue looping and parsing VLAN tags until no more VLAN EtherType
	// values are detected
	et := EtherType(binary.BigEndian.Uint16(b[n-2 : n]))
	for ; et == EtherTypeVLAN; n += 4 {
		// 2 or more bytes must remain for valid VLAN tag
		if len(b[n:]) < 2 {
			return io.ErrUnexpectedEOF
		}

		// Body of VLAN tag is 2 bytes in length
		vlan := new(VLAN)
		if err := vlan.UnmarshalBinary(b[n : n+2]); err != nil {
			return err
		}
		f.VLAN = append(f.VLAN, vlan)

		// Parse next tag to determine if it is another VLAN, or if not,
		// break the loop
		et = EtherType(binary.BigEndian.Uint16(b[n+2 : n+4]))
	}
	f.EtherType = et

	// Payload must be 46 bytes minimum, but the required number decreases
	// to 42 if a VLAN tag is present.
	//
	// Special case: the operating system will likely automatically remove VLAN
	// tags before we get ahold of the traffic.  If the packet length seems to
	// indicate that a VLAN tag was present (42 bytes payload instead of 46
	// bytes), but no VLAN tags were detected, we relax the minimum length
	// restriction and act as if a VLAN tag was detected.

	// Check how many bytes under minimum the payload is
	l := 46 - len(b[n:])

	// Check for number of VLANs detected, but only use 1 to reduce length
	// requirement if more than 1 is present
	vl := len(f.VLAN)
	if vl > 1 {
		vl = 1
	}

	// If no VLANs detected and exactly 4 bytes below requirement, a VLAN tag
	// may have been stripped, so factor a single VLAN tag into the minimum length
	// requirement
	if vl == 0 && l == 4 {
		vl++
	}
	if len(b[n:]) < 46-(vl*4) {
		return io.ErrUnexpectedEOF
	}

	payload := make([]byte, len(b[n:]))
	copy(payload, b[n:])
	f.Payload = payload

	return nil
}
