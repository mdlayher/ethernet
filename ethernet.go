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
	// not be present in a Frame.  If no VLAN tags are present, this length of
	// the slice will be 0.
	VLAN []*VLAN

	// EtherType is a value used to identify an upper layer protocol
	// encapsulated in this Frame.
	EtherType EtherType

	// Payload is a variable length data payload encapsulated by this Frame.
	Payload []byte
}

// MarshalBinary allocates a byte slice and marshals a Frame into binary form.
//
// MarshalBinary never returns an error.
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
		// vlan.MarshalBinary never returns an error.
		vb, _ := v.MarshalBinary()

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

		// Body of VLAN tag is 2 bytes in length; will not return an error
		// because of the above length check
		vlan := new(VLAN)
		_ = vlan.UnmarshalBinary(b[n : n+2])
		f.VLAN = append(f.VLAN, vlan)

		// Parse next tag to determine if it is another VLAN, or if not,
		// break the loop
		et = EtherType(binary.BigEndian.Uint16(b[n+2 : n+4]))
	}
	f.EtherType = et

	// Payload must be 46 bytes minimum, but the required number decreases
	// to 42 if a VLAN tag is present.
	//
	// TODO(mdlayher): confirm if multiple VLAN tags further decrease this
	// threshold.  For now, this is the way this check is implemented.
	if len(b[n:]) < 46-(len(f.VLAN)*4) {
		return io.ErrUnexpectedEOF
	}

	payload := make([]byte, len(b[n:]))
	copy(payload, b[n:])
	f.Payload = payload

	return nil
}
