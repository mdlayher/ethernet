package ethernet

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"
)

func TestFrameMarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		f    *Frame
		b    []byte
		err  error
	}{
		{
			desc: "VLAN priority too large",
			f: &Frame{
				VLAN: []*VLAN{{
					Priority: 8,
				}},
			},
			err: ErrInvalidVLAN,
		},
		{
			desc: "VLAN ID too large",
			f: &Frame{
				VLAN: []*VLAN{{
					ID: VLANMax,
				}},
			},
			err: ErrInvalidVLAN,
		},
		{
			desc: "IPv4, no VLANs",
			f: &Frame{
				Destination: net.HardwareAddr{0, 1, 0, 1, 0, 1},
				Source:      net.HardwareAddr{1, 0, 1, 0, 1, 0},
				EtherType:   EtherTypeIPv4,
				Payload:     bytes.Repeat([]byte{0}, 50),
			},
			b: append([]byte{
				0, 1, 0, 1, 0, 1,
				1, 0, 1, 0, 1, 0,
				0x08, 0x00,
			}, bytes.Repeat([]byte{0}, 50)...),
		},
		{
			desc: "IPv6, 1 VLAN: PRI 1, ID 101",
			f: &Frame{
				Destination: net.HardwareAddr{1, 0, 1, 0, 1, 0},
				Source:      net.HardwareAddr{0, 1, 0, 1, 0, 1},
				VLAN: []*VLAN{{
					Priority: 1,
					ID:       101,
				}},
				EtherType: EtherTypeIPv6,
				Payload:   bytes.Repeat([]byte{0}, 50),
			},
			b: append([]byte{
				1, 0, 1, 0, 1, 0,
				0, 1, 0, 1, 0, 1,
				0x81, 0x00,
				0x20, 0x65,
				0x86, 0xDD,
			}, bytes.Repeat([]byte{0}, 50)...),
		},
		{
			desc: "ARP, 2 VLANs: (PRI 0, DROP, ID 100) (PRI 1, ID 101)",
			f: &Frame{
				Destination: Broadcast,
				Source:      net.HardwareAddr{0, 1, 0, 1, 0, 1},
				VLAN: []*VLAN{
					{
						DropEligible: true,
						ID:           100,
					},
					{
						Priority: 1,
						ID:       101,
					},
				},
				EtherType: EtherTypeARP,
				Payload:   bytes.Repeat([]byte{0}, 50),
			},
			b: append([]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0, 1, 0, 1, 0, 1,
				0x81, 0x00,
				0x10, 0x64,
				0x81, 0x00,
				0x20, 0x65,
				0x08, 0x06,
			}, bytes.Repeat([]byte{0}, 50)...),
		},
	}

	for i, tt := range tests {
		b, err := tt.f.MarshalBinary()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Frame bytes:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}

func TestFrameUnmarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		b    []byte
		f    *Frame
		err  error
	}{
		{
			desc: "nil buffer",
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "short buffer",
			b:    bytes.Repeat([]byte{0}, 13),
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "1 short VLAN",
			b: []byte{
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x81, 0x00,
				0x00,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "VLAN ID too large",
			b: []byte{
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x81, 0x00,
				0xff, 0xff,
				0x00, 0x00,
			},
			err: ErrInvalidVLAN,
		},
		{
			desc: "go-fuzz crasher: VLAN tag without enough bytes for trailing EtherType",
			b:    []byte("190734863281\x81\x0032"),
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "0 VLANs detected, but 1 may have been present",
			b:    bytes.Repeat([]byte{0}, 56),
			f: &Frame{
				Destination: net.HardwareAddr{0, 0, 0, 0, 0, 0},
				Source:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
				Payload:     bytes.Repeat([]byte{0}, 42),
			},
		},
		{
			desc: "IPv4, no VLANs",
			b: append([]byte{
				0, 1, 0, 1, 0, 1,
				1, 0, 1, 0, 1, 0,
				0x08, 0x00,
			}, bytes.Repeat([]byte{0}, 50)...),
			f: &Frame{
				Destination: net.HardwareAddr{0, 1, 0, 1, 0, 1},
				Source:      net.HardwareAddr{1, 0, 1, 0, 1, 0},
				EtherType:   EtherTypeIPv4,
				Payload:     bytes.Repeat([]byte{0}, 50),
			},
		},
		{
			desc: "IPv6, 1 VLAN: PRI 1, ID 101",
			b: append([]byte{
				1, 0, 1, 0, 1, 0,
				0, 1, 0, 1, 0, 1,
				0x81, 0x00,
				0x20, 0x65,
				0x86, 0xDD,
			}, bytes.Repeat([]byte{0}, 50)...),
			f: &Frame{
				Destination: net.HardwareAddr{1, 0, 1, 0, 1, 0},
				Source:      net.HardwareAddr{0, 1, 0, 1, 0, 1},
				VLAN: []*VLAN{{
					Priority: 1,
					ID:       101,
				}},
				EtherType: EtherTypeIPv6,
				Payload:   bytes.Repeat([]byte{0}, 50),
			},
		},
		{
			desc: "ARP, 2 VLANs: (PRI 0, DROP, ID 100), (PRI 1, ID 101)",
			b: append([]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0, 1, 0, 1, 0, 1,
				0x81, 0x00,
				0x10, 0x64,
				0x81, 0x00,
				0x20, 0x65,
				0x08, 0x06,
			}, bytes.Repeat([]byte{0}, 50)...),
			f: &Frame{
				Destination: Broadcast,
				Source:      net.HardwareAddr{0, 1, 0, 1, 0, 1},
				VLAN: []*VLAN{
					{
						DropEligible: true,
						ID:           100,
					},
					{
						Priority: 1,
						ID:       101,
					},
				},
				EtherType: EtherTypeARP,
				Payload:   bytes.Repeat([]byte{0}, 50),
			},
		},
	}

	for i, tt := range tests {
		f := new(Frame)
		if err := f.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.f, f; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Frame:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}

// Benchmarks for Frame.MarshalBinary with varying VLAN tags and payloads

func BenchmarkFrameMarshalBinary(b *testing.B) {
	f := &Frame{
		Payload: []byte{0, 1, 2, 3, 4},
	}

	benchmarkFrameMarshalBinary(b, f)
}

func BenchmarkFrameMarshalBinaryOneVLAN(b *testing.B) {
	f := &Frame{
		VLAN: []*VLAN{
			{
				Priority: PriorityBackground,
				ID:       10,
			},
		},
		Payload: []byte{0, 1, 2, 3, 4},
	}

	benchmarkFrameMarshalBinary(b, f)
}

func BenchmarkFrameMarshalBinaryTwoVLANs(b *testing.B) {
	f := &Frame{
		VLAN: []*VLAN{
			{
				Priority: PriorityBackground,
				ID:       10,
			},
			{
				Priority: PriorityBestEffort,
				ID:       20,
			},
		},
		Payload: []byte{0, 1, 2, 3, 4},
	}

	benchmarkFrameMarshalBinary(b, f)
}

func BenchmarkFrameMarshalBinaryJumboPayload(b *testing.B) {
	f := &Frame{
		Payload: make([]byte, 8192),
	}

	benchmarkFrameMarshalBinary(b, f)
}

func benchmarkFrameMarshalBinary(b *testing.B, f *Frame) {
	f.Destination = net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}
	f.Source = net.HardwareAddr{0xad, 0xbe, 0xef, 0xde, 0xad, 0xde}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := f.MarshalBinary(); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmarks for Frame.UnmarshalBinary with varying VLAN tags and payloads

func BenchmarkFrameUnmarshalBinary(b *testing.B) {
	f := &Frame{
		Payload: []byte{0, 1, 2, 3, 4},
	}

	benchmarkFrameUnmarshalBinary(b, f)
}

func BenchmarkFrameUnmarshalBinaryOneVLAN(b *testing.B) {
	f := &Frame{
		VLAN: []*VLAN{
			{
				Priority: PriorityBackground,
				ID:       10,
			},
		},
		Payload: []byte{0, 1, 2, 3, 4},
	}

	benchmarkFrameUnmarshalBinary(b, f)
}

func BenchmarkFrameUnmarshalBinaryTwoVLANs(b *testing.B) {
	f := &Frame{
		VLAN: []*VLAN{
			{
				Priority: PriorityBackground,
				ID:       10,
			},
			{
				Priority: PriorityBestEffort,
				ID:       20,
			},
		},
		Payload: []byte{0, 1, 2, 3, 4},
	}

	benchmarkFrameUnmarshalBinary(b, f)
}

func BenchmarkFrameUnmarshalBinaryJumboPayload(b *testing.B) {
	f := &Frame{
		Payload: make([]byte, 8192),
	}

	benchmarkFrameUnmarshalBinary(b, f)
}

func benchmarkFrameUnmarshalBinary(b *testing.B, f *Frame) {
	f.Destination = net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}
	f.Source = net.HardwareAddr{0xad, 0xbe, 0xef, 0xde, 0xad, 0xde}

	fb, err := f.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := f.UnmarshalBinary(fb); err != nil {
			b.Fatal(err)
		}
	}
}
