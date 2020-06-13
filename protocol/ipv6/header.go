package ipv6

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/zartbot/network/pktreader"
	"github.com/zartbot/network/protocol/types"
)

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type ipv6hdr_t struct {
	VtcFlow    [4]byte
	PayloadLen pktreader.BEUint16
	NextProto  uint8
	HopLimits  uint8
	SrcAddr    pktreader.IPv6Address
	DstAddr    pktreader.IPv6Address
}

//IPv6Hdr is the decoded IPv6 header struct
type IPv6Hdr struct {
	Length       uint
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextProto    uint8
	HopLimits    uint8
	SrcAddr      net.IP
	DstAddr      net.IP
}

func (hdr *IPv6Hdr) String() string {
	return fmt.Sprintf("IPv6, Src: %s Dst: %s , Length: %d",
		hdr.SrcAddr.String(), hdr.DstAddr.String(), hdr.PayloadLen)
}

//Decode is used to decode IPv6 Header
func Decode(ptr unsafe.Pointer, len uint) (*IPv6Hdr, error) {
	if len < types.IPv6Len {
		return &IPv6Hdr{}, fmt.Errorf("IPv6 Header Decode:INVALID_LENGTH")
	}
	h := (*ipv6hdr_t)(ptr)
	result := &IPv6Hdr{
		Length:       types.IPv6Len,
		Version:      h.VtcFlow[0] & 0xF0 >> 4,
		TrafficClass: h.VtcFlow[0]&0x0F<<4 + h.VtcFlow[1]&0xF0>>4,
		FlowLabel:    uint32(h.VtcFlow[1]&0x0F)<<16 + uint32(h.VtcFlow[2])<<8 + uint32(h.VtcFlow[3]),
		PayloadLen:   h.PayloadLen.Read(),
		NextProto:    h.NextProto,
		HopLimits:    h.HopLimits,
		SrcAddr:      h.SrcAddr.Read(),
		DstAddr:      h.DstAddr.Read(),
	}

	return result, nil
}
