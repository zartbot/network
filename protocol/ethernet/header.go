package ethernet

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/zartbot/network/pktreader"
	"github.com/zartbot/network/protocol/types"
)

const (
	EtherType_IPV4 = 0x0800
	EtherType_ARP  = 0x0806
	EtherType_VLAN = 0x8100
	EtherType_MPLS = 0x8847
	EtherType_IPV6 = 0x86dd
)

//Internal use for mapping with unsafe.Pointer
type etherHdr_t struct {
	DAddr     pktreader.MACAddress
	SAddr     pktreader.MACAddress
	EtherType pktreader.BEUint16
}

type EtherHdr struct {
	Length    uint
	DstAddr   net.HardwareAddr
	SrcAddr   net.HardwareAddr
	EtherType uint16
}

func (hdr *EtherHdr) String() string {
	return fmt.Sprintf("Ethernet, EtherType: 0x%04x Src: %s Dst: %s",
		hdr.EtherType, hdr.SrcAddr.String(), hdr.DstAddr.String(),
	)
}

//Decode is used to decode Ethernet Header
func Decode(ptr unsafe.Pointer, len uint) (*EtherHdr, error) {
	h := (*etherHdr_t)(ptr)
	if len < types.EtherLen {
		return &EtherHdr{}, fmt.Errorf("EthernetHeader Decode:INVALID_LENGTH")
	}
	result := &EtherHdr{
		Length:    types.EtherLen,
		EtherType: h.EtherType.Read(),
		SrcAddr:   h.SAddr.Read(),
		DstAddr:   h.DAddr.Read(),
	}
	return result, nil
}
