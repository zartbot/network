package udp

import (
	"fmt"
	"unsafe"

	"github.com/zartbot/network/pktreader"
	"github.com/zartbot/network/protocol/types"
)

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Length              |            CheckSum           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

type udphdr_t struct {
	SrcPort       pktreader.BEUint16
	DstPort       pktreader.BEUint16
	PayloadLength pktreader.BEUint16
	ChkSum        pktreader.BEUint16
}

type UDPHdr struct {
	SrcPort       uint16
	DstPort       uint16
	PayloadLength uint16
	ChkSum        uint16
}

func (hdr *UDPHdr) String() string {
	return fmt.Sprintf("UDP, Src: %d Dst: %d , Length: %d",
		hdr.SrcPort, hdr.DstPort, hdr.PayloadLength)
}

//Decode is used to decode IPv4 Header
func Decode(ptr unsafe.Pointer, len uint) (*UDPHdr, error) {
	if len < types.UDPLen {
		return &UDPHdr{}, fmt.Errorf("UDP Header Decode:INVALID_LENGTH")
	}
	h := (*udphdr_t)(ptr)
	result := &UDPHdr{
		SrcPort:       h.SrcPort.Read(),
		DstPort:       h.DstPort.Read(),
		PayloadLength: h.PayloadLength.Read(),
		ChkSum:        h.ChkSum.Read(),
	}
	return result, nil
}
