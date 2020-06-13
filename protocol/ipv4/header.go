package ipv4

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
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type ipv4hdr_t struct {
	VersionIhl    uint8
	TypeOfService uint8
	TotalLength   pktreader.BEUint16
	PacketID      pktreader.BEUint16
	FlagFragment  [2]byte
	TimeToLive    uint8
	NextProto     uint8
	HdrChecksum   pktreader.BEUint16
	SrcAddr       pktreader.IPv4Address
	DstAddr       pktreader.IPv4Address
}

//IPv4Hdr is the decoded IPv4 header struct
type IPv4Hdr struct {
	Version        uint8
	Length         uint
	TotalLength    uint16
	PacketID       uint16
	DF             bool
	MF             bool
	FragmentOffset uint16
	TTL            uint8
	NextProto      uint8
	Chksum         uint16
	SrcAddr        net.IP
	DstAddr        net.IP
}

func (hdr *IPv4Hdr) String() string {
	return fmt.Sprintf("IPv4, Src: %s Dst: %s , Length: %d",
		hdr.SrcAddr.String(), hdr.DstAddr.String(), hdr.TotalLength)
}

//Decode is used to decode IPv4 Header
func Decode(ptr unsafe.Pointer, len uint) (*IPv4Hdr, error) {
	if len < types.IPv4MinLen {
		return &IPv4Hdr{}, fmt.Errorf("IPv4 Header Decode:INVALID_LENGTH")
	}
	h := (*ipv4hdr_t)(ptr)
	result := &IPv4Hdr{
		Version:        h.VersionIhl & 0xF0 >> 4,
		Length:         uint(h.VersionIhl&0x0F) << 2,
		TotalLength:    h.TotalLength.Read(),
		PacketID:       h.PacketID.Read(),
		DF:             h.FlagFragment[0]&40 > 0,
		MF:             h.FlagFragment[0]&20 > 0,
		FragmentOffset: uint16(h.FlagFragment[0]&0x1F)<<8 + uint16(h.FlagFragment[1]),
		TTL:            h.TimeToLive,
		NextProto:      h.NextProto,
		SrcAddr:        h.SrcAddr.Read(),
		DstAddr:        h.DstAddr.Read(),
	}

	if len < result.Length {
		return result, fmt.Errorf("IPv4 Header Decode:INVALID_LENGTH")
	}
	return result, nil
}
