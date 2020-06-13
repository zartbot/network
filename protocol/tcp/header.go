package tcp

import (
	"fmt"
	"unsafe"

	"github.com/zartbot/network/pktreader"
	"github.com/zartbot/network/protocol/types"
)

/*

  TCP Header Format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |       |C|E|U|A|P|R|S|F|                               |
   | Offset| Rsvd  |W|C|R|C|S|S|Y|I|            Window             |
   |       |       |R|E|G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            TCP Header Format

*/

type tcphdr_t struct {
	SrcPort    pktreader.BEUint16
	DstPort    pktreader.BEUint16
	SeqNum     pktreader.BEUint32
	AckNum     pktreader.BEUint32
	DataLength uint8
	Flags      uint8
	Window     pktreader.BEUint16
	Chksum     pktreader.BEUint16
	UrgPtr     pktreader.BEUint16
}

type TCPHdr struct {
	SrcPort  uint16
	DstPort  uint16
	SentSeq  uint32
	RecvAck  uint32
	Length   uint
	TCPFlags types.TCP_FLAGS
	RxWin    uint16
	ChkSum   uint16
	UrgPtr   uint16
	Option   *TCPOption
}

func (hdr *TCPHdr) String() string {
	return fmt.Sprintf("TCP, Src: %d Dst: %d , Length: %d",
		hdr.SrcPort, hdr.DstPort, hdr.Length)
}

//Decode is used to decode IPv4 Header
func Decode(ptr unsafe.Pointer, len uint) (*TCPHdr, error) {
	if len < types.TCPMinLen {
		return &TCPHdr{}, fmt.Errorf("TCP Header Decode:INVALID_LENGTH")
	}
	h := (*tcphdr_t)(ptr)
	result := &TCPHdr{
		SrcPort:  h.SrcPort.Read(),
		DstPort:  h.DstPort.Read(),
		SentSeq:  h.SeqNum.Read(),
		RecvAck:  h.AckNum.Read(),
		Length:   uint(h.DataLength>>4) << 2,
		TCPFlags: types.TCP_FLAGS(h.Flags),
		RxWin:    h.Window.Read(),
		ChkSum:   h.Chksum.Read(),
		UrgPtr:   h.UrgPtr.Read(),
		Option:   &TCPOption{},
	}

	if result.Length > types.TCPMinLen {

		optionStartPtr := unsafe.Pointer(uintptr(ptr) + uintptr(types.TCPMinLen))
		optionLength := uint(result.Length - types.TCPMinLen)
		err := result.Option.DecodeTCPOption(optionStartPtr, optionLength)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}
