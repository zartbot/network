package tcp

import (
	"fmt"
	"unsafe"

	"github.com/zartbot/network/pktreader"
)

/*
TCP Option

Kind(Type) 	Length 		Name			Reference   	描述 & 用途
0  			1   		EOL  			RFC 793   		选项列表结束
1  			1 			NOP  			RFC 793  		无操作（用于补位填充）
2  			4  			MSS  			RFC 793  		最大Segment长度
3  			3  			WSOPT  			RFC 1323   		窗口扩大系数（Window Scaling Factor）
4  			2			SACK-Premitted  RFC 2018   		SACK Capability Annoucement
5 			Variable	SACK  			RFC 2018  		SACK Block（收到乱序数据）
8  			10   		TSPOT  			RFC 1323  		Timestamps
19  		18 			TCP-MD5 		RFC 2385 		MD5认证
28  		4  			UTO  			RFC 5482  		User Timeout（超过一定闲置时间后拆除连接）
29  		Variable 	TCP-AO 			RFC 5925 		认证（可选用各种算法）
253/254 	Variable 	Experimental 	RFC 4727 		保留，用于科研实验


一般Option的格式为TLV结构，如下所示：

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Kind       |   Length      |       Value...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

1.    EOL和NOP Option（Kind 0、Kind 1）只占1 Byte，没有Length和Value字段；
2.    NOP用于 将TCP Header的长度补齐至32bit的倍数（由于Header Length字段以32bit为单位，因此TCP Header的长度一定是32bit的倍数）；
3.    SACK-Premitted Option占2 Byte，没有Value字段；
4.    其余Option都以1 Byte的“Kind”开头，指明Option的类型；Length指明Option的总长度（包括Kind和Length）
5.    对于收到“不能理解”的Option，TCP会无视掉，并不影响该TCP Segment的其它内容；
*/

const (
	TCP_OPTION_EOL         uint8 = 0
	TCP_OPTION_NOP         uint8 = 1
	TCP_OPTION_MSS         uint8 = 2
	TCP_OPTION_WSOPT       uint8 = 3
	TCP_OPTION_SACK_PERMIT uint8 = 4
	TCP_OPTION_SACK        uint8 = 5
	TCP_OPTION_TSOPT       uint8 = 8
	TCP_OPTION_MD5         uint8 = 19
	TCP_OPTION_UTO         uint8 = 28
	TCP_OPTION_AO          uint8 = 29
)

type TCPOption struct {
	MSS      uint16
	SACK     bool
	WinScale uint8
}

//DecodeTCPOption is used to decode TCP option header
//    ptr: the start pointer to optionfield
//    len: calculated by TCP HeaderOffset
func (t *TCPOption) DecodeTCPOption(ptr unsafe.Pointer, len uint) error {
	for {
		if len < 1 {
			return nil
		}
		//read kind
		kind := (*uint8)(ptr)
		switch *kind {
		case TCP_OPTION_EOL:
			return nil
		case TCP_OPTION_NOP:
			len = len - 1
			ptr = unsafe.Pointer(uintptr(ptr) + uintptr(1))
		case TCP_OPTION_MSS:
			if len < 4 {
				return fmt.Errorf("INVALID_LENGTH_DECODE_TCP_OPTION_MSS")
			}
			data := (*pktreader.BEUint16)(unsafe.Pointer(uintptr(ptr) + uintptr(2)))
			t.MSS = data.Read()
			len = len - 4
			ptr = unsafe.Pointer(uintptr(ptr) + uintptr(4))
		case TCP_OPTION_WSOPT:
			if len < 3 {
				return fmt.Errorf("INVALID_LENGTH_DECODE_TCP_OPTION_WSOPT")
			}
			t.WinScale = *(*uint8)(unsafe.Pointer(uintptr(ptr) + uintptr(2)))
			len = len - 3
			ptr = unsafe.Pointer(uintptr(ptr) + uintptr(3))
		case TCP_OPTION_SACK_PERMIT:
			if len < 2 {
				return fmt.Errorf("INVALID_LENGTH_DECODE_TCP_OPTION_SACK_PERMIT")
			}
			t.SACK = true
			len = len - 2
			ptr = unsafe.Pointer(uintptr(ptr) + uintptr(2))
		case TCP_OPTION_SACK:
			if len < 2 {
				return fmt.Errorf("INVALID_LENGTH_DECODE_TCP_OPTION_SACK")
			}
			optLen := *(*uint8)(unsafe.Pointer(uintptr(ptr) + uintptr(1)))
			len = len - uint(optLen)
			ptr = unsafe.Pointer(uintptr(ptr) + uintptr(optLen))
		case TCP_OPTION_TSOPT:
			if len < 2 {
				return fmt.Errorf("INVALID_LENGTH_DECODE_TCP_OPTION_TIMESTAMP")
			}
			optLen := *(*uint8)(unsafe.Pointer(uintptr(ptr) + uintptr(1)))
			len = len - uint(optLen)
			ptr = unsafe.Pointer(uintptr(ptr) + uintptr(optLen))
		default:
			if len < 2 {
				return fmt.Errorf("INVALID_LENGTH_DECODE_TCP_OPTION_TIMESTAMP")
			}
			optLen := *(*uint8)(unsafe.Pointer(uintptr(ptr) + uintptr(1)))
			len = len - uint(optLen)
			ptr = unsafe.Pointer(uintptr(ptr) + uintptr(optLen))
		}
	}

}
