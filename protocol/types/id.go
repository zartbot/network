package types

const (
	PROTOCOL_ETHERNET_L2 uint8 = 3
	PROTOCOL_IPV4        uint8 = 4
	PROTOCOL_IPV6        uint8 = 6
)

const (
	PROTOCOL_ICMP   uint8 = 0x01
	PROTOCOL_TCP    uint8 = 0x06
	PROTOCOL_UDP    uint8 = 0x11
	PROTOCOL_GRE    uint8 = 0x2f
	PROTOCOL_ICMPv6 uint8 = 0x3a
)

type TCP_FLAGS uint8

const (
	TCPFlagFin = 0x01
	TCPFlagSyn = 0x02
	TCPFlagRst = 0x04
	TCPFlagPsh = 0x08
	TCPFlagAck = 0x10
	TCPFlagUrg = 0x20
	TCPFlagEce = 0x40
	TCPFlagCwr = 0x80
)
