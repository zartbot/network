package pktreader

import (
	"net"
)

func BigEndianUint16(b [2]byte) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[1]) | uint16(b[0])<<8
}

func BigEndianUint32(b [4]byte) uint32 {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

func BigEndianUint64(b [8]byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

func LittleEndianUint16(b [2]byte) uint16 {
	_ = b[0] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[0]) | uint16(b[1])<<8
}

func LittleEndianUint32(b [4]byte) uint32 {
	_ = b[0] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func LittleEndianUint64(b [8]byte) uint64 {
	_ = b[0] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

//BEUint16 is a struct for BigEndian Uint16
type BEUint16 [2]byte

//Read is used convert to uint16
func (b *BEUint16) Read() uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[1]) | uint16(b[0])<<8
}

//BEUint32 is a struct for BigEndian Uint32
type BEUint32 [4]byte

//Read is used convert to uint32
func (b *BEUint32) Read() uint32 {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

//BEUint64 is a struct for BigEndian Uint64
type BEUint64 [8]byte

//Read is used convert to uint64
func (b *BEUint64) Read() uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

//MACAddress is a struct for 6 bytes
type MACAddress [6]byte

//Read is used convert to net.HardwareAddr
func (m *MACAddress) Read() net.HardwareAddr {
	return net.HardwareAddr([]byte{m[0], m[1], m[2], m[3], m[4], m[5]})
}

//IPv4Address is a struct for 4 bytes
type IPv4Address [4]byte

//Read is used convert to net.IP
func (ip *IPv4Address) Read() net.IP {
	b := []byte{ip[0], ip[1], ip[2], ip[3]}
	return net.IP(b)
}

//Uint32 is used convert to net.IP
func (ip *IPv4Address) Uint32() uint32 {
	_ = ip[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(ip[3]) | uint32(ip[2])<<8 | uint32(ip[1])<<16 | uint32(ip[0])<<24
}

//IPv6Address is a struct for 16 bytes
type IPv6Address [16]byte

//Read is used convert to net.IP
func (ip *IPv6Address) Read() net.IP {
	b := []byte{ip[0], ip[1], ip[2], ip[3],
		ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11],
		ip[12], ip[13], ip[14], ip[15]}
	return net.IP(b)
}

//SwapUint16 is used to...
func SwapUint16(x uint16) uint16 {
	return x<<8 | x>>8
}
