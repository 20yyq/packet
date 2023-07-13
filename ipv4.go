// @@
// @ Author       : Eacher
// @ Date         : 2023-07-13 15:20:40
// @ LastEditTime : 2023-07-13 15:57:04
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /packet/ipv4.go
// @@
package packet

import (
	"fmt"
	"unsafe"
	"runtime"
	"encoding/binary"
)

const (
	SizeofIPv4Packet = 0x14
)

// NativeEndian is the machine native endian implementation of ByteOrder.
var ipv4NativeEndian binary.ByteOrder

func init() {
	b := [4]byte{}
	*(*uint32)(unsafe.Pointer(&b[0])) = 1
	ipv4NativeEndian = binary.LittleEndian
	if b[0] != 1 {
		ipv4NativeEndian = binary.BigEndian
	}
}

/*

// 14.byte  EthernetPacket 

3.1.  Internet Header Format
	A summary of the contents of the internet header follows:
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

                    Example Internet Datagram Header

                               Figure 4.

  Note that each tick mark represents one bit position.

  Version:  		4 bits
  IHL:  			4 bits
  Type of Service:  8 bits
  		its 0-2:  Precedence.
  		Bit    3:  0 = Normal Delay,      1 = Low Delay.
  		Bits   4:  0 = Normal Throughput, 1 = High Throughput.
  		Bits   5:  0 = Normal Relibility, 1 = High Relibility.
  		Bit  6-7:  Reserved for Future Use.

  Total Length:  	16 bits
  Identification:  	16 bits
  Flags:  			3 bits
  Fragment Offset:  13 bits
  Time to Live:  	8 bits
  Protocol:  		8 bits
  Header Checksum:  16 bits
  Source Address:  	32 bits
  Destination Address:  32 bits
 */
type IPv4Packet struct {
	Version  uint8
	TOS      uint8
	TotalLen uint16
	ID       uint16
	FragOff  uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	Src      IPv4
	Dst      IPv4

	Flags    uint8
	IHL      uint8
	Options  []byte
}

func NewIPv4Packet(b []byte) (ipv4 *IPv4Packet) {
	if len(b) < SizeofIPv4Packet {
		return
	}
	ipv4 = (*IPv4Packet)(unsafe.Pointer((*[SizeofIPv4Packet]byte)(b)))
	ipv4.IHL = (ipv4.Version & 0b00001111) << 2
	ipv4.Version >>= 4
	if ipv4.Version != 4 || len(b[SizeofIPv4Packet:]) < int(ipv4.IHL - SizeofIPv4Packet) {
		ipv4 = nil
		return
	}
	ipv4.TotalLen 	= binary.BigEndian.Uint16(b[2:4])
	ipv4.ID 		= binary.BigEndian.Uint16(b[4:6])
	ipv4.FragOff 	= binary.BigEndian.Uint16(b[6:8])
	ipv4.Checksum 	= binary.BigEndian.Uint16(b[10:12])
	switch runtime.GOOS {
	case "darwin", "ios", "dragonfly", "netbsd":
		ipv4.TotalLen 	= ipv4NativeEndian.Uint16(b[2:4]) + uint16(ipv4.IHL)
		ipv4.FragOff 	= ipv4NativeEndian.Uint16(b[6:8])
	}
	ipv4.Flags 		= uint8((ipv4.FragOff & 0b1110000000000000) >> 13)
	ipv4.FragOff  	= ipv4.FragOff & 0b0001111111111111
	ipv4.Options 	= make([]byte, ipv4.IHL - SizeofIPv4Packet)
	copy(ipv4.Options, b[SizeofIPv4Packet: SizeofIPv4Packet + ipv4.IHL])
	return
}

func (ipv4 *IPv4Packet) WireFormat() []byte {
	b := make([]byte, SizeofIPv4Packet + len(ipv4.Options))
	b[0] = byte(ipv4.Version << 4 | uint8(((SizeofIPv4Packet + len(ipv4.Options)) >> 2 & 0b00001111)))
	b[1], b[8], b[9] = ipv4.TOS, ipv4.TTL, ipv4.Protocol
	binary.BigEndian.PutUint16(b[2:4], ipv4.TotalLen)
	binary.BigEndian.PutUint16(b[4:6], ipv4.ID)
	binary.BigEndian.PutUint16(b[6:8], (ipv4.FragOff & 0b0001111111111111) | uint16(ipv4.Flags << 13))
	binary.BigEndian.PutUint16(b[10:12], ipv4.Checksum)
	switch runtime.GOOS {
	case "darwin", "ios", "dragonfly", "netbsd":
		ipv4NativeEndian.PutUint16(b[2:4], ipv4.TotalLen)
		ipv4NativeEndian.PutUint16(b[6:8], (ipv4.FragOff & 0b0001111111111111) | uint16(ipv4.Flags << 13))
	}
	*(*IPv4)(b[12:16]) = ipv4.Src
	*(*IPv4)(b[16:20]) = ipv4.Dst
	if len(ipv4.Options) > 0 {
		copy(b[SizeofIPv4Packet:], ipv4.Options)
	}
	return b
}

func (ipv4 *IPv4Packet) String() string {
	str := fmt.Sprintf(
		`V=%d IHL=%d TOS=%#x TotalLen=%d ID=%#x Flags=%#x FragOff=%#x TTL=%d Protocol=%d Checksum=%#x Src=%v Dst=%v`, 
		ipv4.Version, ipv4.IHL, ipv4.TOS, ipv4.TotalLen, ipv4.ID, ipv4.Flags, 
		ipv4.FragOff, ipv4.TTL, ipv4.Protocol, ipv4.Checksum, ipv4.Src, ipv4.Dst,
	)
	return str
}
