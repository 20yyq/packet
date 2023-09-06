// @@
// @ Author       : Eacher
// @ Date         : 2023-07-13 16:56:05
// @ LastEditTime : 2023-09-04 09:40:16
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /20yyq/packet/udp.go
// @@
package packet

import (
	"encoding/binary"
)

const (
	SizeofDUPPacket = 0x08
)

type DUPPacket struct {
	SrcPort 	uint16
	DstPort 	uint16
	Len  		uint16
	CheckSum 	uint16
}

// 14.byte  EthernetPacket
// 20.byte  IPv4Packet 或者 IPv6Packet
func NewDUPPacket(b [SizeofDUPPacket]byte) (udp DUPPacket) {
	udp = DUPPacket{}
	udp.SrcPort 	= binary.BigEndian.Uint16(b[:2])
	udp.DstPort 	= binary.BigEndian.Uint16(b[2:4])
	udp.Len 		= binary.BigEndian.Uint16(b[4:6])
	udp.CheckSum 	= binary.BigEndian.Uint16(b[6:8])
	return
}

func (udp DUPPacket) WireFormat() []byte {
	var b [SizeofDUPPacket]byte
	binary.BigEndian.PutUint16(b[:2], udp.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], udp.DstPort)
	binary.BigEndian.PutUint16(b[4:6], udp.Len)
	binary.BigEndian.PutUint16(b[6:8], udp.CheckSum)
	return b[:]
}
