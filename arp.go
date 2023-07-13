// @@
// @ Author       : Eacher
// @ Date         : 2023-07-01 15:19:37
// @ LastEditTime : 2023-07-13 15:16:04
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /packet/arp.go
// @@
package packet

import (
	"unsafe"
	"encoding/binary"
)

/*
	Also define the following values (to be discussed later):
	ares_hrd$Ethernet 	(= 1),
    ares_op$REQUEST 	(= 1, high byte transmitted first)
    ares_op$REPLY   	(= 2).
 */
const (
	ARP_ETHERNETTYPE= 0x01
	ARP_REQUEST 	= 0x01
	ARP_REPLY 		= 0x02

	SizeofArpPacket = 0x1c
)

/*
    Ethernet transmission layer (not necessarily accessible to the user):
    // 14.byte  EthernetPacket 
	2.byte  16.bit: (ar$hrd) Hardware address space (e.g., Ethernet, Packet Radio Net.)
	2.byte  16.bit: (ar$pro) Protocol address space.  For Ethernet hardware, this is from the set of type fields ether_typ$<protocol>.
	1.byte   8.bit: (ar$hln) byte length of each hardware address
	1.byte   8.bit: (ar$pln) byte length of each protocol address
	2.byte  16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
	        nbytes: (ar$sha) Hardware address of sender of this packet, n from the ar$hln field.
	        mbytes: (ar$spa) Protocol address of sender of this packet, m from the ar$pln field.
	        nbytes: (ar$tha) Hardware address of target of this packet (if known).
	        mbytes: (ar$tpa) Protocol address of target.

 */
type ArpPacket struct {
	HardwareType 	uint16
	ProtocolType 	uint16
	HardwareLen  	uint8
	IPLen 		 	uint8
	Operation 	 	uint16
	SendHardware 	HardwareAddr
	SendIP 			IPv4
	TargetHardware 	HardwareAddr
	TargetIP 		IPv4
}

func NewArpPacket(b [SizeofArpPacket]byte) (arp *ArpPacket) {
	arp = (*ArpPacket)(unsafe.Pointer(&b[0]))
	arp.HardwareType 	= binary.BigEndian.Uint16(b[0:2])
	arp.ProtocolType 	= binary.BigEndian.Uint16(b[2:4])
	arp.Operation 		= binary.BigEndian.Uint16(b[6:8])
	return
}

func (arp *ArpPacket) WireFormat() []byte {
	var b [SizeofArpPacket]byte
	binary.BigEndian.PutUint16(b[:2], arp.HardwareType)
	binary.BigEndian.PutUint16(b[2:4], arp.ProtocolType)
	b[4], b[5] = arp.HardwareLen, arp.IPLen
	binary.BigEndian.PutUint16(b[6:8], arp.Operation)
	*(*HardwareAddr)(b[8:14]) = arp.SendHardware
	*(*IPv4)(b[14:18]) = arp.SendIP
	*(*HardwareAddr)(b[18:24]) = arp.TargetHardware
	*(*IPv4)(b[24:28]) = arp.TargetIP
	return b[:]
}

func (arp *ArpPacket) String() string {
	str := "OP: request"
	if 1 != arp.Operation {
		str = "OP: replay" 
	}
	str += " Src-MAC: " + arp.SendHardware.String() + " Src-IP: " + arp.SendIP.String()
	str += " Dst-MAC: " + arp.TargetHardware.String() + " Dst-IP: " + arp.TargetIP.String()
	return str
}
