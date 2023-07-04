// @@
// @ Author       : Eacher
// @ Date         : 2023-07-01 15:19:37
// @ LastEditTime : 2023-07-04 09:11:59
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /packet/arp.go
// @@
package packet

import (
	"net"
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

	SizeofArpPacket = 0x2a
)

type HardwareAddr [6]byte 
type IPv4 [4]byte 

const hexDigit = "0123456789abcdef"

/*
    Ethernet transmission layer (not necessarily accessible to the user):
	6.byte  48.bit: Ethernet address of destination
	6.byte  48.bit: Ethernet address of sender
	2.byte  16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION Ethernet packet data:
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
	HeadMAC 	 	[2]HardwareAddr
	FrameType 	 	uint16
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

var Broadcast = HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func (h *HardwareAddr) String() string {
	if len(h) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(h)*3-1)
	for i, b := range h {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return string(buf)
}

//go:linkname ubtoa net.ubtoa
func ubtoa([]byte, int, byte) int

func (v4 *IPv4) String() string {
	if len(v4) == 0 {
		return ""
	}
	b := make([]byte, len("255.255.255.255"))

	n := ubtoa(b, 0, v4[0])
	b[n] = '.'
	n++

	n += ubtoa(b, n, v4[1])
	b[n] = '.'
	n++

	n += ubtoa(b, n, v4[2])
	b[n] = '.'
	n++

	n += ubtoa(b, n, v4[3])
	return string(b[:n])
}

func NewArpPacket(b [SizeofArpPacket]byte) (arp *ArpPacket) {
	arp = (*ArpPacket)(unsafe.Pointer(&b[0]))
	arp.FrameType 	 = binary.BigEndian.Uint16(b[12:14])
	arp.HardwareType = binary.BigEndian.Uint16(b[14:16])
	arp.ProtocolType = binary.BigEndian.Uint16(b[16:18])
	arp.Operation 	 = binary.BigEndian.Uint16(b[20:22])
	return
}

func (arp *ArpPacket) WireFormat() []byte {
	var b [SizeofArpPacket]byte
	*(*HardwareAddr)(b[0:6]) = arp.HeadMAC[0]
	*(*HardwareAddr)(b[6:12]) = arp.HeadMAC[1]

	*(*[2]byte)(b[12:14]) = ([2]byte)(binary.BigEndian.AppendUint16(nil, arp.FrameType))
	*(*[2]byte)(b[14:16]) = ([2]byte)(binary.BigEndian.AppendUint16(nil, arp.HardwareType))
	*(*[2]byte)(b[16:18]) = ([2]byte)(binary.BigEndian.AppendUint16(nil, arp.ProtocolType))
	b[18], b[19] = arp.HardwareLen, arp.IPLen
	*(*[2]byte)(b[20:22]) = ([2]byte)(binary.BigEndian.AppendUint16(nil, arp.Operation))
	*(*HardwareAddr)(b[22:28]) = arp.SendHardware
	*(*IPv4)(b[28:32]) = arp.SendIP
	*(*HardwareAddr)(b[32:38]) = arp.TargetHardware
	*(*IPv4)(b[38:42]) = arp.TargetIP
	return b[:]
}

func (arp *ArpPacket) String() string {
	str := "OP: request"
	if 1 != arp.Operation {
		str = "OP: replay" 
	}
	buf := make([]byte, 0, len(arp.SendHardware)*3-1)
	for i, b := range arp.SendHardware {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	str += " Src-MAC: " + string(buf) + " Src-IP: " + net.IP(arp.SendIP[:]).String()
	buf = make([]byte, 0, len(arp.TargetHardware)*3-1)
	for i, b := range arp.TargetHardware {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	str += " Dst-MAC: " + string(buf) + " Dst-IP: " + net.IP(arp.TargetIP[:]).String()
	return str
}
