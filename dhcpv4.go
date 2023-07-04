// @@
// @ Author       : Eacher
// @ Date         : 2023-07-04 08:48:44
// @ LastEditTime : 2023-07-04 09:15:50
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /packet/dhcpv4.go
// @@
package packet

import (
	"unsafe"
	"encoding/binary"
)

var MagicCookie 		= [4]byte{99, 130, 83, 99}

const (
	DHCP_ServerPort 	= 67
	DHCP_ClientPort 	= 68

	SizeofDhcpV4Packet 	= 240
	SizeofOptionsPacket = 2
)

/*
	FIELD   BYTES   DESCRIPTION
	-----   -----   -----------
	op      1       packet op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
	htype   1       hardware address type, see ARP section in "Assigned Numbers" RFC. '1' = 10mb ethernet
	hlen    1       hardware address length (eg '6' for 10mb ethernet).
	hops    1       client sets to zero, optionally used by gateways in cross-gateway booting.
	xid     4       transaction ID, a random number, used to match this boot request with the responses it generates.
	secs    2       filled in by client, seconds elapsed since client started trying to boot.
	--      2       unused
	ciaddr  4       client IP address; filled in by client in bootrequest if known.
	yiaddr  4       'your' (client) IP address; filled by server if client doesn't know its own address (ciaddr was 0).
	siaddr  4       server IP address; returned in bootreply by server.
	giaddr  4       gateway IP address, used in optional cross-gateway booting.
	chaddr  16      client hardware address, filled in by client.
	sname   64      optional server host name, null terminated string.
	file    128     boot file name, null terminated string; 'generic' name or null in bootrequest, fully qualified directory-path name in bootreply.
	vend    64      optional vendor-specific area, e.g. could be hardware type/serial on request, or 'capability' / remote file system handle on reply.  This info may be set aside for use by a third phase bootstrap or kernel.
 */
type DhcpV4Packet struct {
	Op 				uint8
	HardwareType 	uint8
	HardwareLen  	uint8
	Hops 			uint8
	XID 			uint32
	Secs 			uint16
	Flags 			uint16
	CIAddr   		IPv4
	YIAddr   		IPv4
	SIAddr   		IPv4
	GIAddr   		IPv4
	ChHardware 		[16]byte
	HostName 		[64]byte
	FileName 		[128]byte
	cookie   		[4]byte
	Options  		[]*OptionsPacket
}

type OptionsPacket struct {
	Types 		uint8
	Length 		uint8
	Value 		[]byte
}

func NewDhcpV4Packet(b []byte) (dhcp *DhcpV4Packet) {
	if len(b) > SizeofDhcpV4Packet {
		tmp := ([SizeofDhcpV4Packet]byte)(b)
		dhcp = (*DhcpV4Packet)(unsafe.Pointer(&tmp[0]))
		dhcp.XID = binary.BigEndian.Uint32(b[4:8])
		dhcp.Secs = binary.BigEndian.Uint16(b[8:10])
		dhcp.Flags 	 = binary.BigEndian.Uint16(b[10:12])
		dhcp.Options = NewOptionsPacket(b[SizeofDhcpV4Packet:])
	}
	return
}

func (dhcp *DhcpV4Packet) WireFormat() []byte {
	var opb []byte
	if 0 < len(dhcp.Options) {
		for _, val := range dhcp.Options {
			opb = append(opb, val.WireFormat()...)
		}
		opb = append(opb, 255)
		var b [SizeofDhcpV4Packet]byte
		b[0], b[1], b[2], b[3] 	= dhcp.Op, dhcp.HardwareType, dhcp.HardwareLen, dhcp.Hops
		*(*[4]byte)(b[4:8]) 	= ([4]byte)(binary.BigEndian.AppendUint32(nil, dhcp.XID))
		*(*[2]byte)(b[8:10]) 	= ([2]byte)(binary.BigEndian.AppendUint16(nil, dhcp.Secs))
		*(*[2]byte)(b[10:12]) 	= ([2]byte)(binary.BigEndian.AppendUint16(nil, dhcp.Flags))
		*(*IPv4)(b[12:16]) 	= dhcp.CIAddr
		*(*IPv4)(b[16:20]) 	= dhcp.YIAddr
		*(*IPv4)(b[20:24]) 	= dhcp.SIAddr
		*(*IPv4)(b[24:28]) 	= dhcp.GIAddr
		*(*[16]byte)(b[28:44]) 	= dhcp.ChHardware
		*(*[64]byte)(b[44:108]) = dhcp.HostName
		*(*[128]byte)(b[108:236]) = dhcp.FileName
		*(*[4]byte)(b[236:240]) 	= MagicCookie
		opb = append(b[:], opb...)
	}
	return opb
}

func NewOptionsPacket(b []byte) (list []*OptionsPacket) {
	var idx, next uint8
	if len(b) > SizeofOptionsPacket {
		opp := &OptionsPacket{b[idx], b[idx+1], nil}
		idx = 2
		for opp.Types != 255 {
			next = idx + opp.Length
			opp.Value = make([]byte, opp.Length)
			copy(opp.Value, b[idx:next])
			list = append(list, opp)
			opp = &OptionsPacket{b[next], b[next+1], nil}
			idx = next + 2
		}
	}
	return
}

func (opp *OptionsPacket) WireFormat() []byte {
	b := make([]byte, SizeofOptionsPacket)
	b[0], b[1] = opp.Types, opp.Length
	return append(b, opp.Value...)
}
