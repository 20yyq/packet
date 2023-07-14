// @@
// @ Author       : Eacher
// @ Date         : 2023-07-04 08:48:44
// @ LastEditTime : 2023-07-14 10:18:56
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /packet/dhcpv4.go
// @@
package packet

import (
	"time"
	"unsafe"
	"encoding/binary"
)

var MagicCookie 		= [4]byte{99, 130, 83, 99}

const (
	DHCP_ServerPort 	= 0x43
	DHCP_ClientPort 	= 0x44

	DHCP_BOOTREQUEST 	= 0x01
	DHCP_BOOTREPLY 		= 0x02
	DHCP_Ethernet_TYPE 	= 0x01
	DHCP_Ethernet_LEN 	= 0x06

	SizeofDhcpV4Packet 	= 0xf0
	SizeofOptionsPacket = 0x02
)

/*
	// 14.byte  EthernetPacket 
	// 20.byte  IPv4Packet 

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
	Options  		[]OptionsPacket
}

type OptionsPacket struct {
	Code 		uint8
	Length 		uint8
	Value 		[]byte
}

// 14.byte  EthernetPacket
// 20.byte  IPv4Packet 或者 IPv6Packet
func NewDhcpV4Packet(b []byte) (dhcp DhcpV4Packet) {
	if len(b) > SizeofDhcpV4Packet {
		back := make([]byte, len(b))
		copy(back, b)
		dhcp = *(*DhcpV4Packet)(unsafe.Pointer((*[SizeofDhcpV4Packet]byte)(back)))
		dhcp.XID = binary.BigEndian.Uint32(back[4:8])
		dhcp.Secs = binary.BigEndian.Uint16(back[8:10])
		dhcp.Flags 	 = binary.BigEndian.Uint16(back[10:12])
		dhcp.Options = NewOptionsPacket(back[SizeofDhcpV4Packet:])
	}
	return
}

func (dhcp DhcpV4Packet) WireFormat() []byte {
	var opb []byte
	if 0 < len(dhcp.Options) {
		for _, val := range dhcp.Options {
			opb = append(opb, val.WireFormat()...)
		}
		b := make([]byte, len(opb) + SizeofDhcpV4Packet + 1)
		copy(b[SizeofDhcpV4Packet:], opb)
		opb, b[len(b) - 1] = b, 255
		b[0], b[1], b[2], b[3] 	= dhcp.Op, dhcp.HardwareType, dhcp.HardwareLen, dhcp.Hops
		binary.BigEndian.PutUint32(b[4:8], dhcp.XID)
		binary.BigEndian.PutUint16(b[8:10], dhcp.Secs)
		binary.BigEndian.PutUint16(b[10:12], dhcp.Flags)
		*(*IPv4)(b[12:16]) 	= dhcp.CIAddr
		*(*IPv4)(b[16:20]) 	= dhcp.YIAddr
		*(*IPv4)(b[20:24]) 	= dhcp.SIAddr
		*(*IPv4)(b[24:28]) 	= dhcp.GIAddr
		*(*[16]byte)(b[28:44]) 	= dhcp.ChHardware
		*(*[64]byte)(b[44:108]) = dhcp.HostName
		*(*[128]byte)(b[108:236]) = dhcp.FileName
		*(*[4]byte)(b[236:240]) 	= MagicCookie
	}
	return opb
}

func NewOptionsPacket(b []byte) (list []OptionsPacket) {
	var idx, next uint8
	if len(b) > SizeofOptionsPacket {
		opp := OptionsPacket{b[idx], b[idx+1], nil}
		idx = 2
		for opp.Code != 255 {
			next = idx + opp.Length
			opp.Value = make([]byte, opp.Length)
			copy(opp.Value, b[idx:next])
			list = append(list, opp)
			opp = OptionsPacket{b[next], b[next+1], nil}
			idx = next + 2
		}
	}
	return
}

func (opp OptionsPacket) WireFormat() []byte {
	b := make([]byte, SizeofOptionsPacket)
	b[0], b[1] = opp.Code, opp.Length
	return append(b, opp.Value...)
}

/*
9.6. DHCP Message Type
	This option is used to convey the type of the DHCP message.  The code
	for this option is 53, and its length is 1.  Legal values for this
	option are:

	       Value   Message Type
	       -----   ------------
	         1     DHCPDISCOVER
	         2     DHCPOFFER
	         3     DHCPREQUEST
	         4     DHCPDECLINE
	         5     DHCPACK
	         6     DHCPNAK
	         7     DHCPRELEASE
	         8     DHCPINFORM
 */
type DHCP_Message_Type uint8

const (
	DHCP_DISCOVER DHCP_Message_Type = iota + 1
	DHCP_OFFER
	DHCP_REQUEST
	DHCP_DECLINE
	DHCP_ACK
	DHCP_NAK
	DHCP_RELEASE
	DHCP_INFORM
)

func SetDHCPMessage(t DHCP_Message_Type) OptionsPacket {
	return OptionsPacket{53, 1, []byte{byte(t)}}
}

/*
9.8. Parameter Request List
	This option is used by a DHCP client to request values for specified
	configuration parameters.  The list of requested parameters is
	specified as n octets, where each octet is a valid DHCP option code
	as defined in this document.

	The client MAY list the options in order of preference.  The DHCP
	server is not required to return the options in the requested order,
	but MUST try to insert the requested options in the order requested
	by the client.

	The code for this option is 55.  Its minimum length is 1.

	Code   Len   Option Codes
	+-----+-----+-----+-----+---
	|  55 |  n  |  c1 |  c2 | ...
	+-----+-----+-----+-----+---
 */
func SetDHCPOptionsRequestList(codes ...uint8) OptionsPacket {
	return OptionsPacket{55, uint8(len(codes)), codes}
}

/*
9.10. Maximum DHCP Message Size
	This option specifies the maximum length DHCP message that it is
	willing to accept.  The length is specified as an unsigned 16-bit
	integer.  A client may use the maximum DHCP message size option in
	DHCPDISCOVER or DHCPREQUEST messages, but should not use the option
	in DHCPDECLINE messages.

	The code for this option is 57, and its length is 2.  The minimum
	legal value is 576 octets.

	Code   Len     Length
	+-----+-----+-----+-----+
	|  57 |  2  |  l1 |  l2 |
	+-----+-----+-----+-----+
 */
func SetDHCPMaximumMessageSize(size uint16) OptionsPacket {
	if size < 576 {
		size = 576
	}
	return OptionsPacket{57, 2, binary.BigEndian.AppendUint16(nil, size)}
}

/*
8.1. Network Information Service Domain Option
	This option specifies the name of the client's NIS [17] domain.  The
	domain is formatted as a character string consisting of characters
	from the NVT ASCII character set.

	The code for this option is 40.  Its minimum length is 1.

	Code   Len      NIS Domain Name
	+-----+-----+-----+-----+-----+-----+---
	|  40 |  n  |  n1 |  n2 |  n3 |  n4 | ...
	+-----+-----+-----+-----+-----+-----+---
8.8. NetBIOS over TCP/IP Scope Option
	The NetBIOS scope option specifies the NetBIOS over TCP/IP scope
	parameter for the client as specified in RFC 1001/1002. See [19],
	[20], and [8] for character-set restrictions.

	The code for this option is 47.  The minimum length of this option is
	1.

	Code   Len       NetBIOS Scope
	+-----+-----+-----+-----+-----+-----+----
	|  47 |  n  |  s1 |  s2 |  s3 |  s4 | ...
	+-----+-----+-----+-----+-----+-----+----
8.11. Network Information Service+ Domain Option
	This option specifies the name of the client's NIS+ [17] domain.  The
	domain is formatted as a character string consisting of characters
	from the NVT ASCII character set.

	The code for this option is 64.  Its minimum length is 1.

	Code   Len      NIS Client Domain Name
	+-----+-----+-----+-----+-----+-----+---
	|  64 |  n  |  n1 |  n2 |  n3 |  n4 | ...
	+-----+-----+-----+-----+-----+-----+---
9.4 TFTP server name
	This option is used to identify a TFTP server when the 'sname' field
	in the DHCP header has been used for DHCP options.

	The code for this option is 66, and its minimum length is 1.

	Code  Len   TFTP server
	+-----+-----+-----+-----+-----+---
	| 66  |  n  |  c1 |  c2 |  c3 | ...
	+-----+-----+-----+-----+-----+---
9.5 Bootfile name
	This option is used to identify a bootfile when the 'file' field in
	the DHCP header has been used for DHCP options.

	The code for this option is 67, and its minimum length is 1.

	   Code  Len   Bootfile name
	  +-----+-----+-----+-----+-----+---
	  | 67  |  n  |  c1 |  c2 |  c3 | ...
	  +-----+-----+-----+-----+-----+---
9.9. Message
	This option is used by a DHCP server to provide an error message to a
	DHCP client in a DHCPNAK message in the event of a failure. A client
	may use this option in a DHCPDECLINE message to indicate the why the
	client declined the offered parameters.  The message consists of n
	octets of NVT ASCII text, which the client may display on an
	available output device.

	The code for this option is 56 and its minimum length is 1.

	Code   Len     Text
	+-----+-----+-----+-----+---
	|  56 |  n  |  c1 |  c2 | ...
	+-----+-----+-----+-----+---
9.13. Vendor class identifier
	This option is used by DHCP clients to optionally identify the vendor
	type and configuration of a DHCP client.  The information is a string
	of n octets, interpreted by servers.  Vendors may choose to define
	specific vendor class identifiers to convey particular configuration
	or other identification information about a client.  For example, the
	identifier may encode the client's hardware configuration.  Servers
	not equipped to interpret the class-specific information sent by a
	client MUST ignore it (although it may be reported). Servers that
	respond SHOULD only use option 43 to return the vendor-specific
	information to the client.

	The code for this option is 60, and its minimum length is 1.

	Code   Len   Vendor class Identifier
	+-----+-----+-----+-----+---
	|  60 |  n  |  i1 |  i2 | ...
	+-----+-----+-----+-----+---
 */
type DHCP_STRING_TYPE uint8

const (
	DHCP_Network_Information_Service_Domain DHCP_STRING_TYPE = 40
	DHCP_NetBIOS_Scope DHCP_STRING_TYPE 							= 47
	DHCP_Network_Information_ServiceS_Domain DHCP_STRING_TYPE= 64
	DHCP_TFTP_Server_Name DHCP_STRING_TYPE 						= 66
	DHCP_Bootfile_Name DHCP_STRING_TYPE								= 67
	DHCP_Error_Message DHCP_STRING_TYPE								= 56
	DHCP_Vendor_Class_Identifier DHCP_STRING_TYPE 				= 60
)

func SetDHCPString(t DHCP_STRING_TYPE, s string) OptionsPacket {
	length := len(s) + 1
	if length > 255 {
		return OptionsPacket{}
	}
	s += string([]byte{0})
	return OptionsPacket{uint8(t), uint8(length), []byte(s)}
}

/*
3.3. Subnet Mask
	The subnet mask option specifies the client's subnet mask as per RFC
	950 [5].

	If both the subnet mask and the router option are specified in a DHCP
	reply, the subnet mask option MUST be first.
	The code for the subnet mask option is 1, and its length is 4 octets.

	Code   Len        Subnet Mask
	+-----+-----+-----+-----+-----+-----+
	|  1  |  4  |  m1 |  m2 |  m3 |  m4 |
	+-----+-----+-----+-----+-----+-----+
3.5. Router Option
	The router option specifies a list of IP addresses for routers on the
	client's subnet.  Routers SHOULD be listed in order of preference.

	The code for the router option is 3.  The minimum length for the
	router option is 4 octets, and the length MUST always be a multiple
	of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  3  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
3.6. Time Server Option
	The time server option specifies a list of RFC 868 [6] time servers
	available to the client.  Servers SHOULD be listed in order of
	preference.

	The code for the time server option is 4.  The minimum length for
	this option is 4 octets, and the length MUST always be a multiple of
	4.
	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  4  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
3.7. Name Server Option
	The name server option specifies a list of IEN 116 [7] name servers
	available to the client.  Servers SHOULD be listed in order of
	preference.

	The code for the name server option is 5.  The minimum length for
	this option is 4 octets, and the length MUST always be a multiple of
	4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  5  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
3.8. Domain Name Server Option
	The domain name server option specifies a list of Domain Name System
	(STD 13, RFC 1035 [8]) name servers available to the client.  Servers
	SHOULD be listed in order of preference.

	The code for the domain name server option is 6.  The minimum length
	for this option is 4 octets, and the length MUST always be a multiple
	of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  6  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
3.9. Log Server Option
	The log server option specifies a list of MIT-LCS UDP log servers
	available to the client.  Servers SHOULD be listed in order of
	preference.

	The code for the log server option is 7.  The minimum length for this
	option is 4 octets, and the length MUST always be a multiple of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  7  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
3.10. Cookie Server Option
	The cookie server option specifies a list of RFC 865 [9] cookie
	servers available to the client.  Servers SHOULD be listed in order
	of preference.

	The code for the log server option is 8.  The minimum length for this
	option is 4 octets, and the length MUST always be a multiple of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  8  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
3.11. LPR Server Option
	The LPR server option specifies a list of RFC 1179 [10] line printer
	servers available to the client.  Servers SHOULD be listed in order
	of preference.

	The code for the LPR server option is 9.  The minimum length for this
	option is 4 octets, and the length MUST always be a multiple of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  9  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
3.12. Impress Server Option
	The Impress server option specifies a list of Imagen Impress servers
	available to the client.  Servers SHOULD be listed in order of
	preference.

	The code for the Impress server option is 10.  The minimum length for
	this option is 4 octets, and the length MUST always be a multiple of
	4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  10 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
3.13. Resource Location Server Option
	This option specifies a list of RFC 887 [11] Resource Location
	servers available to the client.  Servers SHOULD be listed in order
	of preference.

	The code for this option is 11.  The minimum length for this option
	is 4 octets, and the length MUST always be a multiple of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  11 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.2. Network Information Servers Option
	This option specifies a list of IP addresses indicating NIS servers
	available to the client.  Servers SHOULD be listed in order of
	preference.

	The code for this option is 41.  Its minimum length is 4, and the
	length MUST be a multiple of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  41 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.3. Network Time Protocol Servers Option
	This option specifies a list of IP addresses indicating NTP [18]
	servers available to the client.  Servers SHOULD be listed in order
	of preference.

	The code for this option is 42.  Its minimum length is 4, and the
	length MUST be a multiple of 4.
	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  42 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.5. NetBIOS over TCP/IP Name Server Option
	The NetBIOS name server (NBNS) option specifies a list of RFC
	1001/1002 [19] [20] NBNS name servers listed in order of preference.

	The code for this option is 44.  The minimum length of the option is
	4 octets, and the length must always be a multiple of 4.

	Code   Len           Address 1              Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----
	|  44 |  n  |  a1 |  a2 |  a3 |  a4 |  b1 |  b2 |  b3 |  b4 | ...
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----
8.6. NetBIOS over TCP/IP Datagram Distribution Server Option
	The NetBIOS datagram distribution server (NBDD) option specifies a
	list of RFC 1001/1002 NBDD servers listed in order of preference. The
	code for this option is 45.  The minimum length of the option is 4
	octets, and the length must always be a multiple of 4.

	Code   Len           Address 1              Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----
	|  45 |  n  |  a1 |  a2 |  a3 |  a4 |  b1 |  b2 |  b3 |  b4 | ...
	+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----
8.9. X Window System Font Server Option
	This option specifies a list of X Window System [21] Font servers
	available to the client. Servers SHOULD be listed in order of
	preference.

	The code for this option is 48.  The minimum length of this option is
	4 octets, and the length MUST be a multiple of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+---
	|  48 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |   ...
	+-----+-----+-----+-----+-----+-----+-----+-----+---
8.10. X Window System Display Manager Option
	This option specifies a list of IP addresses of systems that are
	running the X Window System Display Manager and are available to the
	client.

	Addresses SHOULD be listed in order of preference.
	The code for the this option is 49. The minimum length of this option
	is 4, and the length MUST be a multiple of 4.

	Code   Len         Address 1               Address 2

	+-----+-----+-----+-----+-----+-----+-----+-----+---
	|  49 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |   ...
	+-----+-----+-----+-----+-----+-----+-----+-----+---
8.12. Network Information Service+ Servers Option
	This option specifies a list of IP addresses indicating NIS+ servers
	available to the client.  Servers SHOULD be listed in order of
	preference.

	The code for this option is 65.  Its minimum length is 4, and the
	length MUST be a multiple of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	|  65 |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.13. Mobile IP Home Agent option
	This option specifies a list of IP addresses indicating mobile IP
	home agents available to the client.  Agents SHOULD be listed in
	order of preference.

	The code for this option is 68.  Its minimum length is 0 (indicating
	no home agents are available) and the length MUST be a multiple of 4.
	It is expected that the usual length will be four octets, containing
	a single home agent's address.

	Code Len    Home Agent Addresses (zero or more)
	+-----+-----+-----+-----+-----+-----+--
	| 68  |  n  | a1  | a2  | a3  | a4  | ...
	+-----+-----+-----+-----+-----+-----+--
8.14. Simple Mail Transport Protocol (SMTP) Server Option
	The SMTP server option specifies a list of SMTP servers available to
	the client.  Servers SHOULD be listed in order of preference.

	The code for the SMTP server option is 69.  The minimum length for
	this option is 4 octets, and the length MUST always be a multiple of
	4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	| 69  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.15. Post Office Protocol (POP3) Server Option
	The POP3 server option specifies a list of POP3 available to the
	client.  Servers SHOULD be listed in order of preference.

	The code for the POP3 server option is 70.  The minimum length for
	this option is 4 octets, and the length MUST always be a multiple of
	4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	| 70  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.16. Network News Transport Protocol (NNTP) Server Option
	The NNTP server option specifies a list of NNTP available to the
	client.  Servers SHOULD be listed in order of preference.

	The code for the NNTP server option is 71. The minimum length for
	this option is 4 octets, and the length MUST always be a multiple of
	4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	| 71  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.17. Default World Wide Web (WWW) Server Option
	The WWW server option specifies a list of WWW available to the
	client.  Servers SHOULD be listed in order of preference.

	The code for the WWW server option is 72.  The minimum length for
	this option is 4 octets, and the length MUST always be a multiple of
	4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	| 72  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.18. Default Finger Server Option
	The Finger server option specifies a list of Finger available to the
	client.  Servers SHOULD be listed in order of preference.

	The code for the Finger server option is 73.  The minimum length for
	this option is 4 octets, and the length MUST always be a multiple of
	4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	| 73  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.19. Default Internet Relay Chat (IRC) Server Option
	The IRC server option specifies a list of IRC available to the
	client.  Servers SHOULD be listed in order of preference.

	The code for the IRC server option is 74.  The minimum length for
	this option is 4 octets, and the length MUST always be a multiple of
	4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	| 74  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.20. StreetTalk Server Option
	The StreetTalk server option specifies a list of StreetTalk servers
	available to the client.  Servers SHOULD be listed in order of
	preference.

	The code for the StreetTalk server option is 75.  The minimum length
	for this option is 4 octets, and the length MUST always be a multiple
	of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	| 75  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
8.21. StreetTalk Directory Assistance (STDA) Server Option
	The StreetTalk Directory Assistance (STDA) server option specifies a
	list of STDA servers available to the client.  Servers SHOULD be
	listed in order of preference.

	The code for the StreetTalk Directory Assistance server option is 76.
	The minimum length for this option is 4 octets, and the length MUST
	always be a multiple of 4.

	Code   Len         Address 1               Address 2
	+-----+-----+-----+-----+-----+-----+-----+-----+--
	| 76  |  n  |  a1 |  a2 |  a3 |  a4 |  a1 |  a2 |  ...
	+-----+-----+-----+-----+-----+-----+-----+-----+--
9.1. Requested IP Address
	This option is used in a client request (DHCPDISCOVER) to allow the
	client to request that a particular IP address be assigned.

	The code for this option is 50, and its length is 4.

	Code   Len          Address
	+-----+-----+-----+-----+-----+-----+
	|  50 |  4  |  a1 |  a2 |  a3 |  a4 |
	+-----+-----+-----+-----+-----+-----+
9.7. Server Identifier
	This option is used in DHCPOFFER and DHCPREQUEST messages, and may
	optionally be included in the DHCPACK and DHCPNAK messages.  DHCP
	servers include this option in the DHCPOFFER in order to allow the
	client to distinguish between lease offers.  DHCP clients use the
	contents of the 'server identifier' field as the destination address
	for any DHCP messages unicast to the DHCP server.  DHCP clients also
	indicate which of several lease offers is being accepted by including
	this option in a DHCPREQUEST message.

	The identifier is the IP address of the selected server.

	The code for this option is 54, and its length is 4.

	Code   Len            Address
	+-----+-----+-----+-----+-----+-----+
	|  54 |  4  |  a1 |  a2 |  a3 |  a4 |
	+-----+-----+-----+-----+-----+-----+
 */
type DHCP_IPv4_TYPE uint8

const (
	DHCP_Subnet_Mask DHCP_IPv4_TYPE = iota + 1
	_
	DHCP_Router
	DHCP_Time_Server
	DHCP_Name_Server
	DHCP_Domain_Name_Server
	DHCP_Log_Server
	DHCP_Cookie_Server
	DHCP_LPR_Server
	DHCP_Impress_Server
	DHCP_Resource_Location_Server
)

const (
	DHCP_Information_Servers DHCP_IPv4_TYPE = iota + 41
	DHCP_Protocol_Servers
	_
	DHCP_NetBIOS_Name_Server
	DHCP_NetBIOS_Distribution_Server
	_
	_
	DHCP_Window_System_Server
	DHCP_Window_System_Display_Manager
	DHCP_Requested_IP_Address
	_
	_
	_
	DHCP_Server_Identifier
)

const (
	DHCP_Network_Information_Service_Servers DHCP_IPv4_TYPE = iota + 65
	_
	_
	DHCP_Mobile_IP_Home_Agent
	DHCP_SMTP_Server
	DHCP_POP3_Server
	DHCP_NNTP_Server
	DHCP_WWW_Server
	DHCP_Default_Finger_Server
	DHCP_IRC_Server
	DHCP_StreetTalk_Server
	DHCP_STDA_Server
)

func SetDHCPIPv4(t DHCP_IPv4_TYPE, ip ...IPv4) OptionsPacket {
	length := len(ip)*4
	if length > 255 || length < 1 {
		return OptionsPacket{}
	}
	b := make([]byte, length)
	for i, v := range ip {
		copy(b[i*4:], v[:])
	}
	return OptionsPacket{uint8(t), uint8(length), b}
}

/*
8.7. NetBIOS over TCP/IP Node Type Option
	The NetBIOS node type option allows NetBIOS over TCP/IP clients which
	are configurable to be configured as described in RFC 1001/1002.  The
	value is specified as a single octet which identifies the client type
	as follows:

	Value         Node Type
	-----         ---------
	0x1           B-node
	0x2           P-node
	0x4           M-node
	0x8           H-node
 */
type DHCP_NetBIOS_Node_Type uint8

const (
	DHCP_B_node DHCP_NetBIOS_Node_Type = iota + 1
	DHCP_P_node
	_
	DHCP_M_node
	_
	_
	_
	DHCP_H_node
)

func SetDHCPNetBIOSNodeType(t DHCP_NetBIOS_Node_Type) OptionsPacket {
	return OptionsPacket{46, 1, []byte{byte(t)}}
}

/*
9.2. IP Address Lease Time
	This option is used in a client request (DHCPDISCOVER or DHCPREQUEST)
	to allow the client to request a lease time for the IP address.  In a
	server reply (DHCPOFFER), a DHCP server uses this option to specify
	the lease time it is willing to offer.

	The time is in units of seconds, and is specified as a 32-bit
	unsigned integer.

	The code for this option is 51, and its length is 4.

	Code   Len         Lease Time
	+-----+-----+-----+-----+-----+-----+
	|  51 |  4  |  t1 |  t2 |  t3 |  t4 |
	+-----+-----+-----+-----+-----+-----+
9.11. Renewal (T1) Time Value
	This option specifies the time interval from address assignment until
	the client transitions to the RENEWING state.

	The value is in units of seconds, and is specified as a 32-bit
	unsigned integer.

	The code for this option is 58, and its length is 4.

	Code   Len         T1 Interval
	+-----+-----+-----+-----+-----+-----+
	|  58 |  4  |  t1 |  t2 |  t3 |  t4 |
	+-----+-----+-----+-----+-----+-----+
9.12. Rebinding (T2) Time Value
	This option specifies the time interval from address assignment until
	the client transitions to the REBINDING state.

	The value is in units of seconds, and is specified as a 32-bit
	unsigned integer.

	The code for this option is 59, and its length is 4.

	Code   Len         T2 Interval
	+-----+-----+-----+-----+-----+-----+
	|  59 |  4  |  t1 |  t2 |  t3 |  t4 |
	+-----+-----+-----+-----+-----+-----+
 */
type DHCP_TIME_TYPE uint8

const (
	DHCP_Renewal_Time DHCP_TIME_TYPE = iota + 58
	DHCP_Rebinding_Time
	DHCP_IP_Address_Lease DHCP_TIME_TYPE = 51
)

func SetDHCPTime(t DHCP_TIME_TYPE, d time.Duration) OptionsPacket {
	return OptionsPacket{uint8(t), 4, binary.BigEndian.AppendUint32(nil, uint32(d.Seconds()))}
}
