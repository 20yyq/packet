// @@
// @ Author       : Eacher
// @ Date         : 2023-07-13 14:02:39
// @ LastEditTime : 2023-09-15 10:32:23
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /20yyq/packet/ethernet.go
// @@
package packet

import (
	_ "net"
	"unsafe"
	"encoding/binary"
)

const (
	SizeofEthernetPacket = 0x0e
)

type HardwareAddr [6]byte 
type IPv4 [4]byte 

const hexDigit = "0123456789abcdef"
const maxIPv4StringLen = len("255.255.255.255")

var Broadcast = HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

/*

 //来源 https://www.rfc-editor.org/rfc/rfc1071 [Page 6]

	4.1  "C"

in 6 {
	// Compute Internet Checksum for "count" bytes
	// beginning at location "addr".
	//
	register long sum = 0;

	while( count > 1 )  {
		// This is the inner loop
		sum += * (unsigned short) addr++;
		count -= 2;
	}
	// Add left-over byte, if any
	if( count > 0 )
		sum += * (unsigned char *) addr;

	// Fold 32-bit sum to 16 bits
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	checksum = ~sum;
}
*/

func CheckSum(b []byte) uint16 {
    l, i, sum := len(b) - 1, 0, uint64(0)
    for ; i < l; i += 2 {
        sum += uint64(*(*uint16)(unsafe.Pointer(&b[i])))
    }
    if i == l {
        sum += uint64(b[i])
    }
    for sum >> 16 > 0 {
        sum = (sum & 0b1111111111111111) + (sum >> 16)
    }
    return uint16(^sum)
}

//go:linkname ubtoa net.ubtoa
func ubtoa([]byte, int, byte) int

func (h HardwareAddr) String() string {
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

func (v4 IPv4) String() string {
	if len(v4) == 0 {
		return ""
	}
	b := make([]byte, maxIPv4StringLen)

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

/*
    Ethernet transmission layer (not necessarily accessible to the user):
	6.byte  48.bit: Ethernet address of destination
	6.byte  48.bit: Ethernet address of sender
	2.byte  16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION Ethernet packet data:
	// N.byte packet
 */
type EthernetPacket struct {
	HeadMAC 	[2]HardwareAddr
	FrameType 	uint16
}

func NewEthernetPacket(b [SizeofEthernetPacket]byte) (eth EthernetPacket) {
	eth = *(*EthernetPacket)(unsafe.Pointer(&b[0]))
	eth.FrameType = binary.BigEndian.Uint16(b[12:14])
	return
}

func (eth EthernetPacket) WireFormat() []byte {
	var b [SizeofEthernetPacket]byte
	*(*HardwareAddr)(b[0:6]) = eth.HeadMAC[0]
	*(*HardwareAddr)(b[6:12]) = eth.HeadMAC[1]
	binary.BigEndian.PutUint16(b[12:14], eth.FrameType)
	return b[:]
}
