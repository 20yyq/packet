// @@
// @ Author       : Eacher
// @ Date         : 2023-07-01 15:20:41
// @ LastEditTime : 2023-09-16 11:58:40
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /20yyq/packet/netlink.go
// @@
package packet

import (
	"unsafe"
	"syscall"
)

const (
	SizeofNlMsghdr 	= syscall.SizeofNlMsghdr
	SizeofNlAttr 	= syscall.SizeofNlAttr
	SizeofRtAttr 	= syscall.SizeofRtAttr
	SizeofNlMsgerr 	= syscall.SizeofNlMsgerr
	SizeofIfAddrmsg = syscall.SizeofIfAddrmsg
	SizeofRtMsg 	= syscall.SizeofRtMsg
	SizeofIfInfomsg = syscall.SizeofIfInfomsg
)

type IfInfomsg syscall.IfInfomsg
type IfAddrmsg syscall.IfAddrmsg
type RtMsg syscall.RtMsg
type NlMsghdr syscall.NlMsghdr
type NlMsgerr struct {
	Error int32
	Msg   NlMsghdr
}
type NetlinkMessage struct {
	Header *NlMsghdr
	Data   []byte
}
type RtAttr struct {
	*syscall.RtAttr
	Data   []byte
}
type NlAttr struct {
	*syscall.NlAttr
	Data   []byte
}

//go:linkname nlmAlignOf syscall.nlmAlignOf
func nlmAlignOf(msglen int) int

//go:linkname rtaAlignOf syscall.rtaAlignOf
func rtaAlignOf(attrlen int) int

func NewIfInfomsg(b [SizeofIfInfomsg]byte) (info *IfInfomsg) {
	info = (*IfInfomsg)(unsafe.Pointer(&b[0]))
	return
}

func (info IfInfomsg) WireFormat() []byte {
	var b [SizeofIfInfomsg]byte
	b[0], b[1] = info.Family, info.X__ifi_pad
	*(*uint16)(unsafe.Pointer(&b[2])) = info.Type
	*(*int32)(unsafe.Pointer(&b[4])) = info.Index
	*(*uint32)(unsafe.Pointer(&b[8])) = info.Flags
	*(*uint32)(unsafe.Pointer(&b[12])) = info.Change
	return b[:]
}

func NewIfAddrmsg(b [SizeofIfAddrmsg]byte) (addr *IfAddrmsg) {
	addr = (*IfAddrmsg)(unsafe.Pointer(&b[0]))
	return
}

func (addr IfAddrmsg) WireFormat() []byte {
	var b [SizeofIfAddrmsg]byte
	b[0], b[1], b[2], b[3] = addr.Family, addr.Prefixlen, addr.Flags, addr.Scope
	*(*uint32)(unsafe.Pointer(&b[4])) = addr.Index
	return b[:]
}

func NewRtMsg(b [SizeofRtMsg]byte) (rtmsg *RtMsg) {
	rtmsg = (*RtMsg)(unsafe.Pointer(&b[0]))
	return
}

func (rtmsg RtMsg) WireFormat() []byte {
	var b [SizeofRtMsg]byte
	b[0], b[1], b[2], b[3] = rtmsg.Family, rtmsg.Dst_len, rtmsg.Src_len, rtmsg.Tos
	b[4], b[5], b[6], b[7] = rtmsg.Table, rtmsg.Protocol, rtmsg.Scope, rtmsg.Type
	*(*uint32)(unsafe.Pointer(&b[8])) = rtmsg.Flags
	return b[:]
}

func NewNlMsghdr(b [SizeofNlMsghdr]byte) (hdr *NlMsghdr) {
	hdr = (*NlMsghdr)(unsafe.Pointer(&b[0]))
	return
}

func (hdr NlMsghdr) WireFormat() []byte {
	var b [SizeofNlMsghdr]byte
	hdr.WireFormatToByte(&b)
	return b[:]
}

func (hdr NlMsghdr) WireFormatToByte(b *[SizeofNlMsghdr]byte) {
	*(*uint32)(unsafe.Pointer(&b[0])) = hdr.Len
	*(*uint16)(unsafe.Pointer(&b[4])) = hdr.Type
	*(*uint16)(unsafe.Pointer(&b[6])) = hdr.Flags
	*(*uint32)(unsafe.Pointer(&b[8])) = hdr.Seq
	*(*uint32)(unsafe.Pointer(&b[12])) = hdr.Pid
}

func NewNlMsgerr(b [SizeofNlMsgerr]byte) (nlmsge *NlMsgerr) {
	nlmsge = (*NlMsgerr)(unsafe.Pointer(&b[0]))
	return
}

func (nlmsge NlMsgerr) WireFormat() []byte {
	var b [SizeofNlMsgerr]byte
	*(*int32)(unsafe.Pointer(&b[0])) = nlmsge.Error
	nlmsge.Msg.WireFormatToByte((*[SizeofNlMsghdr]byte)(b[4:]))
	return b[:]
}

func NewNetlinkMessage(b []byte) (nlmsg []*NetlinkMessage) {
	for len(b) >= SizeofNlMsghdr {
		m := &NetlinkMessage{Header: NewNlMsghdr(([SizeofNlMsghdr]byte)(b))}
		l := nlmAlignOf(int(m.Header.Len))
		if m.Header.Len < SizeofNlMsghdr || l > len(b) {
			break
		}
		if int(m.Header.Len - SizeofNlMsghdr) < len(b) {
			m.Data = b[SizeofNlMsghdr:m.Header.Len-SizeofNlMsghdr]
		} else {
			m.Data = b[SizeofNlMsghdr:]
		}
		b = b[l:]
		nlmsg = append(nlmsg, m)
	}
	return
}

func (nlmsg NetlinkMessage) WireFormat() []byte {
	b := make([]byte, SizeofNlMsghdr + len(nlmsg.Data))
	copy(b, nlmsg.Header.WireFormat())
	copy(b[SizeofNlMsghdr:], nlmsg.Data)
	return b
}

// ParseNetlinkRouteAttr parses m's payload as an array of netlink
// route attributes and returns the slice containing the
// NetlinkRouteAttr structures.
func ParseNetlinkRouteAttr(m *NetlinkMessage) ([]*RtAttr, error) {
	var b []byte
	switch m.Header.Type {
	case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
		b = m.Data[SizeofIfInfomsg:]
	case syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
		b = m.Data[SizeofIfAddrmsg:]
	case syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE:
		b = m.Data[SizeofRtMsg:]
	default:
		return nil, syscall.EINVAL
	}
	return NewRtAttrs(b)
}

func NewRtAttrs(b []byte) ([]*RtAttr, error) {
	var attrs []*RtAttr
	for len(b) >= SizeofRtAttr {
		r := (*syscall.RtAttr)(unsafe.Pointer(&b[0]))
		if int(r.Len) < SizeofRtAttr || int(r.Len) > len(b) {
			return nil, syscall.EINVAL
		}
		attrs = append(attrs, &RtAttr{RtAttr: r, Data: b[SizeofRtAttr:r.Len]})
		b = b[rtaAlignOf(int(r.Len)):]
	}
	return attrs, nil
}

func (rta RtAttr) WireFormat() []byte {
	b := make([]byte, SizeofRtAttr + len(rta.Data))
	*(*uint16)(unsafe.Pointer(&b[0])) = rta.Len
	*(*uint16)(unsafe.Pointer(&b[2])) = rta.Type
	copy(b[SizeofRtAttr:], rta.Data)
	return b
}

func NewNlAttrs(b []byte) ([]*NlAttr, error) {
	var attrs []*NlAttr
	for len(b) >= SizeofNlAttr {
		nl := (*syscall.NlAttr)(unsafe.Pointer(&b[0]))
		if int(nl.Len) < SizeofNlAttr || int(nl.Len) > len(b) {
			return nil, syscall.EINVAL
		}
		attrs = append(attrs, &NlAttr{NlAttr: nl, Data: b[SizeofNlAttr:nl.Len]})
		b = b[rtaAlignOf(int(nl.Len)):]
	}
	return attrs, nil
}

func (nla NlAttr) WireFormat() []byte {
	b := make([]byte, SizeofNlAttr + len(nla.Data))
	*(*uint16)(unsafe.Pointer(&b[0])) = nla.Len
	*(*uint16)(unsafe.Pointer(&b[2])) = nla.Type
	copy(b[SizeofNlAttr:], nla.Data)
	return b
}
