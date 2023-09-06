// @@
// @ Author       : Eacher
// @ Date         : 2023-07-01 15:20:41
// @ LastEditTime : 2023-09-04 09:40:28
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

func NewIfInfomsg(b [SizeofIfInfomsg]byte) (info *IfInfomsg) {
	info = (*IfInfomsg)(unsafe.Pointer(&b[0]))
	return
}

func (info *IfInfomsg) WireFormat() []byte {
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

func (addr *IfAddrmsg) WireFormat() []byte {
	var b [SizeofIfAddrmsg]byte
	b[0], b[1], b[2], b[3] = addr.Family, addr.Prefixlen, addr.Flags, addr.Scope
	*(*uint32)(unsafe.Pointer(&b[4])) = addr.Index
	return b[:]
}

func NewRtMsg(b [SizeofRtMsg]byte) (rtmsg *RtMsg) {
	rtmsg = (*RtMsg)(unsafe.Pointer(&b[0]))
	return
}

func (rtmsg *RtMsg) WireFormat() []byte {
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

func (hdr *NlMsghdr) WireFormat() []byte {
	var b [SizeofNlMsghdr]byte
	hdr.WireFormatToByte(&b)
	return b[:]
}

func (hdr *NlMsghdr) WireFormatToByte(b *[SizeofNlMsghdr]byte) {
	*(*uint32)(unsafe.Pointer(&b[0])) = hdr.Len
	*(*uint16)(unsafe.Pointer(&b[4])) = hdr.Type
	*(*uint16)(unsafe.Pointer(&b[6])) = hdr.Flags
	*(*uint32)(unsafe.Pointer(&b[8])) = hdr.Seq
	*(*uint32)(unsafe.Pointer(&b[12])) = hdr.Pid
}

func NewNlMsgerr(b [SizeofNlMsgerr]byte) (nlmsg *NlMsgerr) {
	nlmsg = (*NlMsgerr)(unsafe.Pointer(&b[0]))
	return
}

func (nlmsg *NlMsgerr) WireFormat() []byte {
	var b [SizeofNlMsgerr]byte
	*(*int32)(unsafe.Pointer(&b[0])) = nlmsg.Error
	nlmsg.Msg.WireFormatToByte((*[SizeofNlMsghdr]byte)(b[4:]))
	return b[:]
}
