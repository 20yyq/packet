// @@
// @ Author       : Eacher
// @ Date         : 2023-07-01 15:20:41
// @ LastEditTime : 2023-07-01 16:01:44
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /packet/netlink.go
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
	b[0], b[1] = byte(info.Family), byte(info.X__ifi_pad)
	*(*uint16)(unsafe.Pointer(&b[2:4][0])) = info.Type
	*(*int32)(unsafe.Pointer(&b[4:8][0])) = info.Index
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = info.Flags
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = info.Change
	return b[:]
}

func NewIfAddrmsg(b [SizeofIfAddrmsg]byte) (addr *IfAddrmsg) {
	addr = (*IfAddrmsg)(unsafe.Pointer(&b[0]))
	return
}

func (addr *IfAddrmsg) WireFormat() []byte {
	var b [SizeofIfAddrmsg]byte
	b[0], b[1], b[2], b[3] = byte(addr.Family), byte(addr.Prefixlen), byte(addr.Flags), byte(addr.Scope)
	*(*uint32)(unsafe.Pointer(&b[4:8][0])) = addr.Index
	return b[:]
}

func NewRtMsg(b [SizeofRtMsg]byte) (rtmsg *RtMsg) {
	rtmsg = (*RtMsg)(unsafe.Pointer(&b[0]))
	return
}

func (rtmsg *RtMsg) WireFormat() []byte {
	var b [SizeofRtMsg]byte
	b[0], b[1], b[2], b[3] = byte(rtmsg.Family), byte(rtmsg.Dst_len), byte(rtmsg.Src_len), byte(rtmsg.Tos)
	b[4], b[5], b[6], b[7] = byte(rtmsg.Table), byte(rtmsg.Protocol), byte(rtmsg.Scope), byte(rtmsg.Type)
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rtmsg.Flags
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
	*(*uint32)(unsafe.Pointer(&(*b)[0:4][0])) = hdr.Len
	*(*uint16)(unsafe.Pointer(&(*b)[4:6][0])) = hdr.Type
	*(*uint16)(unsafe.Pointer(&(*b)[6:8][0])) = hdr.Flags
	*(*uint32)(unsafe.Pointer(&(*b)[8:12][0])) = hdr.Seq
	*(*uint32)(unsafe.Pointer(&(*b)[12:16][0])) = hdr.Pid
}

func NewNlMsgerr(b [SizeofNlMsgerr]byte) (nlmsg *NlMsgerr) {
	nlmsg = (*NlMsgerr)(unsafe.Pointer(&b[0]))
	return
}

func (nlmsg *NlMsgerr) WireFormat() []byte {
	var b [SizeofNlMsgerr]byte
	*(*int32)(unsafe.Pointer(&b[0:4][0])) = nlmsg.Error
	nlmsg.Msg.WireFormatToByte((*[SizeofNlMsghdr]byte)(b[4:]))
	return b[:]
}
