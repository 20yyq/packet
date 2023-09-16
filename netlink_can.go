// @@
// @ Author       : Eacher
// @ Date         : 2023-09-16 14:21:44
// @ LastEditTime : 2023-09-16 14:50:29
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /20yyq/packet/netlink_can.go
// @@
package packet

import (
	"unsafe"
	"golang.org/x/sys/unix"
)

const (
	SizeofCANBitTiming		= 0x20
	SizeofCANBitTimingConst	= 0x30
	SizeofCANDeviceStats	= 0x18
	SizeofCANCtrlMode		= 0x08
)

type CANBitTiming unix.CANBitTiming
type CANBitTimingConst unix.CANBitTimingConst
type CANDeviceStats unix.CANDeviceStats
type CANClock unix.CANClock
type CANBusErrorCounters unix.CANBusErrorCounters
type CANCtrlMode unix.CANCtrlMode


func NewCANBitTiming(b [SizeofCANBitTiming]byte) *CANBitTiming {
	return (*CANBitTiming)(unsafe.Pointer(&b[0]))
}

func (bitt CANBitTiming) WireFormat() []byte {
	var b [SizeofCANBitTiming]byte
	*(*uint32)(unsafe.Pointer(&b[0]))	= bitt.Bitrate
	*(*uint32)(unsafe.Pointer(&b[4]))	= bitt.Sample_point
	*(*uint32)(unsafe.Pointer(&b[8]))	= bitt.Tq
	*(*uint32)(unsafe.Pointer(&b[12]))	= bitt.Prop_seg
	*(*uint32)(unsafe.Pointer(&b[16]))	= bitt.Phase_seg1
	*(*uint32)(unsafe.Pointer(&b[20]))	= bitt.Phase_seg2
	*(*uint32)(unsafe.Pointer(&b[24]))	= bitt.Sjw
	*(*uint32)(unsafe.Pointer(&b[28]))	= bitt.Brp
	return b[:]
}

func NewCANBitTimingConst(b [SizeofCANBitTimingConst]byte) *CANBitTimingConst {
	return (*CANBitTimingConst)(unsafe.Pointer(&b[0]))
}

func (bitc CANBitTimingConst) WireFormat() []byte {
	var b [SizeofCANBitTimingConst]byte
	*(*[16]uint8)(b[:])					= bitc.Name
	*(*uint32)(unsafe.Pointer(&b[16]))	= bitc.Tseg1_min
	*(*uint32)(unsafe.Pointer(&b[20]))	= bitc.Tseg1_max
	*(*uint32)(unsafe.Pointer(&b[24]))	= bitc.Tseg2_min
	*(*uint32)(unsafe.Pointer(&b[28]))	= bitc.Tseg2_max
	*(*uint32)(unsafe.Pointer(&b[32]))	= bitc.Sjw_max
	*(*uint32)(unsafe.Pointer(&b[36]))	= bitc.Brp_min
	*(*uint32)(unsafe.Pointer(&b[40]))	= bitc.Brp_max
	*(*uint32)(unsafe.Pointer(&b[44]))	= bitc.Brp_inc
	return b[:]
}

func NewCANDeviceStats(b [SizeofCANDeviceStats]byte) *CANDeviceStats {
	return (*CANDeviceStats)(unsafe.Pointer(&b[0]))
}

func (devs CANDeviceStats) WireFormat() []byte {
	var b [SizeofCANDeviceStats]byte
	*(*uint32)(unsafe.Pointer(&b[0]))	= devs.Bus_error
	*(*uint32)(unsafe.Pointer(&b[4]))	= devs.Error_warning
	*(*uint32)(unsafe.Pointer(&b[8]))	= devs.Error_passive
	*(*uint32)(unsafe.Pointer(&b[12]))	= devs.Bus_off
	*(*uint32)(unsafe.Pointer(&b[16]))	= devs.Arbitration_lost
	*(*uint32)(unsafe.Pointer(&b[20]))	= devs.Restarts
	return b[:]
}

func NewCANClock(b [4]byte) *CANClock {
	return (*CANClock)(unsafe.Pointer(&b[0]))
}

func (clock CANClock) WireFormat() []byte {
	var b [4]byte
	*(*uint32)(unsafe.Pointer(&b[0]))	= clock.Freq
	return b[:]
}

func NewCANBusErrorCounters(b [4]byte) *CANBusErrorCounters {
	return (*CANBusErrorCounters)(unsafe.Pointer(&b[0]))
}

func (buse CANBusErrorCounters) WireFormat() []byte {
	var b [4]byte
	*(*uint16)(unsafe.Pointer(&b[0]))	= buse.Txerr
	*(*uint16)(unsafe.Pointer(&b[2]))	= buse.Rxerr
	return b[:]
}

func NewCANCtrlMode(b [SizeofCANCtrlMode]byte) *CANCtrlMode {
	return (*CANCtrlMode)(unsafe.Pointer(&b[0]))
}

func (ctrl CANCtrlMode) WireFormat() []byte {
	var b [SizeofCANCtrlMode]byte
	*(*uint32)(unsafe.Pointer(&b[0]))	= ctrl.Mask
	*(*uint32)(unsafe.Pointer(&b[4]))	= ctrl.Flags
	return b[:]
}
