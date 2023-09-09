// @@
// @ Author       : Eacher
// @ Date         : 2023-09-06 10:48:53
// @ LastEditTime : 2023-09-09 13:50:30
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /20yyq/packet/can/frame.go
// @@
package can

import (
	"fmt"
	"unsafe"
)

const (
	// SocketCAN frame 最大 bytes 长度
	CanFrameLength	= 0x10
	// SocketCAN frame 数据最大 bytes 长度
	CanDataLength	= 0x08
	// SocketCANFD frame 最大 bytes 长度
	CanFDFrameLength= 0x48
	// SocketCANFD frame 数据最大 bytes 长度
	CanFDDataLength	= 0x40

	FlagExtended= 0x80000000
	FlagRemote	= 0x40000000
	FlagError	= 0x20000000
	MaxExtended	= 0x1FFFFFFF
	MaxStandard	= 0x7FF
)

func NewCanFrame(b [CanFrameLength]byte) (f Frame) {
	f = *(*Frame)(unsafe.Pointer(&b[0]))
	f.initAttr()
	return
}

func NewCanFDFrame(b [CanFDFrameLength]byte) (f Frame) {
	f = *(*Frame)(unsafe.Pointer(&b[0]))
	f.CanFd = true
	f.initAttr()
	return
}

// 来源 https://www.kernel.org/doc/Documentation/networking/can.txt
// 
// The struct canfd_frame is defined in include/linux/can.h:

// struct canfd_frame {
//         canid_t can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
//         __u8    len;     /* frame payload length in byte (0 .. 64) */
//         __u8    flags;   /* additional flags for CAN FD */
//         __u8    __res0;  /* reserved / padding */
//         __u8    __res1;  /* reserved / padding */
//         __u8    data[64] __attribute__((aligned(8)));
// };
type Frame struct {
	id			uint32
	Len			uint8
	Flags		uint8
	Res0		uint8
	Res1		uint8
	Data		[CanFDDataLength]byte
	
	CanFd		bool
	Extended	bool
	Remote		bool
	Error		bool
}

func (f *Frame) initAttr() {
	f.Extended = f.id & FlagExtended > 0
	f.Error = f.id & FlagError > 0
	f.Remote = f.id & FlagRemote > 0
}

func (f *Frame) SetID(id uint32) error {
	if id > MaxExtended {
		return fmt.Errorf("invalid extended Can id: %v does not fit in 29 bits", id)
	}
	f.id = id
	if f.Error {
		f.id |= FlagError
	}
	if f.Remote {
		f.id |= FlagRemote
	}
	if f.Extended {
		f.id |= FlagExtended
	} else if f.id > MaxStandard {
		return fmt.Errorf("invalid standard Can id: %v does not fit in 11 bits", id)
	}
	return nil
}

func (f Frame) ID() uint32 {
	if f.id & FlagExtended > 0 || f.id & FlagRemote > 0 || f.id & FlagError > 0 {
		return f.id & MaxExtended
	}
	return f.id & MaxStandard
}

func (f Frame) WireFormat() []byte {
	var b [CanFDFrameLength]byte
	*(*uint32)(unsafe.Pointer(&b[0])) = f.id
	b[4], b[5], b[6], b[7] = f.Len, f.Flags, f.Res0, f.Res1
	if f.CanFd {
		*(*[CanFDDataLength]byte)(b[8:]) = f.Data
		return b[:]
	}
	*(*[CanDataLength]byte)(b[8:]) = ([CanDataLength]byte)(f.Data[:])
	return b[:CanFrameLength]
}

func (f Frame) String() string {
	format := "%d\t%-4X\t[%d]\t% -24X\t%s\t%d\t%d\t%d\n"
	return fmt.Sprintf(format, f.id, f.ID(), f.Len, f.Data[:f.Len], f.Data[:f.Len], f.Flags, f.Res0, f.Res1)
}
