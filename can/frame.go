// @@
// @ Author       : Eacher
// @ Date         : 2023-09-06 10:48:53
// @ LastEditTime : 2023-09-06 10:49:07
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
	FrameLength	= 0x10
	// SocketCAN frame 数据最大 bytes 长度
	DataLength	= 0x08

	FlagExtended= 0x80000000
	FlagRemote	= 0x40000000
	MaxExtended	= 0x1FFFFFFF
	MaxStandard	= 0x7FF
)

func NewFrame(b [FrameLength]byte) (f Frame) {
	f = *(*Frame)(unsafe.Pointer(&b[0]))
	f.Extended = f.id & FlagExtended > 0
	f.Remote = f.id & FlagRemote > 0
	return
}

// 来源 https://www.kernel.org/doc/Documentation/networking/can.txt
// 
// The basic CAN frame structure and the sockaddr structure are defined
// in include/linux/can.h:

//   struct can_frame {
//           canid_t can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
//           __u8    can_dlc; /* frame payload length in byte (0 .. 8) */
//           __u8    __pad;   /* padding */
//           __u8    __res0;  /* reserved / padding */
//           __u8    __res1;  /* reserved / padding */
//           __u8    data[8] __attribute__((aligned(8)));
//   };
type Frame struct {
	id			uint32
	DLC			uint8
	Pad			uint8
	Res0		uint8
	Res1		uint8
	Data		[DataLength]byte
	Extended	bool
	Remote		bool
}

func (f *Frame) SetID(id uint32) error {
	if id > MaxExtended {
		return fmt.Errorf("invalid extended Can id: %v does not fit in 29 bits", id)
	}
	f.id = id
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
	if f.id & FlagExtended > 0 {
		return f.id & MaxExtended
	}
	return f.id & MaxStandard
}

func (f Frame) WireFormat() []byte {
	var b [FrameLength]byte
	*(*uint32)(unsafe.Pointer(&b[0])) = f.id
	b[4], b[5], b[6], b[7] = f.DLC, f.Pad, f.Res0, f.Res1
	*(*[DataLength]byte)(b[8:]) = f.Data
	return b[:]
}

func (f Frame) String() string {
	format := "%d\t%-4x\t[%x]\t% -24X\t%s\t%d\t%d\t%d\n"
	return fmt.Sprintf(format, f.id, f.ID(), f.DLC, f.Data[:f.DLC], f.Data[:f.DLC], f.Pad, f.Res0, f.Res1)
}
