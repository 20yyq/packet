// @@
// @ Author       : Eacher
// @ Date         : 2023-09-15 15:48:53
// @ LastEditTime : 2023-09-15 15:50:09
// @ LastEditors  : Eacher
// @ --------------------------------------------------------------------------------<
// @ Description  : 
// @ --------------------------------------------------------------------------------<
// @ FilePath     : /20yyq/packet/interface.go
// @@
package packet

type Attrs interface {
	WireFormat() []byte
}
