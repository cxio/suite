// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package inst 脚本基础指令集的实现。
package inst

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cxio/suite/cbase"
	"github.com/cxio/suite/cbase/base58"
	"github.com/cxio/suite/cbase/chash"
	"github.com/cxio/suite/cbase/paddr"
	"github.com/cxio/suite/locale"
	"github.com/cxio/suite/script/ibase"
	"github.com/cxio/suite/script/icode"
	"github.com/cxio/suite/script/inst/expr"
	"github.com/cxio/suite/script/inst/instex"
	"github.com/cxio/suite/script/inst/ipriv"
	"github.com/cxio/suite/script/inst/model"
	"github.com/cxio/suite/script/inst/mox"
	"github.com/cxio/suite/script/instor"
	"github.com/cxio/suite/script/xpool"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

var _T = locale.GetText // 本地化文本获取。

// 执行器引用。
type Actuator = ibase.Actuator

// 指令配置器引用。
type Instx = ibase.Instx

// 调用器引用
type Wrapper = ibase.Wrapper

// 指令信息包引用。
type Insted = instor.Insted

// 公钥类型引用。
type PubKey = ibase.PubKey

// 出错提示信息。
var (
	neverToHere   = ibase.ErrToHere
	inputEmpty    = _T("输入缓存区为空，无法继续")
	errConvInt    = _T("转换到整数时出错")
	errConvByte   = _T("转换到字节时出错")
	errConvRune   = _T("转换到单个字符时出错")
	errConvBigInt = _T("转换到大整数时出错")
	errConvFloat  = _T("转换到浮点数时出错")
	errConvDate   = _T("转换到时间时出错")
	bytesLenFail  = _T("字节长度出错")
	accessError   = _T("执行流抵达不可访问的占位指令")
	errMChkSig    = _T("多重签名的公钥和签名数量不相等")
)

// 基本错误值。
var (
	// 通关检查失败。
	NotPass = errors.New(_T("通关验证没有通过"))

	// 模式取值失败。
	ErrModel = errors.New(_T("目标脚本的模式匹配失败"))
)

/*
 * 基本类型。
 ******************************************************************************
 */

// 布尔类型
type Bool = instor.Bool

// 通用整数
type Int = instor.Int

// 字节类型
type Byte = instor.Byte

// 字符类型
type Rune = instor.Rune

// 通用浮点数
type Float = instor.Float

// 大整数
type BigInt = instor.BigInt

// 文本串
type String = instor.String

// 字节序列
type Bytes = instor.Bytes

// 字符序列
type Runes = instor.Runes

// 时间类型
type Time = instor.Time

// 脚本类型
type Script = instor.Script

// 正则表达式
type RegExp = instor.RegExp

// 数值类型约束
type Number = instor.Number

// 整数类型约束
type Integer = instor.Integer

// 切片成员类型约束
type Itemer = instor.Itemer

// 字典类型。
// 注：与切片类型一起被归类为集合。
type Dict map[string]any

// 退出类型：
// - RETURN	函数内返回，结束函数执行。
// - EXIT	脚本结束（视为验证通过）。
// 说明：
// 与 cease 类似，由内层panic()抛出，但携带数据用于表达返回值。
type Leave struct {
	Kind int // RETURN or EXIT
	Data any // 返回值
}

// 停止类型：
// - _CONTINUE_	EACH{} 内进入下一迭代（结束当前循环）。
// - _BREAK_	退出当前 CASE 或中断 EACH 迭代。
// 说明：
// 该类型的值通过panic()抛出，上级调用者捕获后判断执行相应逻辑。
type cease int

// 停止类型定义
const (
	_CONTINUE_ cease = iota // 默认下一轮
	_BREAK_
)

// 退出类型定义
const (
	RETURN int = iota
	EXIT
)

// 脚本源码片段标识
// 仅针对当前块，包含子块但无法包含父块。
const (
	SOURCE_ALL   = 0  // 全部
	SOURCE_PAST  = -1 // 已执行过（含当前）
	SOURCE_PASTX = -2 // 已执行过（NULL=>当前）
	SOURCE_NEXT  = 1  // 后阶部分
	SOURCE_XALL  = 2  // NULL=>末尾
)

// 环境值提取器配置。
// 用于提取不直接存在于env集合内的值。
var __envGetter = map[int]func(*Actuator) any{
	// 跳转计数
	instor.EnvGotos: func(a *Actuator) any { return a.Gotos() },
	// 嵌入计数
	instor.EnvJumps: func(a *Actuator) any { return a.Jumps() },
	//... 待定
}

// 映射指令集。
// - 键：目标指令索引。
// - 值：目标指令配置对象。
// 适用：
// 由附参直接定义目标指令的扩展类指令，
// 如 FN_X, EX_FN 和具体的某个模块如 MO_RE 等。
type mapInst = map[int]Instx

// 直接扩展类指令清单配置。
// - 键：指令码。
// - 值：映射指令集。
// 注：
// 不含自由扩展类 MO_X、EX_INST 和 EX_PRIV。
var __extenList = map[int]mapInst{
	icode.FN_X:    __fnxSet,
	icode.EX_FN:   __exfnSet,
	icode.MO_RE:   __moSetRE,
	icode.MO_TIME: __moSetTime,
	// ...
}

// 指令配置集。
// 下标位置对应指令的值，该位置存放相应指令的封装器和参数数量定义。
// 注：
// FN_X 及之后为扩展部分，并不在此设置。
var __InstSet [icode.FN_X]Instx

/*
 * 值指令
 * 多字节整数采用变长正整数存储。
 * 其它多字节长度定义采用大端/网络字节序（BigEndian）。
 ******************************************************************************
 */

// 指令：NIL
// 返回：nil
func _NIL(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.Revert()
	return []any{nil}
}

// 指令：TRUE
// 返回：Bool
func _TRUE(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.Revert()
	return []any{true}
}

// 指令：FALSE
// 返回：Bool
func _FALSE(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.Revert()
	return []any{false}
}

// 指令：{}(1-x) 整数指令
// 附参：1-x bytes，即整数值本身。x为变长字节。
// 返回：Int
func _Int(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(Int)}
}

// 指令：{}(1) 字节类型 byte
// 附参：1 byte，单字节值。
// 返回：Byte
func _Byte(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(Byte)}
}

// 指令：{}(4) 字符类型 rune
// 附参：4 byte，单字符值。
// 返回：Rune
func _Rune(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(Rune)}
}

// 指令：{}(4-8) 浮点数
// 附参：4-8 bytes，浮点数值
// 返回：Float
func _Float(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(Float)}
}

// 指令：DATE{}(~) 时间对象
// 附参：不定长度，变长正整数毫秒数。
// 返回：Time
func _DATE(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(Time)}
}

// 指令：{}(1)+N 大整数
// 附参：1 byte，值占用的字节数（长度）
// 返回：一个实例指针。
func _BigInt(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(*BigInt)}
}

// 指令：DATA{}(1-2) 短字节序列
// 附参：1-2 bytes，字节序列长度
// 返回：Bytes
func _DATA(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(Bytes)}
}

// 指令：TEXT{}(1-2) 文本串
// 附参：1-2 bytes，文本串长度
// 返回：String
func _TEXT(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(String)}
}

// 指令：/.../(1) 正则表达式
// 附参：1 byte，表达式长度（<256）
// 返回：一个实例指针。
func _RegExp(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(*RegExp)}
}

// 指令：CODE{}(1) 指令代码序列
// 附参：1 byte，序列长度（<256）
// 返回：*Script
func _CODE(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()
	return []any{data.(*Script)}
}

/*
 * 取值指令
 * 返回值：无。
 ******************************************************************************
 */

// 指令：@ 实参捕获
// 仅需设置一个标志指明返回值去向即可。
// .fromStack确定为假，强制 ~ 指令只能跟随在后。
func _Capture(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.BackTo = ibase.ArgsFlag
	a.FromStack = false
	a.Change()
	return nil
}

// 指令：~ 实参直取
// 可能跟随在 @ 和 $ 之后，标记跟随指令的实参渠道。
func _Bring(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.FromStack = true
	a.Change()
	return nil
}

// 指令：$ 局域存值
// .fromStack确定为假，强制 ~ 指令只能跟随在后。
func _ScopeAdd(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.BackTo = ibase.ScopeFlag
	a.FromStack = false
	a.Change()
	return nil
}

// 指令：$(1) 局域取值
// 附参：1 byte，指示取值下标，int8
// 注：
// 普通状态下取值直接进入实参区。
// 在表达式内时直接返回参与计算。
func _ScopeVal(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	v := a.ScopeItem(aux[0].(int))

	// 表达式内时
	if a.InExpr() {
		return []any{v}
	}
	a.PutArgs(v)
	return nil
}

// 指令：${}(1) 循环域取值
// 附参：1 byte，目标值位置下标 [0-3]。
// 注：
// 同上取值自动进入实参区，但表达式内例外。
func _LoopVal(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	i := aux[0].(int)

	// 表达式内时
	if a.InExpr() {
		return []any{a.LoopItem(i)}
	}
	a.PutArgs(a.LoopItem(i))
	return nil
}

/*
 * 栈操作指令
 ******************************************************************************
 */

// 指令：NOP 无操作
// 返回：无。
// 外部会根据实参数量配置（-1）自动提取实参，
// 因此简单忽略传入的实参即可。
func _NOP(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.Revert()
	return nil
}

// 指令：PUSH 数据入栈
// 返回：无。
func _PUSH(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	if len(vs) > 0 {
		a.StackPush(vs...)
	}
	return nil
}

// 指令：SHIFT(1) 提取栈顶条目
// 附参：1 byte，取栈条目数，uint8
// 返回：多值自动展开。
func _SHIFT(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	return a.StackPops(aux[0].(int))
}

// 指令：CLONE(1) 栈顶项克隆
// 附参：1 byte，栈顶项数，uint8
// 返回：多值自动展开。
func _CLONE(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	return a.StackTops(aux[0].(int))
}

// 指令：POP 弹出栈顶项
// 返回：any
func _POP(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.Revert()
	return []any{a.StackPop()}
}

// 指令：POPS(1) 弹出栈顶多项
// 附参：1 byte，弹出条目数，uint8，0表示全部。
// 返回：[]any
func _POPS(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	n := aux[0].(int)

	if n == 0 {
		n = a.StackSize()
	}
	return []any{a.StackPops(n)}
}

// 指令：TOP 引用栈顶项
// 返回：any
func _TOP(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.Revert()
	return []any{a.StackTop()}
}

// 指令：TOPS(1) 引用栈顶多项
// 附参：1 byte，引用条目数，uint8
// 返回：[]any
func _TOPS(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	n := aux[0].(int)

	if n == 0 {
		return []any{} // 空集
	}
	return []any{a.StackTops(n)}
}

// 指令：PEEK 引用栈内任意条目
// 实参：目标条目下标，支持负数从栈顶倒算。
// 返回：any
func _PEEK(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	i := vs[0].(Int) // 错误即失败

	return []any{a.StackItem(int(i))}
}

// 指令：PEEKS(1) 引用栈内任意位置段条目
// 附参：1 byte，引用条目数，uint8
// 实参：起始位置下标，支持负数从栈顶算起。
// 返回：[]any
// 下标位置超出边界或数量超出实际存在都视为异常（失败）。
// 注记：
// 位置实参不计在内。实际上该值已经由上级调用者取出（如果实参区为空）。
func _PEEKS(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	n := aux[0].(int)
	i := vs[0].(Int)

	return []any{a.StackItems(int(i), n)}
}

/*
 * 集合指令
 * 集合包含两种类型：切片 和 字典。
 * 这里只提供集合的一些基础性操作，更多的功能在其各自所属的模块内。
 ******************************************************************************
 * 注记：
 * 这里仅支持会由脚本指令产生的切片类型：
 * - Bytes    由值指令直接创建。
 * - Runes    逻辑上必要，也由本指令和转换指令RUNES创建。
 * - []any    由数据栈部分操作指令（POPS、TOPS、PEEKS）等创建。
 * - []Int    由 RANGE 指令创建。
 * - []Float  由 RANGE 指令创建。
 * - []String 由正则匹配指令 MATCH 创建。
 * 其它值类型的切片不会产生，因此不作支持。
 */

// 指令： SLICE 局部切片
// 实参1：目标切片。
// 实参2：起始下标，支持负数从末尾算起。
// 实参3：结束下标（不含），同上支持负数。nil值表示末尾之后。
// 返回： 一个新切片。
func _SLICE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	i := int(vs[1].(Int))

	switch x := vs[0].(type) {
	case Bytes:
		return []any{slice(x, i, vs[2])}
	case Runes:
		return []any{slice(x, i, vs[2])}
	case []any:
		return []any{slice(x, i, vs[2])}
	case []Int:
		return []any{slice(x, i, vs[2])}
	case []Float:
		return []any{slice(x, i, vs[2])}
	case []String:
		return []any{slice(x, i, vs[2])}
	}
	panic(neverToHere)
}

// 指令：REVERSE 序列反转
// 实参：目标切片。
// 返回：一个新的反转后的切片。
// 提示：
// 如果需要反转字符串，应当先将字符串转为 Runes 后反转，
// 然后再转回字符串。
func _REVERSE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Bytes:
		return []any{reverse(x)}
	case Runes:
		return []any{reverse(x)}
	case []any:
		return []any{reverse(x)}
	case []Int:
		return []any{reverse(x)}
	case []Float:
		return []any{reverse(x)}
	case []String:
		return []any{reverse(x)}
	}
	panic(neverToHere)
}

// 指令：MERGE 分片合并
// 实参：1+不定数量子切片，首个实参必须存在。
// 返回：一个新的合并后的切片。
// 注意：各切片的成员类型应当相同。
func _MERGE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch vs[0].(type) {
	case Bytes:
		return []any{merge[byte](vs)}
	case Runes:
		return []any{merge[rune](vs)}
	case []any:
		return []any{merge[any](vs)}
	case []Int:
		return []any{merge[Int](vs)}
	case []Float:
		return []any{merge[Float](vs)}
	case []String:
		return []any{merge[String](vs)}
	}
	panic(neverToHere)
}

// 指令：EXPAND 集合扩充
// 实参：1+不定数量的成员值，首个实参为目标切片。
// 返回：一个新的扩充后的切片。
func _EXPAND(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch buf := vs[0].(type) {
	case Bytes:
		return []any{expand(buf, vs[1:])}
	case Runes:
		return []any{expand(buf, vs[1:])}
	case []any:
		return []any{expand(buf, vs[1:])}
	case []Int:
		return []any{expand(buf, vs[1:])}
	case []Float:
		return []any{expand(buf, vs[1:])}
	case []String:
		return []any{expand(buf, vs[1:])}
	}
	panic(neverToHere)
}

// 指令：GLUE 成员粘合
// 切片成员间无缝连接。仅支持 Bytes, Runes, []any, []String 类型。
// 其中 []any 成员支持 byte、rune、Bytes、String。
// 实参：一个切片。
// 返回：一个新的字节序列。
// 注意：
// 不支持 []Int, []Float 切片类型，它们的粘合缺乏直接意义。
// 若确实需要，可以先将它们转为字节序列或字符串，然后再粘合。
func _GLUE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var buf bytes.Buffer

	switch x := vs[0].(type) {
	case Bytes:
		return []any{newCopy(x, 0)}
	case Runes:
		for _, v := range x {
			buf.WriteRune(v)
		}
	case []any:
		glueAny(&buf, x)
	case []String:
		for _, v := range x {
			buf.WriteString(v)
		}
	default:
		panic(neverToHere)
	}
	return []any{buf.Bytes()}
}

// 指令：SPREAD 序列展开
// 实参：一个切片。需明确的切片类型。
// 返回：Any切片自动展开。
func _SPREAD(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Runes:
		return cbase.ToAnys(x)
	case Bytes:
		return cbase.ToAnys(x)
	case []any:
		return x
	case []Int:
		return cbase.ToAnys(x)
	case []Float:
		return cbase.ToAnys(x)
	case []String:
		return cbase.ToAnys(x)
	}
	panic(neverToHere)
}

// 指令：ITEM 成员条目获取
// 实参1：目标集。切片或字典。
// 实参2：下标或键名（Int|String）或其集合。
// 返回：一个值或一个切片。
// 注意：
// 从字典中取值时，条目不存在会取到一个默认零值。
// 切片下标支持负数从末尾算起。
func _ITEM(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch k := vs[1].(type) {
	case Int:
		return []any{sliceItemX(vs[0], int(k))}
	case []Int:
		return []any{sliceItemsX(vs[0], k)}
	case String:
		return []any{vs[0].(Dict)[k]}
	case []String:
		return []any{dictItems(vs[0].(Dict), k)}
	}
	panic(neverToHere)
}

// 指令：SET 设置集合成员
// 实参1：目标字典。
// 实参2：键名或键名集。
// 实参3：成员数据值或值集。
// 返回：原目标引用。
// 注：
// 如果键为一个集合，值集成员需要与之一一对应。
func _SET(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	d := vs[0].(Dict)

	switch kx := vs[1].(type) {
	case String:
		d[kx] = vs[2]
	case []String:
		for i, k := range kx {
			d[k] = sliceItemX(vs[2], i)
		}
	default:
		panic(neverToHere)
	}
	return []any{vs[0]}
}

// 指令：SIZE 获取成员大小
// 实参：目标集。切片或字典。
// 返回：Int
func _SIZE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Bytes:
		return []any{Int(len(x))}
	case Runes:
		return []any{Int(len(x))}
	case []any:
		return []any{Int(len(x))}
	case []Int:
		return []any{Int(len(x))}
	case []Float:
		return []any{Int(len(x))}
	case []String:
		return []any{Int(len(x))}
	case Dict:
		return []any{Int(len(x))}
	}
	panic(neverToHere)
}

// 指令：MAP{}(1) 迭代映射。
// 附参：1 byte，子语句块长度。
// 实参：1+不定数量。首个实参为目标集（切片或字典），后续为私有数据栈初始成员。
// 针对目标集，迭代每一个成员执行子语句块。
// 返回：
// 一个切片。由每次迭代中的返回值构成，但 nil 会被忽略。
// 环境：
// 子语句块被构造为一个私有环境，数据栈和实参区独立出来。
// 各个迭代之间共享这个私有环境。
func _MAP(a *Actuator, _ []any, data any, vs ...any) []any {
	a.Revert()

	code := data.([]byte)
	a2 := a.ScopeNew(code)
	// 数据栈初始条目
	a2.StackPush(vs[1:]...)

	switch x := vs[0].(type) {
	case Bytes:
		return []any{mapSlice(a2, x, code)}
	case Runes:
		return []any{mapSlice(a2, x, code)}
	case []any:
		return []any{mapSlice(a2, x, code)}
	case []Int:
		return []any{mapSlice(a2, x, code)}
	case []Float:
		return []any{mapSlice(a2, x, code)}
	case []String:
		return []any{mapSlice(a2, x, code)}
	case Dict:
		return []any{mapDict(a2, x, code)}
	}
	panic(neverToHere)
}

// 指令：FILTER{}(1) 集合过滤。
// 附参：1 byte，子语句块长度。
// 实参：1+不定数量。首个实参为目标集（切片或字典），后续为私有数据栈初始成员。
// 针对目标集，迭代每一个成员执行子语句块。
// 子语句块中返回 true 的当前条目留下，返回 false 的条目被移除。
// 返回：
// 一个切片或字典，与原数据相同类型。
// 环境：
// 与上面 MAP 指令相同说明。
func _FILTER(a *Actuator, _ []any, data any, vs ...any) []any {
	a.Revert()

	code := data.([]byte)
	a2 := a.ScopeNew(code)
	// 数据栈初始条目
	a2.StackPush(vs[1:]...)

	switch x := vs[0].(type) {
	case Bytes:
		return []any{filterSlice(a2, x, code)}
	case Runes:
		return []any{filterSlice(a2, x, code)}
	case []any:
		return []any{filterSlice(a2, x, code)}
	case []Int:
		return []any{filterSlice(a2, x, code)}
	case []Float:
		return []any{filterSlice(a2, x, code)}
	case []String:
		return []any{filterSlice(a2, x, code)}
	case Dict:
		return []any{filterDict(a2, x, code)}
	}
	panic(neverToHere)
}

/*
 * 交互指令
 ******************************************************************************
 */

// 指令：INPUT(1) 导入缓存区的数据
// 附参：1 byte，读取的条目数，0值表示全部。
// 实参：无。
// 返回：提取的数据，上级自动展开。
// 说明：
// 如果脚本中包含导入缓存数据逻辑，用户就必须预先灌入数据，
// 否则缓存区无数据或数据不足，将视为失败。
func _INPUT(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()

	if a.InputNil() {
		panic(inputEmpty)
	}
	return a.BufinPick(aux[0].(int))
}

// 指令：OUTPUT 导出数据到缓存区
// 实参：不定数量。
// 返回：无。
// 注记：
// 依然为串行逻辑，因为简单地向内存写数据不会阻塞。
func _OUTPUT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	if len(vs) > 0 {
		a.BufoutPush(vs...)
	}
	return nil
}

// 指令：BUFDUMP 导出区数据转出
// 附参：1 byte，序位标识。可随机，但在同一脚本内应唯一。
// 返回：无。
// 转出全部数据（清空），同时传递脚本id、序位标识和脚本副本。
func _BUFDUMP(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	n := aux[0].(int)

	if !a.OutputNil() {
		// 即时取出&构造
		x := ibase.Middler{
			ID:   a.ID,
			N:    n,
			Code: newCopy(a.Source(), 0),
			Data: a.BufoutTake(),
		}
		go func() { a.Ch <- x }()
	}
	return nil
}

// 指令：PRINT 打印消息
// 实参：不定数量。
// 返回：无。
// 实际上就是调用 fmt.Println()，格式默认。
func _PRINT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	if len(vs) > 0 {
		fmt.Println(vs...)
	}
	return nil
}

/*
 * 结果指令
 ******************************************************************************
 */

// 指令：PASS 通关检查通过
// 实参：布尔值，真值通过，假值失败。
// 返回：无。
func _PASS(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	if !vs[0].(Bool) {
		panic(NotPass)
	}
	return nil
}

// 指令：FAIL 通关检查失败
// 实参：布尔值，真值失败，假值通过。
// 返回：无。
func _FAIL(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	if vs[0].(Bool) {
		panic(NotPass)
	}
	return nil
}

// 指令：GOTO(4,4,2) 执行流跳转
// 附参1：区块高度。
// 附参2：交易序位。
// 附参3：脚本偏移。
// 实参：不定数量，作为目标脚本数据栈初始内容。
// 返回：无。
func _GOTO(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	a.IncrGoto()

	h := aux[0].(int)
	n := aux[1].(int)
	i := aux[2].(int)
	code := xpool.Get(h, n, i)
	a2 := a.ScriptNew(cbase.KeyID(h, n, i), code)

	if len(vs) > 0 {
		// 新数据栈初始内容
		a2.StackPush(vs...)
	}
	a2.GotoIn()
	runEmbed(a2)

	return nil
}

// 指令：JUMP(4,4,2) 跳转脚本嵌入
// 附参1：区块高度。
// 附参2：交易序位。
// 附参3：脚本偏移。
// 实参：无。
// 返回：无。
func _JUMP(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	a.IncrJump()

	h := aux[0].(int)
	n := aux[1].(int)
	i := aux[2].(int)
	code := xpool.Get(h, n, i)
	a2 := a.EmbedNew(cbase.KeyID(h, n, i), code)

	a2.JumpIn()
	runEmbed(a2)

	return nil
}

// 指令：EXIT 结束脚本
// 实参：不定数量。
// 返回：即实参，多个实参会打包为一个切片。
func _EXIT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	if len(vs) == 1 {
		panic(Leave{EXIT, vs[0]})
	}
	if len(vs) > 1 {
		panic(Leave{EXIT, vs})
	}
	return nil
}

// 指令：RETURN 返回一个值
// 实参：任意类型，单值。
// 返回：即实参值。
// 仅用于函数类指令块内（MAP 和 FILTER）。
func _RETURN(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	panic(Leave{RETURN, vs[0]})
}

/*
 * 流程指令
 ******************************************************************************
 */

// 指令：IF{}(1) 真值执行块
// 附参：1 byte，子语句块长度，uint8
// 实参：布尔值，执行判断依据
// 返回：无。
func _IF(a *Actuator, _ []any, code any, vs ...any) []any {
	a.Revert()
	*a.Ifs = vs[0].(Bool)

	if *a.Ifs {
		codeRun(a.BlockNew(code.([]byte)))
	}
	return nil
}

// 指令：ELSE{}(1) IF不满足时执行
// 附参：1 byte，子块长度。
// 实参：无。
// 返回：无。
func _ELSE(a *Actuator, _ []any, code any, _ ...any) []any {
	a.Revert()

	// 需有前置IF赋值。
	if !*a.Ifs {
		codeRun(a.BlockNew(code.([]byte)))
	}
	a.Ifs = nil // 重置

	return nil
}

// 指令：SWITCH{}(~) 分支选择区
// 附参：x bytes，子块长度
// 实参1：标的值，任意可比较类型。
// 实参2：内部 CASE 分支对比值清单（[]any）。
// 返回：无。
func _SWITCH(a *Actuator, _ []any, code any, vs ...any) []any {
	a.Revert()

	a2 := a.SwitchNew(
		code.([]byte),
		vs[0],
		vs[1].([]any),
	)
	// _BREAK_ 无需处理
	// _CONTINUE_ 不适用switch
	execPart(a2)

	return nil
}

// 指令：CASE{}(1) 条件分支
// 附参：1 byte，子语句块长度。
// 实参：无。
// 返回：无。
func _CASE(a *Actuator, _ []any, code any, _ ...any) []any {
	a.Revert()

	if a.CasePass() || a.Fallthrough() {
		// 已消费
		a.CaseThrough(false)
		// 然后 CASE 执行
		codeRun(a.CaseNew(code.([]byte)))
	}
	// 又被下级 fallthrough
	if a.Fallthrough() {
		return nil
	}
	panic(_BREAK_) // 正常结束
}

// 指令：DEFAULT{}(1) 默认分支
// 附参：1 byte, 子语句块长度。
// 实参：无。
// 返回：无。
func _DEFAULT(a *Actuator, _ []any, code any, _ ...any) []any {
	a.Revert()

	codeRun(a.CaseNew(code.([]byte)))
	a.SwitchReset()

	panic(_BREAK_) // 结束
}

// 指令：EACH{}(1) 迭代式循环
// 附参：1 byte，子语句块长度。
// 实参：可迭代集合（切片或字典）
// 返回：无。
func _EACH(a *Actuator, _ []any, data any, vs ...any) []any {
	a.Revert()

	code := data.([]byte)
	a2 := a.LoopNew(code)

	switch x := vs[0].(type) {
	case Bytes:
		sliceEach(a2, x, code)
	case Runes:
		sliceEach(a2, x, code)
	case []any:
		sliceEach(a2, x, code)
	case []Int:
		sliceEach(a2, x, code)
	case []Float:
		sliceEach(a2, x, code)
	case []String:
		sliceEach(a2, x, code)
	case Dict:
		dictEach(a2, x, code)
	default:
		panic(neverToHere)
	}
	return nil
}

// 指令：CONTINUE 跳入下一迭代
// 附参：无。
// 实参：布尔值，单值可选（不定数量）。
// 返回：无。
func _CONTINUE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	n := len(vs)
	if n > 0 {
		// 数量检查（强壮）
		if n != 1 {
			panic(neverToHere)
		}
		if !vs[0].(Bool) {
			return nil
		}
	}
	panic(_CONTINUE_)
}

// 指令：BREAK 退出EACH或SWITCH
// 附参：无。
// 实参：布尔值，单值可选（不定数量）。
// 返回：无。
func _BREAK(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	n := len(vs)
	if n > 0 {
		// 数量检查（强壮）
		if n != 1 {
			panic(neverToHere)
		}
		if !vs[0].(Bool) {
			return nil
		}
	}
	panic(_BREAK_)
}

// 指令：FALLTHROUGH 穿越到下个CASE
// 附参：无。
// 实参：无。
// 返回：无。
func _FALLTHROUGH(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.Revert()
	a.CaseThrough(true)
	return nil
}

// 指令：BLOCK{}(~) 创建子块
// 附参：x byte，子块长度。
// 实参：无。
// 返回：无。
func _BLOCK(a *Actuator, _ []any, code any, _ ...any) []any {
	a.Revert()
	codeRun(a.BlockNew(code.([]byte)))
	return nil
}

/*
 * 转换指令
 ******************************************************************************
 */

// 指令：BOOL 转换为布尔值 Bool
// 实参：
// - 空值：  	nil => false
// - 字符串：	""  => false
// - 整数：  	0   => false
// - 字节：	0   => false
// - 字符：	0   => false
// - 大整数：	0   => false
// - 浮点数：	<= math.SmallestNonzeroFloat64 => false
// 注记：
// 测试字典或切片是否为空，可取 SIZE 后转换。
func _BOOL(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var b bool

	switch x := vs[0].(type) {
	case nil: // false 维持
	case String:
		b = x != ""
	case Int:
		b = x != 0
	case Byte:
		b = x != 0
	case Rune:
		b = x != 0
	case *BigInt:
		b = x.Cmp(big.NewInt(0)) != 0
	case Float:
		b = x > math.SmallestNonzeroFloat64
	default:
		panic(neverToHere)
	}
	return []any{Bool(b)}
}

// 指令：BYTE 转为字节 Byte
// 实参：
// - 布尔值：	true => 1; false => 0
// - 整数：     <256，否则出错
// - 字符：     <256，否则出错
// - 浮点数：   <256 取整转换，否则出错。
// - 空值：     nil => 0
func _BYTE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var b byte

	switch x := vs[0].(type) {
	case nil: // 0
	case Bool:
		if x {
			b = 1
		}
	case Rune:
		b = convToByte(x)
	case Int:
		b = convToByte(x)
	case Float:
		b = convToByte(x)
	default:
		panic(neverToHere)
	}
	return []any{Byte(b)}
}

// 指令：RUNE 转为字符 Rune
// 实参：
// - 空值：     nil => 0
// - 布尔值：	true => 1; false => 0
// - 字节：     直接类型转换
// - 整数：     小于int32最大值时类型转换，否则出错
// - 浮点数：   先取整，同上整数转换规则。
// - 字节序列： 按UTF-8编码解释，仅支持单个字符。
func _RUNE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var r rune
	var n int

	switch x := vs[0].(type) {
	case nil: // 0
	case Bool:
		if x {
			r = 1
		}
	case Byte:
		r = rune(x)
	case Int:
		r = convToRune(x)
	case Float:
		r = convToRune(x)
	case Bytes:
		r, n = utf8.DecodeRune(x)
		if len(x) > n {
			panic(errConvRune)
		}
	default:
		panic(neverToHere)
	}
	return []any{Rune(r)}
}

// 指令：INT 转换为整型 Int
// 实参：
// - 空值：  	nil => 0
// - 布尔值：	true => 1; false => 0
// - 字节值：	简单转换。
// - 字符值：	简单转换。
// - 字符串：	合法前缀的整数字符串表示。
// - 浮点数：	截断小数部分，超过int64上限的大数会抛出异常。
// - 时间对象：	提取Unix时间戳（毫秒数）。
// - 大整数：	值在int64的范围内则转换，否则抛出异常。
// - 字节序列：	按大端序解释，长度需等于 1、2、4、8 的固定值。
func _INT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var i int64
	var err error

	switch x := vs[0].(type) {
	case nil: // 零值保持
	case Bool:
		if x {
			i = 1
		}
	case Byte:
		i = int64(x)
	case Rune:
		i = int64(x)
	case String:
		if i, err = strconv.ParseInt(x, 0, 64); err != nil {
			panic(errConvInt)
		}
	case Float:
		if x > math.MaxInt64 {
			panic(errConvInt)
		}
		i = int64(x)
	case Time:
		i = x.UnixMilli()
	case *BigInt:
		if !x.IsInt64() {
			panic(errConvInt)
		}
		i = x.Int64()
	case Bytes:
		if i, err = convBytesToInt([]byte(x)); err != nil {
			panic(err)
		}
	default:
		panic(neverToHere)
	}
	return []any{Int(i)}
}

// 指令：BIGINT 转换为大整数 BigInt
// 实参：
// - nil:	零值大整数
// - 字符串：   合法的整数字符串表示。
// - 字节序列： 按大端序转换。
// - 布尔值：   true => 1, false => 0
// - 整数：     简单转换，无要求。
// - 字节：     按整数简单转换。
// - 字符：     按整数简单转换。
// - 浮点数：   截断小数部分。
// 注意：
// 返回的大整数是一个指针封装。
func _BIGINT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	bi := new(BigInt)

	switch x := vs[0].(type) {
	case nil: // 零值维持
	case String:
		if _, ok := bi.SetString(x, 0); !ok {
			panic(errConvBigInt)
		}
	case Bytes:
		bi.SetBytes(x)
	case Bool:
		if x {
			bi.SetInt64(1)
		}
		// false => 0
	case Int:
		bi.SetInt64(x)
	case Byte:
		bi.SetInt64(int64(x))
	case Rune:
		bi.SetInt64(int64(x))
	case Float:
		big.NewFloat(x).Int(bi)
	default:
		panic(neverToHere)
	}
	return []any{bi}
}

// 指令：FLOAT 转为浮点数 Float
// 实参：
// - 空值：  	nil => 0.0
// - 布尔值：	true => 1.0; false => 0.0
// - 整数：  	简单的类型转换，无要求
// - 字节：     按整数转换。
// - 字符：     按整数转换。
// - 字符串：	合法的浮点数或科学记数法表示。
func _FLOAT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var f Float
	var err error

	switch x := vs[0].(type) {
	case nil: // 零值维持
	case Bool:
		if x {
			f = 1.0
		}
	case Int:
		f = Float(x)
	case Byte:
		f = Float(x)
	case Rune:
		f = Float(x)
	case String:
		if f, err = strconv.ParseFloat(x, 64); err != nil {
			panic(errConvFloat)
		}
	default:
		panic(neverToHere)
	}
	return []any{f}
}

// 指令：STRING(1) 转为字符串 String
// 附参：1 byte，格式标识，适用数值类型。
// 实参：
// - 空值：	nil => ""
// - 布尔值：	"true" 或 "false"
// - 整数：	按进制格式显示（2~36），strconv逻辑。
// - 大整数：	按进制格式显示（2~62）
// - 浮点数：	按格式标识显示（自动最少位数）
// - 字节：	视为字符值转换。
// - 字符：	视为Unicode码点值转换。
// - 字节序列：	视为UTF-8编码字节序列
// - 字符序列：	自动编码为UIT-8字符串
func _STRING(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	var str string
	f := aux[0].(int)

	switch x := vs[0].(type) {
	case nil: // ""
	case Bool:
		str = strconv.FormatBool(x)
	case Int:
		str = strconv.FormatInt(x, f)
	case Byte:
		str = string(x)
	case Rune:
		str = string(x)
	case *BigInt:
		str = x.Text(f)
	case Float:
		str = strconv.FormatFloat(x, byte(f), -1, 64)
	case Bytes:
		str = string(x)
	case Runes:
		str = string(x)
	default:
		panic(neverToHere)
	}
	return []any{str}
}

// 指令：BYTES 转为字节序列 Bytes
// 实参：
// - 空值：	[] 零长度切片
// - 整数：	按大端序转换，固定8字节长。
// - 大整数：	按大端序转换，长度不定。
// - 字节：	直接转换，只占用1字节。
// - 字符：	按字符的UTF-8编码转换。
// - 字符串：	转换为UTF-8编码的字节序列。
// - 字符序列：	转为UIT-8编码的字节序列。
// - 脚本：	取原始全字节序列（副本）。
func _BYTES(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var bs Bytes

	switch x := vs[0].(type) {
	case nil:
		bs = Bytes{}
	case Int:
		bs = make(Bytes, 8)
		binary.BigEndian.PutUint64(bs, uint64(x))
	case *BigInt:
		bs = x.Bytes()
	case Byte:
		bs = Bytes{x}
	case Rune:
		bs = Bytes(string(x))
	case String:
		bs = Bytes(x)
	case Runes:
		bs = Bytes(string(x))
	case *Script:
		bs = x.New().Source()
	default:
		panic(neverToHere)
	}
	return []any{bs}
}

// 指令：RUNES 转为字符序列 Runes
// 实参：
// - 空值：	一个零长度切片
// - 字符：     包含一个字符的字符切片。
// - 字符串：	视为 UTF-8 编码解码
// - 字节序列：	同上视为 UTF-8 编码解码，无效字符解码为 \uFFFD
func _RUNES(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var rs Runes

	switch x := vs[0].(type) {
	case nil:
		rs = Runes{}
	case Rune:
		rs = Runes{x}
	case String:
		rs = Runes(x)
	case Bytes:
		rs = Runes(string(x))
	default:
		panic(neverToHere)
	}
	return []any{rs}
}

// 指令：TIME 转为时间类型 Time
// 实参：
// - 整数：  UNIX时间戳（毫秒数）。
// - 字符串：仅支持RFC3339时间格式。
// 注记：
// 更多的灵活创建格式在 MO_TIME 中支持。
func _TIME(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var t Time
	var err error

	switch x := vs[0].(type) {
	case Int:
		t = time.UnixMilli(x)
	case String:
		t, err = time.Parse(time.RFC3339, x)
		if err != nil {
			panic(errConvDate)
		}
	default:
		panic(neverToHere)
	}
	return []any{t}
}

// 指令：REGEXP 转为正则表达式 RegExp
// 实参：
// - 字符串：	正则表达式的字符串表示。
func _REGEXP(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{regexp.MustCompile(vs[0].(string))}
}

// 指令：ANYS 切片类型Any转换
// 根据附参标识，在具体类型和 any 之间转换。
// 附参：类型标识。
// 实参：某类型切片。
//   - Bytes => []any
//   - Runes => []any
//   - []Int => []any
//   - []Float => []any
//   - []String => []any
//   - []any => []T 上面5种类型
func _ANYS(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()

	switch aux[0].(int) {
	case instor.ItemAny:
		return []any{convToAnys(vs[0])}
	case instor.ItemByte:
		return []any{anysTo[Byte](vs[0].([]any))}
	case instor.ItemRune:
		return []any{anysTo[Rune](vs[0].([]any))}
	case instor.ItemInt:
		return []any{anysTo[Int](vs[0].([]any))}
	case instor.ItemFloat:
		return []any{anysTo[Float](vs[0].([]any))}
	case instor.ItemString:
		return []any{anysTo[String](vs[0].([]any))}
	}
	panic(neverToHere)
}

// 指令：DICT 创建字典 Dict
// 实参1：键序列（[]string）。
// 实参2：值序列（[]any|[]...）
// 两个序列按相同下标一一对应创建字典。
// 注意：
// 值序列可以比键序列长，多余的成员被忽略，但反之则不行。
// 键序列兼容 []any，但 any 需是字符串。
func _DICT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	v := vs[1].([]any)
	d := make(Dict)

	switch ks := vs[0].(type) {
	case []string:
		for i, k := range ks {
			d[k] = v[i]
		}
	case []any:
		for i, k := range ks {
			d[k.(string)] = v[i]
		}
	default:
		panic(neverToHere)
	}
	return []any{d}
}

/*
 * 运算指令
 * 注：四个运算符指令（* / + -）由expr包处理。
 ******************************************************************************
 */

// 指令：()(1) 表达式封装&优先级分组
// 附参：1 byte，表达式长度。
// 实参：无。
// 返回：Float 类型单值。
// 注：
// 仅支持基本算术的四则运算（乘除加减）。
func _Expr(a *Actuator, _ []any, data any, _ ...any) []any {
	a.Revert()

	a2 := a.ExprNew(data.([]byte))
	a2.ExprIn()

	f := func() (int, []any) {
		return exprNext(a2)
	}
	v := expr.Calculator(f).Calc()
	a2.ExprOut()

	return []any{v}
}

// 指令：* 符号乘
// func _Mul(a *Actuator, _ []any, _ any, _ ...any) []any {}

// 指令：/ 符号除
// func _Div(a *Actuator, _ []any, _ any, _ ...any) []any {}

// 指令：+ 符号正或加
// func _Add(a *Actuator, _ []any, _ any, _ ...any) []any {}

// 指令：- 符号负或减
// func _Sub(a *Actuator, _ []any, _ any, _ ...any) []any {}

// 指令：乘
// 实参：双实参，任意数值。
// 返回：Float，单值
func _MUL(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{number(vs[0]) * number(vs[1])}
}

// 指令：除
// 实参：双实参，任意数值。
// 返回：Float，单值
func _DIV(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{number(vs[0]) / number(vs[1])}
}

// 指令：加&连接
// 实参：双实参。任意数值、字符串、字节序列、字典类型。
// 返回：同类型或Float单值
// 注：
// 支持数值加、字符串和字节序列连接，以及字典的合并。
func _ADD(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case String:
		return []any{x + vs[1].(String)}
	case Bytes:
		return []any{bytesGlue(x, vs[1].(Bytes))}
	case Dict:
		return []any{dictMerge(x, vs[1].(Dict))}
	}
	return []any{number(vs[0]) + number(vs[1])}
}

// 指令：减
// 实参：双实参，任意数值。
// 返回：Float，单值
func _SUB(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{number(vs[0]) - number(vs[1])}
}

// 指令：幂
// 实参：双实参，任意数值。
// 返回：Float，单值
func _POW(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{math.Pow(number(vs[0]), number(vs[1]))}
}

// 指令：模
// 实参：双实参，Int|Float 类型。
// 返回：Int|Float 单值
func _MOD(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	if i, ok := vs[0].(Int); ok {
		return []any{i % vs[1].(Int)}
	}
	if f, ok := vs[0].(Float); ok {
		return []any{math.Mod(f, vs[1].(Float))}
	}
	panic(neverToHere)
}

// 指令：左移位（<<）
// 实参：双实参，Int 类型。
// 返回：Int 单值
// 注意：
// 最多只能向左移动63位，超出int64表示范围视为异常。
func _LMOV(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	n := vs[1].(Int)

	if n > 63 {
		panic(_T("左移位数太多（>63）"))
	}
	return []any{vs[0].(Int) << n}
}

// 指令：右移位（>>）
// 实参：双实参，Int 类型。
// 返回：Int 单值
// 注记：右移位数不予限制，超出左值有效位后得零。
func _RMOV(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{vs[0].(Int) >> vs[1].(Int)}
}

// 指令：位与（&）
// 实参：双实参，Int 类型。
// 返回：Int 单值
func _AND(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{vs[0].(Int) & vs[1].(Int)}
}

// 指令：位清空（&^）
// 实参：双实参，Int 类型。
// 返回：Int 单值
func _ANDX(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{vs[0].(Int) &^ vs[1].(Int)}
}

// 指令：位或（|）
// 实参：双实参，Int 类型。
// 返回：Int 单值
func _OR(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{vs[0].(Int) | vs[1].(Int)}
}

// 指令：位取反、位异或（^）
// 实参：单/双实参（不定），Int 类型。
// 返回：Int 单值
// 注意：
// 这是不定实参指令，用户需将目标实参先取到实参区。
// 单实参时为位取反，双实参时为位异或。
func _XOR(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	if len(vs) == 1 {
		return []any{^vs[0].(Int)}
	}
	return []any{vs[0].(Int) ^ vs[1].(Int)}
}

// 指令：取负（-v）
// 实参：单实参，Int 或 Float 类型。
// 返回：同类型单值
func _NEG(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Int:
		return []any{-x}
	case Float:
		return []any{-x}
	}
	panic(neverToHere)
}

// 指令：取反（!v）
// 实参：单值，Bool 类型。
// 返回：Bool 单值
func _NOT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{!vs[0].(Bool)}
}

// 指令：除并求余
// 实参：双实参
// 返回：商+余数，双 Int 值
// 注：返回值自动展开。
func _DIVMOD(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	x := vs[0].(Int)
	y := vs[1].(Int)

	return []any{x / y, x % y} // 自动展开
}

// 指令：复制
// 附参：1 byte，复制份数，uint8。
// 实参：任意类型值。
// 返回：原值+复制的值，不定数量。
// 注意：
// 只是浅复制（多引用），返回值自动展开。
func _DUP(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()

	n := aux[0].(int)
	buf := make([]any, n)

	for i := 0; i < n; i++ {
		buf[i] = vs[0]
	}
	return buf // 自动展开
}

// 指令：删除
// 实参1：目标字典。
// 实参2：键名或键名序列（兼容 []any，成员需为字符串）。
// 返回：原目标字典。
func _DEL(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	d := vs[0].(Dict)

	switch x := vs[1].(type) {
	case String:
		delete(d, x)
	case []String:
		for _, k := range x {
			delete(d, k)
		}
	case []any:
		for _, k := range x {
			delete(d, k.(String))
		}
	}
	return []any{d}
}

// 指令：清空
// 实参：目标字典
// 返回：原目标
func _CLEAR(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	d := vs[0].(Dict)

	for k := range d {
		delete(d, k)
	}
	return []any{d}
}

/*
 * 比较指令
 * 支持字节序列的比较，逻辑与字符串类似。
 ******************************************************************************
 */

// 指令：相等
// 实参：双实参，可数值比较类型。
// 返回：Bool 值。
// 提示：
// 这里支持浮点数的相等比较，但可能使用后面的 CMPFLO 指令更合适。
func _EQUAL(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{equal(vs[0], vs[1])}
}

// 指令：不相等
// 实参：双实参，可数值比较类型。
// 返回：Bool 值。
func _NEQUAL(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{!equal(vs[0], vs[1])}
}

// 指令：小于
// 实参：双实参，可比较相同类型（数值和字符串，下同）。
// 返回：Bool 值。
func _LT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Int:
		return []any{x < vs[1].(Int)}
	case Float:
		return []any{x < vs[1].(Float)}
	case Byte:
		return []any{x < vs[1].(Byte)}
	case Rune:
		return []any{x < vs[1].(Rune)}
	case String:
		return []any{x < vs[1].(String)}
	case Bytes:
		return []any{bytes.Compare(x, vs[1].(Bytes)) < 0}
	}
	panic(neverToHere)
}

// 指令：小于等于
// 实参：双实参，可比较相同类型。
// 返回：Bool 值。
// 提示：
// 浮点数的该比较有另一个工具指令 CMPFLO。
func _LTE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Int:
		return []any{x <= vs[1].(Int)}
	case Float:
		return []any{x <= vs[1].(Float)}
	case Byte:
		return []any{x <= vs[1].(Byte)}
	case Rune:
		return []any{x <= vs[1].(Rune)}
	case String:
		return []any{x <= vs[1].(String)}
	case Bytes:
		return []any{bytes.Compare(x, vs[1].(Bytes)) <= 0}
	}
	panic(neverToHere)
}

// 指令：大于
// 实参：双实参，可比较相同类型。
// 返回：Bool 值。
func _GT(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Int:
		return []any{x > vs[1].(Int)}
	case Float:
		return []any{x > vs[1].(Float)}
	case Byte:
		return []any{x > vs[1].(Byte)}
	case Rune:
		return []any{x > vs[1].(Rune)}
	case String:
		return []any{x > vs[1].(String)}
	case Bytes:
		return []any{bytes.Compare(x, vs[1].(Bytes)) > 0}
	}
	panic(neverToHere)
}

// 指令：大于等于
// 实参：双实参，可比较相同类型。
// 返回：Bool 值。
func _GTE(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Int:
		return []any{x >= vs[1].(Int)}
	case Float:
		return []any{x >= vs[1].(Float)}
	case Byte:
		return []any{x >= vs[1].(Byte)}
	case Rune:
		return []any{x >= vs[1].(Rune)}
	case String:
		return []any{x >= vs[1].(String)}
	case Bytes:
		return []any{bytes.Compare(x, vs[1].(Bytes)) >= 0}
	}
	panic(neverToHere)
}

// 指令：是否非数字
// 实参：单实参，任意类型。
// 返回：Bool 值。
// 注记：
// 非空字符串视为非数字，即便是数字串，因为这里类型更严格一些。
func _ISNAN(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	_nan := true

	switch x := vs[0].(type) {
	case nil, Bool,
		Byte, Rune, Int, *BigInt,
		Time:
		_nan = false
	case Float:
		_nan = math.IsNaN(x)
	case String:
		_nan = x != ""
	}
	return []any{_nan}
}

// 指令：范围之内判断
// 支持可比较类型（数值、字符串）。
// 实参1：待比较值。
// 实参2：下边界值（包含）。
// 实参2：上边界值（不包含）。
// 返回：Bool 值。
func _WITHIN(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Int:
		return []any{within(x, vs[1].(Int), vs[2].(Int))}
	case Float:
		return []any{within(x, vs[1].(Float), vs[2].(Float))}
	case Byte:
		return []any{within(x, vs[1].(Byte), vs[2].(Byte))}
	case Rune:
		return []any{within(x, vs[1].(Rune), vs[2].(Rune))}
	case String:
		return []any{within(x, vs[1].(String), vs[2].(String))}
	case Bytes:
		return []any{bytes.Compare(vs[1].(Bytes), x) <= 0 && bytes.Compare(x, vs[1].(Bytes)) < 0}
	}
	panic(neverToHere)
}

/*
 * 逻辑指令
 ******************************************************************************
 */

// 指令：两者都为真
// 实参：双实参，Bool类型。
// 返回：Bool 值。
func _BOTH(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{vs[0].(Bool) && vs[1].(Bool)}
}

// 指令：全部都为真
// 实参：一个布尔值集合，兼容 []any，但成员需为布尔值。
// 返回：Bool 值。
// 提示：
// 如果实参为一个空集（类型合法），会返回true。
func _EVERY(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	var v bool

	switch x := vs[0].(type) {
	case []Bool:
		v = every(x, func(b bool) bool { return b })
	case []any:
		v = every(x, func(a any) bool { return a.(bool) })
	default:
		panic(neverToHere)
	}
	return []any{v}
}

// 指令：两者任一真
// 实参：双实参，Bool类型。
// 返回：Bool 值。
func _EITHER(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	return []any{vs[0].(Bool) || vs[1].(Bool)}
}

// 指令：部分为真
// 附参：1 byte，为真的最低数量。
// 实参：一个布尔值集合，兼容 []any（成员为bool）。
// 返回：Bool 值。
// 提示：
// 如果附参值为零（没有最低数量要求），无条件返回true。
// 如果实参为一个空集（且附参值>0），会返回false。
func _SOME(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	n := aux[0].(int)
	var v bool

	switch x := vs[0].(type) {
	case []Bool:
		v = some(x, n, func(b bool) bool { return b })
	case []any:
		v = some(x, n, func(a any) bool { return a.(bool) })
	default:
		panic(neverToHere)
	}
	return []any{v}
}

/*
 * 模式指令
 ******************************************************************************
 */

// 指令：创建模式匹配区
// 附参：2 bytes，包含：
// - [0]: 取值标记（bool）
// - [1]: 模式区代码长度（int）
// 实参：待测试指令序列（*Script | Bytes）。
// 数据：模式代码序列。
// 返回：一个切片或布尔值。
// - 有取值：返回值集，失败抛出异常。
// - 无取值：返回匹配成功与否。
func _MODEL(a *Actuator, aux []any, data any, vs ...any) []any {
	a.Revert()

	s := scriptCode(vs[0])
	m := data.([]byte)

	pick, ok := model.Check(s, m, a.Ver)

	if !aux[0].(bool) {
		return []any{ok}
	}
	if ok {
		return []any{pick}
	}
	panic(ErrModel)
}

// 指令：#(1) 取值指示
// func _ValPick(*Actuator, []any, any, ...any) []any {}
// ...
// 注：由 model 包内部处理。

/*
 * 环境指令
 ******************************************************************************
 */

// 指令：ENV(1){} 环境变量提取
// 附参：1 byte，目标名称标识值。
// 实参：无。
// 返回：目标成员值。
func _ENV(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()

	n := aux[0].(int)
	fn := __envGetter[n]
	if fn == nil {
		// 默认直接取值。
		return []any{a.EnvItem(n)}
	}
	return []any{fn(a)}
}

// 指令：OUT(2,1){} 输出项取值
// 附参1：2 bytes, 输出脚本偏移（起始值0）。
// 附参2：1 byte, 目标成员标识。
// 实参：无。
// 返回：目标成员值。
func _OUT(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	i := aux[0].(int)
	n := aux[1].(int)

	return []any{a.TxOutItem(i, n)}
}

// 指令：IN(1){} 输入项取值
// 附参：1 byte，目标成员标识。
// 实参：无。
// 返回：目标成员值。
func _IN(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	n := aux[0].(int)

	return []any{a.TxInItem(n)}
}

// 指令：INOUT(1){} 输入的源输出项取值
// 附参：1 byte，目标成员标识。
// 实参：无。
// 返回：目标成员值。
func _INOUT(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	n := aux[0].(int)

	return []any{a.TxInOutItem(n)}
}

// 指令：XFROM(1){} 获取源脚本信息
// 附参：1 byte，目标信息标识值。
// 实参：无。
// 返回：任意类型，单值。
func _XFROM(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	return []any{a.XFrom(aux[0].(int))}
}

// 指令：VAR(1) 全局变量取值
// 附参：1 byte，目标变量位置。uint8 类型。
// 实参：无。
// 返回：目标位置的值，任意类型单值。
func _VAR(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	return []any{a.GlobalValue(aux[0].(int))}
}

// 指令：SETVAR(1) 全局变量赋值
// 附参：1 byte，变量位置值
// 实参：任意类型，单值。
// 返回：无。
func _SETVAR(a *Actuator, aux []any, data any, _ ...any) []any {
	a.Revert()
	a.GlobalSet(aux[0].(int), data)
	return nil
}

// 指令：SOURCE 获取当前源脚本字节序列
// 附参：1 byte，片段标识值。
// 实参：无。
// 返回：字节切片。
// 注意：错误的片段标识会抛出异常。
func _SOURCE(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()

	switch aux[0].(int) {
	case SOURCE_PAST:
		return []any{a.Script.Past()}
	case SOURCE_PASTX:
		return []any{a.Script.PastNull()}
	case SOURCE_ALL:
		return []any{a.Script.Source()}
	case SOURCE_NEXT:
		return []any{a.Script.Bytes()}
	case SOURCE_XALL:
		return []any{a.Script.SourceNull()}
	}
	panic(neverToHere)
}

// 指令：MULSIG(1) 多重签名序位确认
// 附参：1 byte，目标序位
// 实参：无。
// 返回：布尔值。
func _MULSIG(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	i := aux[0].(int)
	return []any{a.MulSigN(i)}
}

/*
 * 工具指令
 ******************************************************************************
 */

// 指令：EVAL 子脚本执行
// 附参：无
// 实参：脚本实例（*Script）。
// 返回：私有栈条目集。
func _EVAL(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	s := vs[0].(*Script)

	a2 := a.EvalNew(s.Source())
	runEmbed(a2)

	return []any{a2.StackData()}
}

// 指令：COPY 切片复制
// 附参：无
// 实参：一个切片。
// 返回：一个全新切片。
func _COPY(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Bytes:
		return []any{newCopy(x, 0)}
	case Runes:
		return []any{newCopy(x, 0)}
	case []any:
		return []any{newCopy(x, 0)}
	case []Int:
		return []any{newCopy(x, 0)}
	case []Float:
		return []any{newCopy(x, 0)}
	case []String:
		return []any{newCopy(x, 0)}
	}
	panic(neverToHere)
}

// 指令：DCOPY 切片深度复制
// 附参：无
// 实参：一个切片。
// 返回：一个新的切片。
func _DCOPY(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Bytes:
		return []any{newCopy(x, 0)}
	case Runes:
		return []any{newCopy(x, 0)}
	case []any:
		return []any{deepCopy(x)}
	case []Int:
		return []any{newCopy(x, 0)}
	case []Float:
		return []any{newCopy(x, 0)}
	case []String:
		return []any{newCopy(x, 0)}
	}
	panic(neverToHere)
}

// 指令：KEYVAL(1) 字典键值切分
// 附参：1 byte，取值标识
// - 0	返回两个切片，[0]为键集，[1]为值集。
// - 1	返回键集切片 []string。
// - 2	返回值集切片 []any。
// 实参：目标字典。
// 返回：1-2 个切片。
func _KEYVAL(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	k, v := keyVals(vs[0].(Dict))

	switch aux[0].(int) {
	case 0:
		return []any{k, v}
	case 1:
		return []any{k}
	case 2:
		return []any{v}
	}
	panic(neverToHere)
}

// 指令：MATCH(1) 正则匹配取值
// 附参：1 byte，匹配方式（g|G）。
// 实参1：目标字符串或字节序列。
// 实参2：正则表达式（/.../，*RegExp 类型）。
// 返回：一个单值或集合。
func _MATCH(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	re := vs[1].(*RegExp)

	switch aux[0].(int) {
	case 'g':
		return []any{cbase.MatchAll(vs[0], re)}
	case 'G':
		return []any{cbase.MatchEvery(vs[0], re)}
	}
	all := cbase.Match(vs[0], re)

	if len(all) > 1 {
		return []any{all}
	}
	return []any{all[0]}
}

// 指令：SUBSTR(2) 字串截取
// 附参：2 bytes，字符（rune）数量。
// 实参1：目标字符串。
// 实参2：起始字符位置。按字符计算，从0开始。支持负数从末尾算起。
// 返回：一个子字符串。
func _SUBSTR(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()

	n := aux[0].(int)
	s := vs[0].(String)
	i := int(vs[1].(Int))

	if i < 0 {
		return []any{strSub2(s, i, n)}
	}
	return []any{strSub1(s, i, n)}
}

// 指令：REPLACE 字串替换
// 附参：1 byte， 替换次数（0值表示全部）。
// 实参1：目标字符串。
// 实参2：替换匹配式（子串或正则表达式）。
// 实参3：替换串，可含特殊标识（当匹配式为正则表达式时）。
// 返回：一个新的字符串。
func _REPLACE(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()

	n := aux[0].(int)
	if n == 0 {
		n = -1
	}
	s := vs[0].(String)
	new := vs[2].(String)

	switch x := vs[1].(type) {
	case String:
		return []any{strings.Replace(s, x, new, n)}
	case *RegExp:
		return []any{x.ReplaceAllString(s, new)}
	}
	panic(neverToHere)
}

// 指令：SRAND 切片成员顺序扰乱
// 附参：无。
// 实参：目标切片。
// 返回：一个新切片。
func _SRAND(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Bytes:
		return []any{randSlice(x)}
	case Runes:
		return []any{randSlice(x)}
	case []any:
		return []any{randSlice(x)}
	case []Int:
		return []any{randSlice(x)}
	case []Float:
		return []any{randSlice(x)}
	case []String:
		return []any{randSlice(x)}
	}
	panic(neverToHere)
}

// 指令：RANDOM 获取一个安全随机数
// 附参：无。
// 实参：随机数上限值（不含），Int 或 BigInt 类型。
// 返回：一个随机正整数。
// 注：
// 返回值类型与实参类型相同。
func _RANDOM(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	if len(vs) > 0 {
		switch max := vs[0].(type) {
		case Int:
			return []any{randInt(max)}
		case *BigInt:
			return []any{randBigInt(max)}
		default:
			panic(neverToHere)
		}
	}
	return []any{randInt(math.MaxInt64)}
}

// 指令：QRANDOM 获取一个随机数（快速）
// 附参：无。
// 实参：随机数上限值（不含），Int 类型。
// 返回：一个随机正整数。
func _QRANDOM(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	// 种子：
	// 辅以当前指令偏移值增加随机性。
	t := time.Now().UnixMicro() * int64(a.Script.Offset()+1)
	r := rand.New(rand.NewSource(t))

	if len(vs) == 0 {
		return []any{r.Int63()}
	}
	return []any{r.Int63n(vs[0].(Int))}
}

// 指令：CMPFLO(1) 浮点数比较
// 附参：1 byte，比较类型标识（-1|0|1）。
// 实参1：待比较值，Float。
// 实参2：待比较值，Float。
// 实参3：误差值，两个比较值之间的差值不超过误差时视为相等，Float。
// 返回：布尔值。
func _CMPFLO(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()

	x := vs[0].(Float)
	y := vs[1].(Float)
	d := vs[2].(Float)

	switch aux[0].(int) {
	case -1: // <=
		return []any{x < y || cbase.FloatEqual(x, y, d)}
	case 0: // ==
		return []any{cbase.FloatEqual(x, y, d)}
	case 1: // >=
		return []any{x > y || cbase.FloatEqual(x, y, d)}
	}
	panic(neverToHere)
}

// 指令：RANGE(1) 创建数值序列
// 附参：2 bytes，序列长度（成员数量）。
// 实参1：起始值，整数|浮点数。
// 实参2：步进值，整数|浮点数。
// 返回：一个切片，成员类型与起始值相同。
func _RANGE(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	size := aux[0].(int)

	switch x := vs[0].(type) {
	case Int:
		return []any{rangeSlice(x, vs[1].(Int), size)}
	case Float:
		return []any{rangeSlice(x, vs[1].(Float), size)}
	}
	panic(neverToHere)
}

/*
 * 系统指令
 ******************************************************************************
 */

// 指令：SYS_TIME(1){} 获取全局时间特定属性值
// 附参：1 byte，目标属性标识值。
// 实参：无。
// 返回：目标属性值（Int）或一个Time实例。
func _SYS_TIME(a *Actuator, aux []any, _ any, _ ...any) []any {
	a.Revert()
	t := time.Now()

	switch aux[0].(int) {
	case instor.TimeDefault:
		return []any{t} // Time
	case instor.TimeStamp:
		return []any{t.UnixMilli()}
	case instor.TimeYear:
		return []any{Int(t.Year())}
	case instor.TimeMonth:
		return []any{Int(t.Month())}
	case instor.TimeYearDay:
		return []any{Int(t.YearDay())}
	case instor.TimeDay:
		return []any{Int(t.Day())}
	case instor.TimeWeekDay:
		return []any{Int(t.Weekday())}
	case instor.TimeHour:
		return []any{Int(t.Hour())}
	case instor.TimeMinute:
		return []any{Int(t.Minute())}
	case instor.TimeSecond:
		return []any{Int(t.Second())}
	case instor.TimeMillisecond:
		return []any{Int(t.UnixMilli() % 1000)}
	case instor.TimeMicrosecond:
		return []any{Int(t.UnixMicro() % 1000_000)}
	}
	panic(neverToHere)
}

// 指令：SYS_AWARD 兑奖验算
// 附参：无。
// 实参：区块高度（历史区块）。
// 返回：奖金兑现值。
func _SYS_AWARD(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	h := vs[0].(Int)

	return []any{Int(ibase.CheckAward(int(h)))}
}

// 指令：SYS_NULL 断点标记
// 附参：无。
// 实参：无。
// 返回：无。
func _SYS_NULL(a *Actuator, _ []any, _ any, _ ...any) []any {
	a.Revert()
	a.Script.PostNull()
	return nil
}

/*
 * 函数指令
 * 具体的函数指令只有实参，没有附参和关联数据。
 ******************************************************************************
 */

// Base58 编/解码。
// 实参：字节数据或已编码文本串。
// 返回：编码字符串或解码字节序列。
// 注：
// 编码或解码由实参类型决定。下同。
func _FN_BASE58(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Bytes:
		return []any{base58.Encode(x)}
	case String:
		return []any{base58.Decode(x)}
	}
	panic(neverToHere)
}

// Base32 编/解码。
// 实参：字节数据或已编码文本串。
// 返回：编码字符串或解码字节序列。
// 注：无填充字符格式。
func _FN_BASE32(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)

	switch x := vs[0].(type) {
	case String:
		buf, err := enc.DecodeString(x)
		if err != nil {
			panic(err)
		}
		return []any{buf}
	case Bytes:
		return []any{enc.EncodeToString(x)}
	}
	panic(neverToHere)
}

// Base64 编/解码。
// 实参：字节数据或已编码文本串。
// 返回：编码字符串或解码字节序列。
// 注：
// 无填充字符格式，增补字符URL友好（-_）。
func _FN_BASE64(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	enc := base64.RawURLEncoding

	switch x := vs[0].(type) {
	case String:
		buf, err := enc.DecodeString(x)
		if err != nil {
			panic(err)
		}
		return []any{buf}
	case Bytes:
		return []any{enc.EncodeToString(x)}
	}
	panic(neverToHere)
}

// 构造公钥地址或解码账号地址。
// 对公钥执行特定结构的哈希运算创建公钥地址，或解码文本形式的账户地址到公钥地址。
// 实参：公钥数据或账户地址。
// 返回：公钥地址切片。
// 注：
// 执行构造或解码，视实参类型而定。
func _FN_PUBHASH(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	switch x := vs[0].(type) {
	case Bytes:
		pka := paddr.Hash(x, nil)
		return []any{pka[:]}
	case String:
		pks, _, err := paddr.Decode(x)
		if err != nil {
			panic(err)
		}
		return []any{pks}
	}
	panic(neverToHere)
}

// 构造多重签名总公钥地址。
// 实参1：签名公钥集。
// 实参2：剩余未签名公钥地址（非公钥）集。
// 返回：总公钥地址（前置 n/T 配比）。
func _FN_MPUBHASH(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	h, err := paddr.MulHash(
		bytesSlice(vs[0].([]any)),
		bytesSlice(vs[1].([]any)),
	)
	if err != nil {
		panic(err)
	}
	return []any{h}
}

// 公钥地址编码。
// 实参1：公钥地址字节序列。
// 实参2：标识前缀。
// 返回：编码字符串。
func _FN_ADDRESS(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()
	pkh := vs[0].(Bytes)
	fix := vs[1].(String)

	return []any{paddr.Encode(pkh, fix)}
}

// 单签名验证。
// 附参：1 byte，签名类型标识。
// 实参1：签名。
// 实参2：公钥。
// 返回：布尔值。
// 注：
// 仅仅只是签名验证，不含地址检查。下同。
func _FN_CHECKSIG(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	flg := aux[0].(int)
	pbk := vs[1].(Bytes)
	sig := vs[0].(Bytes)

	return []any{ibase.CheckSig(a.Ver, PubKey(pbk), a.SpentMsg(flg), sig)}
}

// 多签名验证。
// 附参：1 byte，签名类型标识。
// 实参1：签名集。
// 实参2：公钥集。
// 返回：布尔值。
func _FN_MCHECKSIG(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	flg := aux[0].(int)
	pbks := bytesSlice(vs[1].([]any))
	sigs := bytesSlice(vs[0].([]any))

	// 提前检查可节省时间（如果出错）。
	if len(pbks) != len(sigs) {
		panic(errMChkSig)
	}
	ids, pks := ibase.MulPubKeys(pbks)
	// 序位登记
	a.SetMulSig(ids...)

	return []any{ibase.CheckSigs(a.Ver, pks, a.SpentMsg(flg), sigs)}
}

// 计算哈希摘要（224位）。
// 附参：1 byte，哈希算法标识。
// 实参：任意长字节序列。
// 返回：28字节序列，Bytes。
// 算法：sha3|sha2|blake2
func _FN_HASH224(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	var buf [sha256.Size224]byte

	switch aux[0].(int) {
	case instor.HashSHA3:
		buf = sha3.Sum224(vs[0].(Bytes))
	case instor.HashSHA2:
		buf = sha256.Sum224(vs[0].(Bytes))
	case instor.HashBLAKE2:
		return []any{chash.BlakeSum224(vs[0].(Bytes))}
	default:
		panic(neverToHere)
	}
	return []any{buf[:]}
}

// 计算哈希摘要（256位）。
// 附参：1 byte，哈希算法标识。
// 实参：任意长字节序列。
// 返回：32字节序列，Bytes。
// 算法：sha3|sha2|blake2
func _FN_HASH256(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	var buf [sha256.Size]byte

	switch aux[0].(int) {
	case instor.HashSHA3:
		buf = sha3.Sum256(vs[0].(Bytes))
	case instor.HashSHA2:
		buf = sha256.Sum256(vs[0].(Bytes))
	case instor.HashBLAKE2:
		buf = blake2b.Sum256(vs[0].(Bytes))
	default:
		panic(neverToHere)
	}
	return []any{buf[:]}
}

// 计算哈希摘要（384位）。
// 附参：1 byte，哈希算法标识。
// 实参：任意长字节序列。
// 返回：48字节序列，Bytes。
// 算法：sha3|sha2|blake2
func _FN_HASH384(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	var buf [sha512.Size384]byte

	switch aux[0].(int) {
	case instor.HashSHA3:
		buf = sha3.Sum384(vs[0].(Bytes))
	case instor.HashSHA2:
		buf = sha512.Sum384(vs[0].(Bytes))
	case instor.HashBLAKE2:
		buf = blake2b.Sum384(vs[0].(Bytes))
	default:
		panic(neverToHere)
	}
	return []any{buf[:]}
}

// 计算哈希摘要（512位）。
// 附参：1 byte，哈希算法标识。
// 实参：任意长字节序列。
// 返回：64字节序列，Bytes。
// 算法：sha3|sha2|blake2
func _FN_HASH512(a *Actuator, aux []any, _ any, vs ...any) []any {
	a.Revert()
	var buf [sha512.Size]byte

	switch aux[0].(int) {
	case instor.HashSHA3:
		buf = sha3.Sum512(vs[0].(Bytes))
	case instor.HashSHA2:
		buf = sha512.Sum512(vs[0].(Bytes))
	case instor.HashBLAKE2:
		buf = blake2b.Sum512(vs[0].(Bytes))
	default:
		panic(neverToHere)
	}
	return []any{buf[:]}
}

// 格式行打印。
// 实参1：格式字符串。
// 实参n：不定数量，与格式字符串内的标识匹配。
// 返回：无。
func _FN_PRINTF(a *Actuator, _ []any, _ any, vs ...any) []any {
	a.Revert()

	s := vs[0].(String)
	fmt.Printf(s, vs[1:]...)

	return nil
}

// 函数指令扩展。
// 由具体的指令实施功能，不会抵达此处。
// 注记：
// 本指令之后的部分皆为扩展逻辑，由提取函数拦截获取具体的实操指令，
// 故此之后的指令不会实际抵达，从略。
func _FN_X(_ *Actuator, _ []any, _ any, _ ...any) []any {
	panic(accessError)
}

//
// 工具函数
///////////////////////////////////////////////////////////////////////////////

// 获取目标指令配置和信息包。
// 返回值：
// - 封装调用器。
// - 指令参数个数。
// - 指令解析信息包。
// 注记：
// FN_X 和之后的所有指令都属于扩展部分，包括模块区。
func instGet(code []byte, c int) (Wrapper, int, *Insted) {
	if c >= icode.FN_X {
		return instExtens(code, c)
	}
	x := __InstSet[c]

	return x.Call, x.Argn, instor.Get(code)
}

// 获取扩展部分的指令配置和信息包。
// c 为目标扩展指令码。
// 注记：
// MO_X 作为扩展模块指令，存在递进取值逻辑。
// EX_INST 作为通用类型扩展有其自身的逻辑，因此也需要单独处理。
// EX_PRIV 应当作为一个单独的子包处理。
func instExtens(code []byte, c int) (Wrapper, int, *Insted) {
	switch c {
	case icode.MO_X:
		return moduleX(code)
	case icode.EX_INST:
		return extenInst(code)
	case icode.EX_PRIV:
		return privInst(code)
	}
	ins := instor.Get(code)
	// 直接扩展类
	x := __extenList[c][ins.Args[0].(int)]

	return x.Call, x.Argn, ins
}

// 获取扩展模块指令配置&信息包。
func moduleX(code []byte) (Wrapper, int, *Insted) {
	ins := instor.Get(code)

	i := ins.Args[0].(int)
	x := mox.GetInstx(i, ins.Data)

	return x.Call, x.Argn, ins
}

// 获取通用扩展指令配置&信息包。
func extenInst(code []byte) (Wrapper, int, *Insted) {
	ins := instor.Get(code)
	i := ins.Args[0].(int)

	x := instex.GetInstx(i, ins.Data)
	return x.Call, x.Argn, ins
}

// 获取第三方私有扩展指令配置&信息包。
func privInst(code []byte) (Wrapper, int, *Insted) {
	ins := instor.Get(code)
	i := ins.Args[0].(int)

	x := ipriv.GetInstx(i, ins.Data)
	return x.Call, x.Argn, ins
}

// 当前指令调用。
// 会自动递进到下一个指令位置。
func instCall(a *Actuator) []any {
	s := a.Script
	f, n, ins := instGet(s.Bytes(), s.Code())

	// 先步进，避免合理的panic原地踏步。
	s.Next(ins.Size)
	val := f(a, ins.Args, ins.Data, a.Arguments(n)...)

	return val
}

// 表达式步进器。
// 返回当前指令码和该指令调用后的原始返回值。
// 如果抵达脚本末尾，返回 (-1, nil)
// 注：
// 用于构造表达式执行器。
func exprNext(a *Actuator) (int, []any) {
	if a.Script.End() {
		return ibase.ExprEnd, nil
	}
	return a.Script.Code(), instCall(a)
}

// 代码执行（通用）。
// 也用于无需捕获异常的子块代码，如：IF, ELSE, CASE 等，让异常正常向上传递。
// a 为脚本执行器。
func codeRun(a *Actuator) {
	for !a.Script.End() {
		x := a.BackTo
		a.ReturnPut(x, instCall(a))
	}
}

// 执行私有代码。
// 内部的脚本代码是一个独立的子段，拥有相对的私有环境。
// 外部传入的状态集 State 定义了这个子环境。
// clen 为目标域代码片段的长度。
// 适用指令：MAP, FILTER, EVAL
// 注：
// - MAP、FILTER、EVAL 指令内支持 RETURN 返回一个值。
// - 私有域内不支持 EXIT 返回。
// 注记：
// RETURN 和 EXIT 用 panic 方式返回值，因为需要中断脚本执行。
func execScope(a *Actuator) (x any) {
	defer func() {
		switch v := recover().(type) {
		case nil: // normal
		case Leave:
			if v.Kind == RETURN {
				x = v.Data
				break
			}
			panic(neverToHere) // 私有域内禁止 EXIT
		default:
			panic(v)
		}
	}()
	codeRun(a)
	return nil
}

// 执行片段代码。
// 用于处理代码块内的 CONTINUE/BREAK 逻辑，
// 适用指令：SWITCH，EACH
// 属于主体代码的一个部分，a 为上层执行器引用（非独立）。
// 返回值：当前结束类型。
func execPart(a *Actuator) (x cease) {
	defer func() {
		switch v := recover().(type) {
		case nil: // normal
		case cease:
			x = v // _CONTINUE_ or _BREAK_
		case Leave:
			// 主体代码禁止 RETURN
			if v.Kind != EXIT {
				panic(neverToHere)
			}
			// 支持EXIT，延续抛出，由上层退出
			panic(v)
		default:
			panic(v)
		}
	}()
	codeRun(a)
	return
}

// 运行嵌入代码。
// 适用普通的子块代码，包括 GOTO、JUMP 引入的。
// 主要为禁止子级代码内使用 RETURN。
// 返回值：无。
func runEmbed(a *Actuator) {
	defer func() {
		switch v := recover().(type) {
		case nil: // normal
		case Leave:
			// 禁止 RETURN
			if v.Kind != EXIT {
				panic(neverToHere)
			}
			panic(v) // 延续抛出，交由上层退出
		default:
			panic(v)
		}
	}()
	codeRun(a)
}

// 运行顶层代码。
// 返回值：EXIT 的返回值。
func ScriptRun(a *Actuator) (x any) {
	defer func() {
		switch v := recover().(type) {
		case nil: // normal
		case Leave:
			// 主体代码禁止 RETURN
			if v.Kind != EXIT {
				panic(neverToHere)
			}
			x = v.Data // 正常结束
		default:
			panic(v)
		}
	}()
	codeRun(a)
	return
}

//
// 私有辅助
///////////////////////////////////////////////////////////////////////////////

// 将any切片转换到特定类型。
func anysTo[T Itemer](data []any) []T {
	buf := make([]T, len(data))

	for i, v := range data {
		buf[i] = v.(T)
	}
	return buf
}

// 切片循环执行（Map循环）。
func mapSlice[T Itemer](a *Actuator, data []T, code []byte) []any {
	var buf []any
	size := len(data)

	for k, v := range data {
		// 每次一个新小环境
		a2 := a.BlockNew(code)
		a2.LoopSet(k, v, data, size)

		x := execScope(a2)
		// 排除 nil 值（忽略）
		if x != nil {
			buf = append(buf, x)
		}
	}
	return buf
}

// 字典循环执行（Map循环）。
// 注：与上面 mapSlice() 内容代码相同。
func mapDict(a *Actuator, data Dict, code []byte) []any {
	var buf []any
	size := len(data)

	for k, v := range data {
		// 每次一个小新环境
		a2 := a.BlockNew(code)
		a2.LoopSet(k, v, data, size)

		x := execScope(a2)
		// 排除 nil 值（忽略）
		if x != nil {
			buf = append(buf, x)
		}
	}
	return buf
}

// 切片过滤迭代（Filter）
// 代码块返回 true 的条目保留。
func filterSlice[T Itemer](a *Actuator, data []T, code []byte) []any {
	var buf []any
	size := len(data)

	for k, v := range data {
		// 每次一个小新环境
		a2 := a.BlockNew(code)
		a2.LoopSet(k, v, data, size)

		b := execScope(a2)
		if b.(Bool) {
			buf = append(buf, v)
		}
	}
	return buf
}

// 字典过滤迭代（Filter）
// 内部创建一个新的字典，避免在原数据上操作（可能有被引用）。
func filterDict(a *Actuator, data Dict, code []byte) Dict {
	var dic = make(Dict)
	size := len(data)

	for k, v := range data {
		// 每次一个小新环境
		a2 := a.BlockNew(code)
		a2.LoopSet(k, v, data, size)

		b := execScope(a2)
		if b.(Bool) {
			dic[k] = v
		}
	}
	return dic
}

// 切出一个子切片。
// i 为起始位置下标，支持负数从末尾算起。
// _z 为结束位置下标（不含），支持负数从末尾算起。
// 特殊 _z 值 nil 表示末尾之后。
// 返回：原始切片的局部引用。
func slice[T Itemer](ss []T, i int, _z any) []T {
	if i < 0 {
		i += len(ss)
	}
	if _z == nil {
		return ss[i:]
	}
	z := int(_z.(Int))

	if z < 0 {
		z += len(ss)
	}
	return ss[i:z]

}

// 切片成员顺序逆转。
// 返回：一个新的副本。
func reverse[T Itemer](ss []T) []T {
	ss = newCopy(ss, 0)

	for i, j := 0, len(ss)-1; i < j; i, j = i+1, j-1 {
		ss[i], ss[j] = ss[j], ss[i]
	}
	return ss
}

// 切片成员合并。
// 各切片的成员类型必须一致，否则会抛出错误。
// 返回：一个新的切片
func merge[T Itemer](vs ...any) []T {
	var buf []T

	for _, v := range vs {
		buf = append(buf, v.([]T)...)
	}
	return buf
}

// 切片扩充。
// 返回：一个新的扩充后的切片。
func expand[T Itemer](buf []T, vs ...any) []T {
	buf = newCopy(buf, len(vs))

	for _, v := range vs {
		buf = append(buf, v.(T))
	}
	return buf
}

// Any数据粘合。
// 返回 buf 的原指针引用。
func glueAny(buf *bytes.Buffer, vs []any) *bytes.Buffer {
	for _, v := range vs {
		switch x := v.(type) {
		case Byte:
			buf.WriteByte(x)
		case Rune:
			buf.WriteRune(x)
		case Bytes:
			buf.Write(x)
		case String:
			buf.WriteString(x)
		default:
			panic(neverToHere)
		}
	}
	return buf
}

// 获取切片成员。
// 下标位置支持负数从末尾算起。
func sliceItem[T Itemer](data []T, i int) T {
	if i < 0 {
		i += len(data)
	}
	return data[i]
}

// 获取切片成员。
func sliceItemX(data any, i int) any {
	switch x := data.(type) {
	case Bytes:
		return sliceItem(x, i)
	case Runes:
		return sliceItem(x, i)
	case []any:
		return sliceItem(x, i)
	case []Int:
		return sliceItem(x, i)
	case []Float:
		return sliceItem(x, i)
	case []String:
		return sliceItem(x, i)
	}
	panic(neverToHere)
}

// 获取切片成员集。
// 下标位置支持负数从末尾算起。
func sliceItems[T Itemer](data []T, ids []Int) []T {
	buf := make([]T, len(ids))

	for i, id := range ids {
		buf[i] = sliceItem(data, int(id))
	}
	return buf
}

// 获取切片成员集。
func sliceItemsX(data any, ids []Int) any {
	switch x := data.(type) {
	case Bytes:
		return sliceItems(x, ids)
	case Runes:
		return sliceItems(x, ids)
	case []any:
		return sliceItems(x, ids)
	case []Int:
		return sliceItems(x, ids)
	case []Float:
		return sliceItems(x, ids)
	case []String:
		return sliceItems(x, ids)
	}
	panic(neverToHere)
}

// 获取字典成员值集。
func dictItems(data Dict, ks []string) []any {
	buf := make([]any, len(ks))

	for i, k := range ks {
		buf[i] = data[k]
	}
	return buf
}

// 切片循环。
// 循环中的相同 JUMP 视为一次，但可能存在不同路径从而改变次数累计。
// 因此会检查记录最高次数，视为循环里的 JUMP 计次。
func sliceEach[T Itemer](a *Actuator, data []T, code []byte) {
	size := len(data)
	orig := a.Jumps()
	_max := orig

	for k, v := range data {
		// 每次一个小新环境
		a2 := a.BlockNew(code)

		a2.SetJumps(orig)
		a2.LoopSet(k, v, data, size)

		x := execPart(a2)
		n := a2.Jumps()

		if _max < n {
			_max = n // 最大记录
		}
		if x == _BREAK_ {
			break
		}
		// x == _CONTINUE_  >> 正常下一轮
	}
	a.SetJumps(_max)
}

// 字典循环。
// 注：代码与上面 sliceEach 相同。
func dictEach(a *Actuator, data Dict, code []byte) {
	size := len(data)
	orig := a.Jumps()
	_max := orig

	for k, v := range data {
		// 每次一个小新环境
		a2 := a.BlockNew(code)

		a2.SetJumps(orig)
		a2.LoopSet(k, v, data, size)

		x := execPart(a2)
		n := a2.Jumps()

		if _max < n {
			_max = n // 最大记录
		}
		if x == _BREAK_ {
			break
		}
	}
	a.SetJumps(_max)
}

// 字节序列转换到整数。
// 仅支持4种固定长度的字节序列：1, 2, 4, 8
func convBytesToInt(x []byte) (int64, error) {
	switch len(x) {
	case 1:
		return int64(x[0]), nil
	case 2:
		return int64(binary.BigEndian.Uint16(x)), nil
	case 4:
		return int64(binary.BigEndian.Uint32(x)), nil
	case 8:
		return int64(binary.BigEndian.Uint64(x)), nil
	}
	return 0, fmt.Errorf(bytesLenFail)
}

// 转换到字节类型。
// v 为数值类型。
func convToByte[T Rune | Int | Float](v T) byte {
	if v < math.MinInt8 || v > math.MaxUint8 {
		panic(errConvByte)
	}
	return byte(v)
}

// 转换到字符类型。
// v 为数值类型。
func convToRune[T Int | Float](v T) Rune {
	if v < math.MinInt32 || v > math.MaxInt32 {
		panic(errConvRune)
	}
	return rune(v)
}

// 转换到Any切片。
func convToAnys(data any) []any {
	switch x := data.(type) {
	case Runes:
		return cbase.ToAnys(x)
	case Bytes:
		return cbase.ToAnys(x)
	case []any:
		return x
	case []Int:
		return cbase.ToAnys(x)
	case []Float:
		return cbase.ToAnys(x)
	case []String:
		return cbase.ToAnys(x)
	}
	panic(neverToHere)
}

// 获取一个数值。
// 转为 float64 以便于统一处理。
func number(v any) Float {
	switch x := v.(type) {
	case Float:
		return x
	case Int:
		return Float(x)
	case Byte:
		return Float(x)
	case Rune:
		return Float(x)
	}
	panic(neverToHere)
}

// 字节序列连接。
func bytesGlue(b1, b2 Bytes) Bytes {
	var buf bytes.Buffer

	buf.Write(b1)
	buf.Write(b2)

	return buf.Bytes()
}

// 字典合并。
// 会返回（保留）首个实参字典的引用。
func dictMerge(d1, d2 Dict) Dict {
	for k, v := range d2 {
		d1[k] = v
	}
	return d1
}

// 数值切片置零。
func zeroNumber[T Number](buf []T) []T {
	for i := range buf {
		buf[i] = 0
	}
	return buf
}

// 是否在范围之内。
func within[T Number | String](x, a, b T) Bool {
	return a <= x && x < b
}

// 相等比较。
// 支持字节序列和支持该操作的内置类型。
func equal(a, b any) bool {
	if x, ok := a.([]byte); ok {
		return bytes.Equal(x, b.([]byte))
	}
	return a == b
}

// 每一个都为真。
func every[T any](list []T, f func(T) bool) bool {
	for _, v := range list {
		if !f(v) {
			return false
		}
	}
	return true
}

// 部分为真。
func some[T any](list []T, n int, f func(T) bool) bool {
	if n == 0 {
		return true
	}
	for _, v := range list {
		if f(v) {
			n--
			if n == 0 {
				return true
			}
		}
	}
	return false
}

// 提取脚本代码。
// 仅支持两种目标类型（Bytes|*Script），用于模式目标获取。
// 注：
// 脚本类型取原始源码（忽略内部 offset）。
func scriptCode(arg any) []byte {
	switch x := arg.(type) {
	case []byte:
		return x
	case *Script:
		return x.Source()
	}
	panic(neverToHere)
}

// 切片深层复制。
// 注：顶层成员仅限于any类型。
func deepCopy(s []any) []any {
	buf := make([]any, len(s))

	for i, v := range s {
		switch x := v.(type) {
		case []any:
			buf[i] = deepCopy(x)
		case Bytes:
			buf[i] = newCopy(x, 0)
		case Runes:
			buf[i] = newCopy(x, 0)
		case []Int:
			buf[i] = newCopy(x, 0)
		case []Float:
			buf[i] = newCopy(x, 0)
		case []String:
			buf[i] = newCopy(x, 0)
		default:
			buf[i] = x // 普通值
		}
	}
	return buf
}

// 切片复制。
// ext 为预留多出的空间大小。
// 仅为直接成员复制，any成员不能保证底层无相互引用。
func newCopy[T any](s []T, ext int) []T {
	n := len(s)
	buf := make([]T, n, n+ext)

	copy(buf, s)
	return buf
}

// 获取字典的键值集。
// 返回的键/值集成员按顺序一一对应。
func keyVals(d Dict) ([]string, []any) {
	ks := make([]string, 0, len(d))
	vs := make([]any, 0, len(d))

	for k, v := range d {
		ks = append(ks, k)
		vs = append(vs, v)
	}
	return ks, vs
}

// 截取子字符串。
// i 为起点字符位置（正数）。
// n 为截取的字符数量。
// 注记：
// 逐个检查，足够即返回（无需全部转换）。
func strSub1(s string, i, n int) string {
	var rs []rune

	for _, r := range s {
		if i > 0 {
			i--
			continue
		}
		if n == 0 {
			break
		}
		n--
		rs = append(rs, r)
	}
	return string(rs)
}

// 截取子字符串（负值下标）。
// i 为起点字符位置。
// n 为截取的字符数量。
// 注记：
// 从末尾计数需要先全部转换为字符集。
func strSub2(s string, i, n int) string {
	rs := []rune(s)
	i += len(rs)
	return string(rs[i : i+n])
}

// 切片随机扰乱。
// 随机数种子是安全的。
func randSlice[T any](s []T) []T {
	new := make([]T, len(s))
	rand.Seed(
		randInt(math.MaxInt64),
	)
	for i, n := range rand.Perm(len(s)) {
		new[i] = s[n]
	}
	return new
}

// 创建一个安全随机int64数。
func randInt(max int64) int64 {
	num, err := crand.Int(crand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}
	return num.Int64()
}

// 创建一个安全随机大整数。
func randBigInt(max *BigInt) *BigInt {
	num, err := crand.Int(crand.Reader, max)
	if err != nil {
		panic(err)
	}
	return num
}

// 创建值范围切片。
// n 为起始值（包含）。
// step 为步进值。
// size 为成员数量。
func rangeSlice[T Number](n, step T, size int) []T {
	buf := make([]T, size)
	buf[0] = n

	for i := 1; i < size; i++ {
		buf[i] = buf[i-1] + step
	}
	return buf
}

// 转换为字节序列集合。
func bytesSlice(list []any) [][]byte {
	var buf [][]byte

	for _, v := range list {
		buf = append(buf, v.([]byte))
	}
	return buf
}

// 访问异常。
// 执行流抵达占位指令的统一错误处理。
func accessPanic(*Actuator, []any, any, ...any) []any {
	panic(accessError)
}

//
// 初始化：
// 按指令值对应下标赋值配置器。
///////////////////////////////////////////////////////////////////////////////

func init() {
	// 值指令 20
	// --------------------------------------
	__InstSet[icode.NIL] = Instx{_NIL, 0}
	__InstSet[icode.TRUE] = Instx{_TRUE, 0}
	__InstSet[icode.FALSE] = Instx{_FALSE, 0}
	__InstSet[icode.Uint8n] = Instx{_Int, 0}
	__InstSet[icode.Uint8] = Instx{_Int, 0}
	__InstSet[icode.Uint63n] = Instx{_Int, 0}
	__InstSet[icode.Uint63] = Instx{_Int, 0}
	__InstSet[icode.Byte] = Instx{_Byte, 0}
	__InstSet[icode.Rune] = Instx{_Rune, 0}
	__InstSet[icode.Float32] = Instx{_Float, 0}
	__InstSet[icode.Float64] = Instx{_Float, 0}
	__InstSet[icode.DATE] = Instx{_DATE, 0}
	__InstSet[icode.BigInt] = Instx{_BigInt, 0}
	__InstSet[icode.DATA8] = Instx{_DATA, 0}
	__InstSet[icode.DATA16] = Instx{_DATA, 0}
	__InstSet[icode.TEXT8] = Instx{_TEXT, 0}
	__InstSet[icode.TEXT16] = Instx{_TEXT, 0}
	__InstSet[icode.RegExp] = Instx{_RegExp, 0}
	__InstSet[icode.CODE] = Instx{_CODE, 0}
	// __InstSet[19] =

	// 截取指令 5
	// --------------------------------------
	__InstSet[icode.Capture] = Instx{_Capture, 0}
	__InstSet[icode.Bring] = Instx{_Bring, 0}
	__InstSet[icode.ScopeAdd] = Instx{_ScopeAdd, 0}
	__InstSet[icode.ScopeVal] = Instx{_ScopeVal, 0}
	__InstSet[icode.LoopVal] = Instx{_LoopVal, 0}

	// 栈操作指令 10
	// --------------------------------------
	__InstSet[icode.NOP] = Instx{_NOP, -1}
	__InstSet[icode.PUSH] = Instx{_PUSH, -1}
	__InstSet[icode.SHIFT] = Instx{_SHIFT, 0}
	__InstSet[icode.CLONE] = Instx{_CLONE, 0}
	__InstSet[icode.POP] = Instx{_POP, 0}
	__InstSet[icode.POPS] = Instx{_POPS, 0}
	__InstSet[icode.TOP] = Instx{_TOP, 0}
	__InstSet[icode.TOPS] = Instx{_TOPS, 0}
	__InstSet[icode.PEEK] = Instx{_PEEK, 0}
	__InstSet[icode.PEEKS] = Instx{_PEEKS, 0}

	// 集合指令 11
	// --------------------------------------
	__InstSet[icode.SLICE] = Instx{_SLICE, 3}
	__InstSet[icode.REVERSE] = Instx{_REVERSE, 1}
	__InstSet[icode.MERGE] = Instx{_MERGE, -1}
	__InstSet[icode.EXPAND] = Instx{_EXPAND, -1}
	__InstSet[icode.GLUE] = Instx{_GLUE, 1}
	__InstSet[icode.SPREAD] = Instx{_SPREAD, 1}
	__InstSet[icode.ITEM] = Instx{_ITEM, 2}
	__InstSet[icode.SET] = Instx{_SET, 3}
	__InstSet[icode.SIZE] = Instx{_SIZE, 1}
	__InstSet[icode.MAP] = Instx{_MAP, -1}
	__InstSet[icode.FILTER] = Instx{_FILTER, -1}

	// 交互指令 5
	// --------------------------------------
	__InstSet[icode.INPUT] = Instx{_INPUT, 0}
	__InstSet[icode.OUTPUT] = Instx{_OUTPUT, -1}
	__InstSet[icode.BUFDUMP] = Instx{_BUFDUMP, 0}
	// __InstSet[51] =
	__InstSet[icode.PRINT] = Instx{_PRINT, -1}

	// 结果指令 6
	// --------------------------------------
	__InstSet[icode.PASS] = Instx{_PASS, 1}
	__InstSet[icode.FAIL] = Instx{_FAIL, 1}
	__InstSet[icode.GOTO] = Instx{_GOTO, -1}
	__InstSet[icode.JUMP] = Instx{_JUMP, 0}
	__InstSet[icode.EXIT] = Instx{_EXIT, -1}
	__InstSet[icode.RETURN] = Instx{_RETURN, 1}

	// 流程指令 10
	// --------------------------------------
	__InstSet[icode.IF] = Instx{_IF, 1}
	__InstSet[icode.ELSE] = Instx{_ELSE, 0}
	__InstSet[icode.SWITCH] = Instx{_SWITCH, 2}
	__InstSet[icode.CASE] = Instx{_CASE, 0}
	__InstSet[icode.DEFAULT] = Instx{_DEFAULT, 0}
	__InstSet[icode.EACH] = Instx{_EACH, 1}
	__InstSet[icode.CONTINUE] = Instx{_CONTINUE, -1}
	__InstSet[icode.BREAK] = Instx{_BREAK, -1}
	__InstSet[icode.FALLTHROUGH] = Instx{_FALLTHROUGH, 0}
	__InstSet[icode.BLOCK] = Instx{_BLOCK, 0}

	// 转换指令 13
	// --------------------------------------
	__InstSet[icode.BOOL] = Instx{_BOOL, 1}
	__InstSet[icode.BYTE] = Instx{_BYTE, 1}
	__InstSet[icode.RUNE] = Instx{_RUNE, 1}
	__InstSet[icode.INT] = Instx{_INT, 1}
	__InstSet[icode.BIGINT] = Instx{_BIGINT, 1}
	__InstSet[icode.FLOAT] = Instx{_FLOAT, 1}
	__InstSet[icode.STRING] = Instx{_STRING, 1}
	__InstSet[icode.BYTES] = Instx{_BYTES, 1}
	__InstSet[icode.RUNES] = Instx{_RUNES, 1}
	__InstSet[icode.TIME] = Instx{_TIME, 1}
	__InstSet[icode.REGEXP] = Instx{_REGEXP, 1}
	__InstSet[icode.ANYS] = Instx{_ANYS, 1}
	__InstSet[icode.DICT] = Instx{_DICT, 2}

	// 运算指令 24
	// --------------------------------------
	__InstSet[icode.Expr] = Instx{_Expr, 0}
	__InstSet[icode.Mul] = Instx{accessPanic, 0}
	__InstSet[icode.Div] = Instx{accessPanic, 0}
	__InstSet[icode.Add] = Instx{accessPanic, 0}
	__InstSet[icode.Sub] = Instx{accessPanic, 0}
	__InstSet[icode.MUL] = Instx{_MUL, 2}
	__InstSet[icode.DIV] = Instx{_DIV, 2}
	__InstSet[icode.ADD] = Instx{_ADD, 2}
	__InstSet[icode.SUB] = Instx{_SUB, 2}
	__InstSet[icode.POW] = Instx{_POW, 2}
	__InstSet[icode.MOD] = Instx{_MOD, 2}
	__InstSet[icode.LMOV] = Instx{_LMOV, 2}
	__InstSet[icode.RMOV] = Instx{_RMOV, 2}
	__InstSet[icode.AND] = Instx{_AND, 2}
	__InstSet[icode.ANDX] = Instx{_ANDX, 2}
	__InstSet[icode.OR] = Instx{_OR, 2}
	__InstSet[icode.XOR] = Instx{_XOR, 2}
	__InstSet[icode.NEG] = Instx{_NEG, 1}
	__InstSet[icode.NOT] = Instx{_NOT, 1}
	__InstSet[icode.DIVMOD] = Instx{_DIVMOD, 2}
	__InstSet[icode.DUP] = Instx{_DUP, 1}
	__InstSet[icode.DEL] = Instx{_DEL, 2}
	__InstSet[icode.CLEAR] = Instx{_CLEAR, 1}
	// __InstSet[103] =

	// 比较指令 8
	// --------------------------------------
	__InstSet[icode.EQUAL] = Instx{_EQUAL, 2}
	__InstSet[icode.NEQUAL] = Instx{_NEQUAL, 2}
	__InstSet[icode.LT] = Instx{_LT, 2}
	__InstSet[icode.LTE] = Instx{_LTE, 2}
	__InstSet[icode.GT] = Instx{_GT, 2}
	__InstSet[icode.GTE] = Instx{_GTE, 2}
	__InstSet[icode.ISNAN] = Instx{_ISNAN, 1}
	__InstSet[icode.WITHIN] = Instx{_WITHIN, 3}

	// 逻辑指令 4
	// --------------------------------------
	__InstSet[icode.BOTH] = Instx{_BOTH, 2}
	__InstSet[icode.EVERY] = Instx{_EVERY, 1}
	__InstSet[icode.EITHER] = Instx{_EITHER, 2}
	__InstSet[icode.SOME] = Instx{_SOME, 1}

	// 模式指令 12
	// --------------------------------------
	__InstSet[icode.MODEL] = Instx{_MODEL, 1}
	__InstSet[icode.ValPick] = Instx{accessPanic, 0}
	__InstSet[icode.Wildcard] = Instx{accessPanic, 0}
	__InstSet[icode.Wildnum] = Instx{accessPanic, 0}
	__InstSet[icode.Wildpart] = Instx{accessPanic, 0}
	__InstSet[icode.Wildlist] = Instx{accessPanic, 0}
	__InstSet[icode.TypeIs] = Instx{accessPanic, 0}
	__InstSet[icode.WithinInt] = Instx{accessPanic, 0}
	__InstSet[icode.WithinFloat] = Instx{accessPanic, 0}
	__InstSet[icode.RE] = Instx{accessPanic, 0}
	__InstSet[icode.RePick] = Instx{accessPanic, 0}
	__InstSet[icode.WildLump] = Instx{accessPanic, 0}

	// 环境指令 10
	// --------------------------------------
	__InstSet[icode.ENV] = Instx{_ENV, 0}
	__InstSet[icode.OUT] = Instx{_OUT, 0}
	__InstSet[icode.IN] = Instx{_IN, 0}
	__InstSet[icode.INOUT] = Instx{_INOUT, 0}
	__InstSet[icode.XFROM] = Instx{_XFROM, 0}
	__InstSet[icode.VAR] = Instx{_VAR, 0}
	__InstSet[icode.SETVAR] = Instx{_SETVAR, 1}
	__InstSet[icode.SOURCE] = Instx{_SOURCE, 0}
	__InstSet[icode.MULSIG] = Instx{_MULSIG, 0}
	// __InstSet[137] =

	// 工具指令 26
	// --------------------------------------
	__InstSet[icode.EVAL] = Instx{_EVAL, 1}
	__InstSet[icode.COPY] = Instx{_COPY, 1}
	__InstSet[icode.DCOPY] = Instx{_DCOPY, 1}
	__InstSet[icode.KEYVAL] = Instx{_KEYVAL, 1}
	__InstSet[icode.MATCH] = Instx{_MATCH, 2}
	__InstSet[icode.SUBSTR] = Instx{_SUBSTR, 2}
	__InstSet[icode.REPLACE] = Instx{_REPLACE, 3}
	__InstSet[icode.SRAND] = Instx{_SRAND, 1}
	__InstSet[icode.RANDOM] = Instx{_RANDOM, -1}
	__InstSet[icode.QRANDOM] = Instx{_QRANDOM, -1}
	__InstSet[icode.CMPFLO] = Instx{_CMPFLO, 3}
	// __InstSet[149-154] =
	__InstSet[icode.RANGE] = Instx{_RANGE, 2}
	// __InstSet[156-163] =

	// 系统指令 6
	// --------------------------------------
	__InstSet[icode.SYS_TIME] = Instx{_SYS_TIME, 0}
	__InstSet[icode.SYS_AWARD] = Instx{_SYS_AWARD, 0}
	// __InstSet[166-168] =
	__InstSet[icode.SYS_NULL] = Instx{_SYS_NULL, 0}

	// 函数指令 40
	// --------------------------------------
	__InstSet[icode.FN_BASE58] = Instx{_FN_BASE58, 1}
	__InstSet[icode.FN_BASE32] = Instx{_FN_BASE32, 1}
	__InstSet[icode.FN_BASE64] = Instx{_FN_BASE64, 1}
	__InstSet[icode.FN_PUBHASH] = Instx{_FN_PUBHASH, 1}
	__InstSet[icode.FN_MPUBHASH] = Instx{_FN_MPUBHASH, 2}
	__InstSet[icode.FN_ADDRESS] = Instx{_FN_ADDRESS, 2}
	__InstSet[icode.FN_CHECKSIG] = Instx{_FN_CHECKSIG, 2}
	__InstSet[icode.FN_MCHECKSIG] = Instx{_FN_MCHECKSIG, 2}
	__InstSet[icode.FN_HASH224] = Instx{_FN_HASH224, 1}
	__InstSet[icode.FN_HASH256] = Instx{_FN_HASH256, 1}
	__InstSet[icode.FN_HASH384] = Instx{_FN_HASH384, 1}
	__InstSet[icode.FN_HASH512] = Instx{_FN_HASH512, 1}
	// __InstSet[182-207] =
	__InstSet[icode.FN_PRINTF] = Instx{_FN_PRINTF, -1}
	// Done.
}
