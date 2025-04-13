// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package instor 提供脚本指令的基本信息，类型定义和名称约定等。
package instor

import (
	"encoding/binary"
	"math"
	"math/big"
	"regexp"
	"time"

	"github.com/cxio/script/icode"
)

// 布尔类型
type Bool = bool

// 通用整数
type Int = int64

// 字节类型
type Byte = byte

// 字符类型
type Rune = rune

// 通用浮点数
type Float = float64

// 大整数
type BigInt = big.Int

// 文本串
type String = string

// 字节序列
type Bytes = []Byte

// 字符序列
type Runes = []Rune

// 时间类型
type Time = time.Time

// 正则表达式
type RegExp = regexp.Regexp

// 脚本对象。
type Script struct {
	source  []byte // 源指令序列
	offset  int    // 当前指令位置偏移
	nullpos int    // NULL 位置点（SYS_NULL）
}

// 新建一个脚本。
func NewScript(b []byte) *Script {
	return &Script{source: b}
}

// 是否抵达末尾。
func (s *Script) End() bool {
	return s.offset >= len(s.source)
}

// 获取当前指令码值。
func (s *Script) Code() int {
	return int(s.source[s.offset])
}

// 截取脚本字节序列。
// 从当前指令位置开始后续全部。
func (s *Script) Bytes() []byte {
	return s.source[s.offset:]
}

// 获取执行过的代码。
func (s *Script) Past() []byte {
	return s.source[:s.offset]
}

// 获取执行过的代码，但从NULL点开始算。
// 注：SYS_NULL => SOURCE 专用。
func (s *Script) PastNull() []byte {
	return s.source[s.nullpos:s.offset]
}

// 获取原始字节序列。
func (s *Script) Source() []byte {
	return s.source[:]
}

// 获取原始字节序列，从NULL点开始。
func (s *Script) SourceNull() []byte {
	return s.source[s.nullpos:]
}

// 获取当前偏移量。
func (s *Script) Offset() int {
	return s.offset
}

// 步进一个指令。
func (s *Script) Next(n int) {
	s.offset += n
}

// 设置NULL点。
// 将当前内部偏移值设置为NULL点。
// 注：SYS_NULL 指令专用。
func (s *Script) PostNull() {
	s.nullpos = s.offset
}

// 脚本重置。
// 内部游标归零，并返回原始引用。
func (s *Script) Reset() {
	s.offset = 0
	s.nullpos = 0
}

// 创建一个副本。
// 注：保留内部的偏移量值。
func (s *Script) New() *Script {
	buf := make([]byte, len(s.source))
	copy(buf, s.source)

	return &Script{buf, s.offset, 0}
}

// 整数类型约束。
type Integer interface {
	Int | Rune | Byte
}

// 数值类型约束。
type Number interface {
	Integer | Float
}

// 切片成员类型约束。
type Itemer interface {
	any | Byte | Rune | Int | Float | String
}

// 指令信息包。
// 附参和关联数据已经解析为指令特定的类型。
type Insted struct {
	Code int   // 指令码
	Args []any // 附参值集
	Data any   // 关联数据
	Size int   // 指令占用总长
}

// 获取指令信息包
// code 为脚本指令序列，从目标指令位置开始。
func Get(code []byte) *Insted {
	c := int(code[0])

	if f := __Parses[c]; f != nil {
		return f(code)
	}
	return &Insted{c, nil, nil, 1}
}

// 解析器。
// 从脚本中解析提取指令信息。
type parser func([]byte) *Insted

// 解析器集。
// 注：简单解析器不会被设置。
var __Parses [256]parser

// 指令信息字节包。
// 不解析类型，提供原始字节/字节序列引用。
type Instor struct {
	Code int      // 指令码
	Args [][]byte // 附参值集
	Data []byte   // 关联数据
	Size int      // 指令占用总长
}

// 获取指令原始信息包
// code 为脚本指令序列，从目标指令位置开始。
func Raw(code []byte) *Instor {
	c := int(code[0])

	if f := __Pickes[c]; f != nil {
		return f(code)
	}
	return &Instor{c, nil, nil, 1}
}

// 捡取器。
// 从脚本中提取指令原始信息。
type picker func([]byte) *Instor

// 捡取器集。
// 注：简单捡取器不会被设置。
var __Pickes [256]picker

//
// 捡取器定义
// 无附参和关联数据的单指令无需定义，将通过默认构造。
// 注记：
// 大都通过Raw()获取原始信息，一致性更好（维护）。
///////////////////////////////////////////////////////////////////////////////

/*
 * 值指令
 * 附参和数据表达同一个值时，以数据表达，附参为nil。
 * 单指令：NIL TRUE FALSE
 ******************************************************************************
 */

// 指令：{}(1) -uint8
// 附参：1 byte 整数值。
// 存值范围：[-255, 0]
func _Uint8n(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		nil,
		-Int(ins.Data[0]),
		ins.Size,
	}
}

// 指令：{}(1) uint8
// 附参：1 byte 整数值。
// 存值范围：[0, 255]
func _Uint8(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		nil,
		Int(ins.Data[0]),
		ins.Size,
	}
}

// 指令：{}(~) -uint63
// 附参：变长整数，按变长正整数存储。
// 存值范围：[-1<<63, -256]
// 注记：
// 实际存储值为int64类型，负值需要先转正再存储。
// 转换：binary.PutUvarint( uint64(-v) )
// 注意：不是 uint64(v)
// 这样除了负值 -1<<63 外，其余都最多只占用9字节空间。
func _Uint63n(code []byte) *Insted {
	ins := Raw(code)
	v, _ := binary.Uvarint(ins.Data)

	// 安全：存储源于int64不会超标
	return &Insted{ins.Code, nil, -Int(v), ins.Size}
}

// 指令：{}(~) uint63
// 附参：变长整数，按变长正整数存储。
// 存值范围：[256, 1<<63-1]
// 注：
// <-255 或 >255 的值由 _Uint8n/_Uint8 存储。
func _Uint63(code []byte) *Insted {
	ins := Raw(code)
	v, _ := binary.Uvarint(ins.Data)

	// 安全：存储源于int64不会超标
	return &Insted{ins.Code, nil, Int(v), ins.Size}
}

// 指令：{}(1) byte
// 附参：1 byte 字节值。
func _Byte(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		nil,
		Byte(ins.Data[0]),
		ins.Size,
	}
}

// 指令：{}(4) rune
// 附参：4 byte 字符码点。
func _Rune(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		nil,
		Rune(binary.BigEndian.Uint32(ins.Data)),
		ins.Size,
	}
}

// 指令：{}(4) float32
// 附参：4 bytes，浮点数
func _Float32(code []byte) *Insted {
	ins := Raw(code)
	v := binary.BigEndian.Uint32(ins.Data)

	return &Insted{
		ins.Code,
		nil,
		Float(math.Float32frombits(v)),
		ins.Size,
	}
}

// 指令：{}(8) float64
// 附参：8 bytes，浮点数
func _Float64(code []byte) *Insted {
	ins := Raw(code)
	v := binary.BigEndian.Uint64(ins.Data)

	return &Insted{
		ins.Code,
		nil,
		Float(math.Float64frombits(v)),
		ins.Size,
	}
}

// 指令：DATE{}(~) 时间对象
// 附参：不定长度，有符号变长整数时间戳，毫秒。
func _DATE(code []byte) *Insted {
	ins := Raw(code)
	v, _ := binary.Varint(ins.Data)

	return &Insted{
		ins.Code,
		nil,
		time.UnixMilli(int64(v)),
		ins.Size,
	}
}

// 指令：{}(1)+N 大整数
// 附参：1 byte，值占用的字节数。
func _BigInt(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(ins.Args[0][0])},
		big.NewInt(0).SetBytes(ins.Data),
		ins.Size,
	}
}

// 指令：DATA{}(1) 字节序列
// 附参：1 byte，序列占用字节数。
// 注记：
// 因为栈脚本保证脚本源为只读，所以这里直接返回引用。
func _DATA8(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(ins.Args[0][0])},
		Bytes(ins.Data),
		ins.Size,
	}
}

// 指令：DATA{}(2) 字节序列
// 附参：2 bytes，序列占用字节数。
// 注：同上返回原始引用。
func _DATA16(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(binary.BigEndian.Uint16(ins.Args[0]))},
		Bytes(ins.Data),
		ins.Size,
	}
}

// 指令：TEXT{}(1) 短文本串
// 附参：1 byte，文本占用字节数。
func _TEXT8(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(ins.Args[0][0])},
		String(ins.Data),
		ins.Size,
	}
}

// 指令：TEXT{}(2) 长文本串
// 附参：2 bytes，文本占用字节数。
func _TEXT16(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(binary.BigEndian.Uint16(ins.Args[0]))},
		String(ins.Data),
		ins.Size,
	}
}

// 指令：/.../(1) 正则表达式
// 附参：1 byte，表达式长度（<256）
func _RegExp(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(ins.Args[0][0])},
		regexp.MustCompile(string(ins.Data)),
		ins.Size,
	}
}

// 指令：CODE{}(1) 指令代码序列
// 附参：1 byte，指令序列长度（<256）
// 注记：
// 代码可能会被执行，使用源码的副本更友好。
func _CODE(code []byte) *Insted {
	ins := Raw(code)

	buf := make([]byte, len(ins.Data))
	copy(buf, ins.Data)

	return &Insted{
		ins.Code,
		[]any{int(ins.Args[0][0])},
		NewScript(buf),
		ins.Size,
	}
}

/*
 * 截取指令
 * 单指令： @  ~  $
 ******************************************************************************
 */

// 指令：$(1) 局域取值
// 附参：1 byte，取值下标，支持负值。
func _ScopeVal(code []byte) *Insted { return parseArg1x(code) }

// 指令：${}(1) 循环域取值
// 附参：1 byte，目标值位置下标 [0-3]。
func _LoopVal(code []byte) *Insted { return parseArg1(code) }

/*
 * 栈操作指令
 * 单指令：NOP PUSH POP TOP PEEK
 ******************************************************************************
 */

// 指令：SHIFT(1) 提取栈顶条目
// 附参：1 byte，取栈条目数。
func _SHIFT(code []byte) *Insted { return parseArg1(code) }

// 指令：CLONE(1) 栈顶项克隆
// 附参：1 byte，栈顶项数。
func _CLONE(code []byte) *Insted { return parseArg1(code) }

// 指令：POPS(1) 弹出栈顶多项
// 附参：1 byte，弹出条目数。
func _POPS(code []byte) *Insted { return parseArg1(code) }

// 指令：TOPS(1) 引用栈顶多项
// 附参：1 byte，引用条目数。
func _TOPS(code []byte) *Insted { return parseArg1(code) }

// 指令：PEEKS(1) 引用栈内任意位置段条目
// 附参：1 byte，引用条目数。
func _PEEKS(code []byte) *Insted { return parseArg1(code) }

/*
 * 集合指令
 * 单指令：SLICE REVERSE MERGE EXPAND GLUE SPREAD ITEM SET SIZE
 ******************************************************************************
 */

// 指令：MAP{}(1) 迭代映射。
// 附参：1 byte，子语句块长度。
func _MAP(code []byte) *Insted { return parseArg1Code(code) }

// 指令：MAP{}(1) 迭代映射。
// 附参：1 byte，子语句块长度。
func _FILTER(code []byte) *Insted { return parseArg1Code(code) }

/*
 * 交互指令
 * 单指令：OUTPUT PRINT
 ******************************************************************************
 */

// 指令：INPUT(1) 导入缓存区的数据
// 附参：1 byte，读取的条目数。
func _INPUT(code []byte) *Insted { return parseArg1(code) }

// 指令：BUFDUMP 导出区数据转出
// 附参：1 byte，序位标识，用户自定义。
func _BUFDUMP(code []byte) *Insted { return parseArg1(code) }

/*
 * 结果指令
 * 单指令：PASS FAIL EXIT RETURN
 ******************************************************************************
 */

// 指令：GOTO(4,4,2) 执行流跳转
// 附参1：4 byts，区块高度。
// 附参2：4 byts，交易序位。
// 附参3：2 byts，脚本序位。
func _GOTO(code []byte) *Insted {
	c := int(code[0])
	h := int(binary.BigEndian.Uint32(code[1:5]))
	n := int(binary.BigEndian.Uint32(code[5:9]))
	i := int(binary.BigEndian.Uint16(code[9:11]))

	return &Insted{c, []any{h, n, i}, nil, 11}
}

// 指令：JUMP(4,4,2) 跳转脚本嵌入
// 附参：参考上面_GOTO。
func _JUMP(code []byte) *Insted {
	return _GOTO(code)
}

/*
 * 流程指令
 * 单指令：CONTINUE BREAK FALLTHROUGH
 * 注：子语句块即是指令的关联数据。
 ******************************************************************************
 */

// 指令：IF{}(1) 真值执行块
// 附参：1 byte，子语句块长度。
func _IF(code []byte) *Insted { return parseArg1Code(code) }

// 指令：ELSE{}(1) IF不满足时执行
// 附参：1 byte，子块长度。
func _ELSE(code []byte) *Insted { return parseArg1Code(code) }

// 指令：SWITCH{}(~) 分支选择区
// 附参：变长字节，子块长度。
func _SWITCH(code []byte) *Insted { return parseArgXCode(code) }

// 指令：CASE{}(1) 条件分支
// 附参：1 byte，子语句块长度。
func _CASE(code []byte) *Insted { return parseArg1Code(code) }

// 指令：DEFAULT{}(1) 默认分支
// 附参：1 byte, 子语句块长度。
func _DEFAULT(code []byte) *Insted { return parseArg1Code(code) }

// 指令：EACH{}(1) 迭代式循环
// 附参：1 byte，子语句块长度。
func _EACH(code []byte) *Insted { return parseArg1Code(code) }

// 指令：BLOCK{}(~) 创建局部域
// 附参：变长字节，子块长度。
func _BLOCK(code []byte) *Insted { return parseArgXCode(code) }

/*
 * 转换指令
 * 单指令：
 * BOOL BYTE RUNE INT BIGINT FLOAT BYTES RUNES TIME SCRIPT REGEXP
 ******************************************************************************
 */

// 指令：STRING(1) 转为字符串
// 附参：1 byte，格式标识，适用数值类型。
func _STRING(code []byte) *Insted { return parseArg1(code) }

// 指令：ANYS(1) 切片互转（Any<=>T）
// 附参：1 byte，目标类型标识。
func _ANYS(code []byte) *Insted { return parseArg1(code) }

/*
 * 运算指令
 * 单指令：
 * / + -
 * MUL DIV ADD SUB POW MOD LMOV RMOV AND ANDX OR XOR NEG NOT
 * DIVMOD DEL CLEAR
 ******************************************************************************
 */

// 指令：()(1) 表达式封装&优先级分组
// 附参：1 byte，表达式长度。
func _Expr(code []byte) *Insted { return parseArg1Code(code) }

// 指令：复制
// 附参：1 byte，复制份数，正整数。
func _DUP(code []byte) *Insted { return parseArg1(code) }

/*
 * 比较指令
 * 单指令：EQUAL NEQUAL LT LTE GT GTE ISNAN WITHIN
 ******************************************************************************
 */

/*
 * 逻辑指令
 * 单指令：BOTH EVERY EITHER
 ******************************************************************************
 */

// 指令：部分为真
// 附参：1 byte，为真的最低数量。
func _SOME(code []byte) *Insted { return parseArg1(code) }

/*
 * 模式指令
 * 单指令： _  ...
 ******************************************************************************
 */

// 指令：创建模式匹配区
// 附参：2 bytes，取值标记和模式区代码长度。
// 附参包含2个部分：
// - [0]: 取值标记，bool
// - [1]: 模式区代码长度（低14位），int。
// 其中：
// - 1000_0000 0000_0000 标记取值逻辑。
// - 0100_0000 0000_0000 （未用）
func _MODEL(code []byte) *Insted {
	ins := Raw(code)
	// 高位序，[0]即可
	f := ins.Args[0][0]&0b1000_0000 != 0

	return &Insted{
		ins.Code,
		[]any{f, len(ins.Data)},
		ins.Data,
		ins.Size,
	}
}

// 指令：#(1) 取值指示
// 附参：1 byte，目标值标识。
func _ValPick(code []byte) *Insted { return parseArg1(code) }

// 指令：_(1) 指令段通配
// 附参：1 byte，忽略的指令个数。
func _Wildnum(code []byte) *Insted { return parseArg1(code) }

// 指令：?(1) 指令局部通配
// 附参：1 byte，指令局部标识。
func _Wildpart(code []byte) *Insted { return parseArg1(code) }

// 指令：?(1){} 指令序列可选
// 附参：1 byte，内部指令序列长度。
func _Wildlist(code []byte) *Insted { return parseArg1Code(code) }

// 指令：!{Type}(1) 类型匹配
// 附参：1 byte，类型标识值。
func _TypeIs(code []byte) *Insted { return parseArg1(code) }

// 指令：!{}(~,~) 整数值范围匹配
// 附参1：下边界值，变长整数，包含。
// 附参2：上边界值，变长整数，不包含。
func _WithinInt(code []byte) *Insted {
	ins := Raw(code)
	low, _ := binary.Varint(ins.Args[0])
	up, _ := binary.Varint(ins.Args[1])

	return &Insted{
		ins.Code,
		[]any{low, up},
		nil,
		ins.Size,
	}
}

// 指令：!{}(8,8,4) 浮点数值范围匹配
// 附参1：8 bytes，下边界值，包含。
// 附参2：8 bytes，上边界值，不包含。
// 附参3：4 bytes，下边界相等误差。
func _WithinFloat(code []byte) *Insted {
	ins := Raw(code)
	low := float64From(ins.Args[0])
	up := float64From(ins.Args[1])
	dev := float64From(ins.Args[2])

	return &Insted{ins.Code, []any{low, up, dev}, nil, ins.Size}
}

// 指令：正则匹配
// 附参1：1 byte，匹配标记（g|G|!）。
// 附参2：1 byte，正则匹配式文本的长度。
func _RE(code []byte) *Insted {
	ins := Raw(code)
	f := int(ins.Args[0][0])
	n := int(ins.Args[1][0])

	return &Insted{
		ins.Code,
		[]any{f, n},
		regexp.MustCompile(string(ins.Data)),
		ins.Size,
	}
}

// 指令：&(1) 正则匹配取值
// 附参：1 byte，正则匹配的取值序位。
func _RePick(code []byte) *Insted { return parseArg1(code) }

/*
 * 环境指令
 ******************************************************************************
 */

// 指令：ENV(1){} 环境变量提取
// 附参：1 byte，目标名称的标识值。
func _ENV(code []byte) *Insted { return parseArg1(code) }

// 指令：OUT(1,1){} 输出项取值
// 附参1：2 bytes，输出项偏移。
// 附参2：1 byte，目标成员标识。
func _OUT(code []byte) *Insted {
	ins := Raw(code)
	i := int(binary.BigEndian.Uint16(ins.Args[0]))
	n := int(ins.Args[1][0])

	return &Insted{ins.Code, []any{i, n}, nil, ins.Size}
}

// 指令：IN(1){} 输入项取值
// 附参：1 byte，目标成员标识。
func _IN(code []byte) *Insted { return parseArg1(code) }

// 指令：INOUT(1){} 输入的源输出项取值
// 附参：1 byte，目标成员标识。
func _INOUT(code []byte) *Insted { return parseArg1(code) }

// 指令：XFROM(1){} 获取源脚本信息
// 附参：1 byte，目标信息标识值，正整数。
func _XFROM(code []byte) *Insted { return parseArg1(code) }

// 指令：VAR(1) 全局变量取值
// 附参：1 byte，目标变量位置/下标，正整数。
func _VAR(code []byte) *Insted { return parseArg1(code) }

// 指令：SETVAR(1) 全局变量赋值
// 附参：1 byte，变量位置/下标，正整数。
func _SETVAR(code []byte) *Insted { return parseArg1(code) }

// 指令：SOURCE(1) 获取源脚本
// 附参：1 byte，片段标识值。
func _SOURCE(code []byte) *Insted { return parseArg1(code) }

// 指令：MULSIG(1) 多重签名序位确认
// 附参：1 byte，目标序位（签名者序号），正整数。
func _MULSIG(code []byte) *Insted { return parseArg1(code) }

/*
 * 工具指令
 * 单指令： EVAL CALL COPY DICT REPLACE SRAND RANDOM QRANDOM
 ******************************************************************************
 */

// 指令：KEYVAL(1) 字典键值切分
// 附参：1 byte，取值标识。0: 键+值；1: 键；2: 值。
func _KEYVAL(code []byte) *Insted { return parseArg1(code) }

// 指令：MATCH(1) 获取源脚本信息（GOTO 源）
// 附参：1 byte，匹配方式（g|G|\0）。
func _MATCH(code []byte) *Insted { return parseArg1(code) }

// 指令：SUBSTR(2) 字串截取
// 附参：2 bytes，字符数量。
func _SUBSTR(code []byte) *Insted { return parseArg2(code) }

// 指令：REPLACE(1) 字串替换
// 附参：1 byte，替换次数，uint8。0值表示全部。
func _REPLACE(code []byte) *Insted { return parseArg1(code) }

// 指令：CMPFLO(1) 浮点数比较
// 附参：1 byte，比较类型标识（==, <=, >=）。int8 支持负数。
func _CMPFLO(code []byte) *Insted { return parseArg1x(code) }

// 指令：RANGE(2) 创建数值序列
// 附参：2 bytes，序列长度（成员数量）。
func _RANGE(code []byte) *Insted { return parseArg2(code) }

/*
 * 系统指令
 * 单指令： SYS_AWARD SYS_NULL
 ******************************************************************************
 */

// 指令：SYS_TIME{}(1) 取全局时间值
// 附参：1 byte，目标属性的标识值。
func _SYS_TIME(code []byte) *Insted { return parseArg1(code) }

/*
 * 函数指令
 * 单指令：大部分都无附参和关联数据。
 ******************************************************************************
 */

// 指令：FN_CHECKSIG(1) 单签名验证
// 附参：1 byte，哈希算法标识。
func _FN_CHECKSIG(code []byte) *Insted { return parseArg1(code) }

// 指令：FN_MCHECKSIG(1) 多签名验证
// 附参：1 byte，哈希算法标识。
func _FN_MCHECKSIG(code []byte) *Insted { return parseArg1(code) }

// 指令：FN_HASH224(1){} 哈希计算
// 附参：1 byte，哈希算法标识。
func _FN_HASH224(code []byte) *Insted { return parseArg1(code) }

// 指令：FN_HASH256(1){} 哈希计算
// 附参：1 byte，哈希算法标识。
func _FN_HASH256(code []byte) *Insted { return parseArg1(code) }

// 指令：FN_HASH384(1){} 哈希计算
// 附参：1 byte，哈希算法标识。
func _FN_HASH384(code []byte) *Insted { return parseArg1(code) }

// 指令：FN_HASH512(1){} 哈希计算
// 附参：1 byte，哈希算法标识。
func _FN_HASH512(code []byte) *Insted { return parseArg1(code) }

// 指令：FN_X(1){} 函数扩展
// 附参：1 byte，目标索引。
func _FN_X(code []byte) *Insted { return parseArg1(code) }

/*
 * 模块指令
 * 单指令：无。
 ******************************************************************************
 */

// 指令：MO_RE(1){} 正则表达式模块
// 附参：1 byte，成员索引。
func _MO_RE(code []byte) *Insted { return parseArg1(code) }

// 指令：MO_TIME(1){} 时间模块
// 附参：1 byte，成员索引。
func _MO_TIME(code []byte) *Insted { return parseArg1(code) }

// 指令：MO_MATH(1){} 数学运算模块
// 附参：1 byte，成员索引。
func _MO_MATH(code []byte) *Insted { return parseArg1(code) }

// 指令：MO_CRYPT(1){} 加密模块
// 附参：1 byte，成员索引。
func _MO_CRYPT(code []byte) *Insted { return parseArg1(code) }

// 指令：MO_X(1){} 标准扩展引用
// 附参：1 byte，目标索引。
// 数据：附参之后的部分由扩展模块自身定义，视为数据。
func _MO_X(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(ins.Args[0][0])},
		ins.Data,
		ins.Size,
	}
}

/*
 * 扩展指令
 * 单指令：无。
 ******************************************************************************
 */

// 指令：EX_FN(2){} 扩展函数集
// 附参：2 bytes，目标索引。
func _EX_FN(code []byte) *Insted {
	return parseArg2(code)
}

// 指令：EX_INST(2){} 通用扩展集
// 附参：2 bytes，目标索引。
// 注记：
// 扩展的部分自成一体，等待定制（暂时按模块逻辑对待）。
func _EX_INST(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(binary.BigEndian.Uint16(ins.Args[0]))},
		ins.Data,
		ins.Size,
	}
}

// 指令：EX_PRIV(2){} 第三方私有扩展
// 附参：2 bytes，目标索引。
// 注记：
// 私有部分自行负责，这里暂时按直接指令对待。
func _EX_PRIV(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(binary.BigEndian.Uint16(ins.Args[0]))},
		ins.Data,
		ins.Size,
	}
}

//
// 工具函数
///////////////////////////////////////////////////////////////////////////////

// 通用单附参（1）
// 附参：1 byte，正整数。
// 数据：无。
func parseArg1(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(ins.Args[0][0])},
		nil,
		ins.Size,
	}
}

// 通用单附参（1）
// 附参：1 byte，int8 支持负数。
// 数据：无。
func parseArg1x(code []byte) *Insted {
	ins := Raw(code)
	n := int8(ins.Args[0][0])

	return &Insted{ins.Code, []any{int(n)}, nil, ins.Size}
}

// 通用单附参（2）
// 附参：2 bytes，正整数。
// 数据：无。
func parseArg2(code []byte) *Insted {
	ins := Raw(code)
	n := binary.BigEndian.Uint16(ins.Args[0])

	return &Insted{
		ins.Code,
		[]any{int(n)},
		nil,
		ins.Size,
	}
}

// 通用单附参&数据
// 附参：1 byte，数据长度，正整数。
// 数据：字节序列。
// 注记：
// 因栈脚本只读保证，数据引用原始脚本（进阶执行）。
func parseArg1Code(code []byte) *Insted {
	ins := Raw(code)

	return &Insted{
		ins.Code,
		[]any{int(ins.Args[0][0])},
		ins.Data,
		ins.Size,
	}
}

// 通用单附参&数据
// 附参：变长字节，数据长度。
// 数据：字节序列。
// 注记：数据引用原始脚本。
func parseArgXCode(code []byte) *Insted {
	ins := Raw(code)
	n, _ := binary.Uvarint(ins.Args[0])

	return &Insted{ins.Code, []any{int(n)}, ins.Data, ins.Size}
}

//
// 原始字节引用
//-----------------------------------------------------------------------------

// 数据单附参（1）
// 附参：1 byte 数据值。
func instData1(code []byte) *Instor {
	c := int(code[0])
	return &Instor{c, nil, code[1:2], 2}
}

// 数据单附参（4）
// 附参：4 bytes 数据值。
func instData4(code []byte) *Instor {
	c := int(code[0])
	return &Instor{c, nil, code[1:5], 5}
}

// 数据单附参（8）
// 附参：8 bytes 数据值。
func instData8(code []byte) *Instor {
	c := int(code[0])
	return &Instor{c, nil, code[1:9], 9}
}

// 数据单附参（n）
// 附参：n bytes 变长数据值。
func instDataX(code []byte) *Instor {
	c := int(code[0])
	// 仅取字节数 Uvarint/Varint 同
	_, len := binary.Uvarint(code[1:])
	len++
	return &Instor{c, nil, code[1:len], len}
}

// 通用单附参（1）
// 附参：1 byte，正整数。
// 数据：无。
func instArg1(code []byte) *Instor {
	c := int(code[0])
	return &Instor{c, [][]byte{code[1:2]}, nil, 2}
}

// 通用单附参（2）
// 附参：2 bytes，正整数。
// 数据：无。
func instArg2(code []byte) *Instor {
	c := int(code[0])
	return &Instor{c, [][]byte{code[1:3]}, nil, 3}
}

// 单附参(1)&字节数据。
func instArg1Bytes(code []byte) *Instor {
	c := int(code[0])
	n := int(code[1])

	return &Instor{c, [][]byte{code[1:2]}, code[2 : 2+n], 2 + n}
}

// 单附参(2)&字节数据。
func instArg2Bytes(code []byte) *Instor {
	c := int(code[0])
	n := int(binary.BigEndian.Uint16(code[1:3]))

	return &Instor{c, [][]byte{code[1:3]}, code[3 : 3+n], 3 + n}
}

// 单附参（~）&字节数据。
func instArgXBytes(code []byte) *Instor {
	c := int(code[0])
	_n, len := binary.Uvarint(code[1:])
	n := int(_n)
	len++ // for c

	return &Instor{c, [][]byte{code[1:len]}, code[len : len+n], len + n}
}

// MODEL 专项提取。
// 附参：2 bytes，包含取值标记和长度。
// 注：
// 高2位保留，低14位记录长度。
func instModel(code []byte) *Instor {
	c := int(code[0])
	x := binary.BigEndian.Uint16(code[1:3])
	n := int(x &^ 0b1100_0000_0000_0000)

	// 附参依然为原始字节序列。
	return &Instor{c, [][]byte{code[1:3]}, code[3 : 3+n], 3 + n}
}

// 双附参(1+1)和字节数据。
// 附参1：匹配标识（g|G|!）。
// 附参2：双斜线之内的正则式内容长度。
func instArg1_1Bytes(code []byte) *Instor {
	c := int(code[0])
	n := int(code[2])

	return &Instor{c, [][]byte{code[1:2], code[2:3]}, code[3 : 3+n], 3 + n}
}

// 跳转/嵌入指令。
// 附参1：4 bytes, 区块高度。
// 附参2：4 bytes, 交易序位。
// 附参3：2 bytes, 脚本序位。
func instArg4_4_2(code []byte) *Instor {
	c := int(code[0])
	h := code[1:5]
	n := code[5:9]
	i := code[9:11]

	return &Instor{c, [][]byte{h, n, i}, nil, 11}
}

// 指令：!{}(~,~) 整数值范围匹配
// 附参1：下边界值，变长整数，包含。
// 附参2：上边界值，变长整数，不包含。
func withinInt(code []byte) *Instor {
	c := int(code[0])
	_, n1 := binary.Varint(code[1:])
	n1++ // for c
	_, n2 := binary.Varint(code[n1:])

	return &Instor{c, [][]byte{code[1:n1], code[n1 : n1+n2]}, nil, n1 + n2}
}

// 指令：!{}(8,8,4) 浮点数值范围匹配
// 附参1：8 bytes，下边界值，包含。
// 附参2：8 bytes，上边界值，不包含。
// 附参3：4 bytes，下边界相等误差。
func withinFloat(code []byte) *Instor {
	c := int(code[0])
	low := code[1:9]
	up := code[9:17]
	dev := code[17:21]

	return &Instor{c, [][]byte{low, up, dev}, nil, 21}
}

// 脚本输出项取值。
// 附参1：2 bytes，输出项序位。
// 附参2：1 byte，输出项中的成员的标识。
func instArg2_1(code []byte) *Instor {
	c := int(code[0])
	i := code[1:3]
	n := code[3:4]

	return &Instor{c, [][]byte{i, n}, nil, 4}
}

// 获取模块指令原始信息包。
// 附参：1 byte，扩展模块索引。
// 数据：即扩展模块自身定义。
func moxInstor(code []byte) *Instor {
	c := int(code[0])
	n := MoxSize(int(code[1]))
	d := code[2 : 2+n]

	return &Instor{c, [][]byte{code[1:2]}, d, 2 + n}
}

// 获取通用扩展指令原始信息包。
// 附参：2 bytes，扩展目标索引。
// 数据：即扩展指令自身定义。
// 注记：
// 扩展指令默认实现为模块逻辑，但容错直接指令逻辑。
func extenInstor(code []byte) *Instor {
	c := int(code[0])
	i := binary.BigEndian.Uint16(code[1:3])

	var d []byte
	n := ExtSize(int(i))

	if n > 0 {
		d = code[3 : 3+n]
	}
	return &Instor{c, [][]byte{code[1:3]}, d, 3 + n}
}

// 私有扩展指令。
// 附参：2 bytes，扩展目标索引。
// 数据：即扩展指令自身定义。
func privInstor(code []byte) *Instor {
	c := int(code[0])
	i := binary.BigEndian.Uint16(code[1:3])

	var d []byte
	n := PrivSize(int(i))

	if n > 0 {
		d = code[3 : 3+n]
	}
	return &Instor{c, [][]byte{code[1:3]}, d, 3 + n}
}

//
// 私有辅助
//-----------------------------------------------------------------------------

// 从字节存储获取浮点数。
func float64From(code []byte) float64 {
	if len(code) == 4 {
		return float64(
			math.Float32frombits(binary.BigEndian.Uint32(code)),
		)
	}
	return math.Float64frombits(binary.BigEndian.Uint64(code))
}

//
// 初始化
///////////////////////////////////////////////////////////////////////////////

// 指令解析处理器集。
func init() {
	// 值指令
	__Parses[icode.Uint8n] = _Uint8n
	__Parses[icode.Uint8] = _Uint8
	__Parses[icode.Uint63n] = _Uint63n
	__Parses[icode.Uint63] = _Uint63
	__Parses[icode.Byte] = _Byte
	__Parses[icode.Rune] = _Rune
	__Parses[icode.Float32] = _Float32
	__Parses[icode.Float64] = _Float64
	__Parses[icode.DATE] = _DATE
	__Parses[icode.BigInt] = _BigInt
	__Parses[icode.DATA8] = _DATA8
	__Parses[icode.DATA16] = _DATA16
	__Parses[icode.TEXT8] = _TEXT8
	__Parses[icode.TEXT16] = _TEXT16
	__Parses[icode.RegExp] = _RegExp
	__Parses[icode.CODE] = _CODE

	// 截取指令
	__Parses[icode.ScopeVal] = _ScopeVal
	__Parses[icode.LoopVal] = _LoopVal

	// 栈操作指令
	__Parses[icode.SHIFT] = _SHIFT
	__Parses[icode.CLONE] = _CLONE
	__Parses[icode.POPS] = _POPS
	__Parses[icode.TOPS] = _TOPS
	__Parses[icode.PEEKS] = _PEEKS

	// 集合指令
	__Parses[icode.MAP] = _MAP
	__Parses[icode.FILTER] = _FILTER

	// 交互指令
	__Parses[icode.INPUT] = _INPUT
	__Parses[icode.BUFDUMP] = _BUFDUMP

	// 结果指令
	__Parses[icode.GOTO] = _GOTO
	__Parses[icode.JUMP] = _JUMP

	// 流程指令
	__Parses[icode.IF] = _IF
	__Parses[icode.ELSE] = _ELSE
	__Parses[icode.SWITCH] = _SWITCH
	__Parses[icode.CASE] = _CASE
	__Parses[icode.DEFAULT] = _DEFAULT
	__Parses[icode.EACH] = _EACH
	__Parses[icode.BLOCK] = _BLOCK

	// 转换指令
	__Parses[icode.STRING] = _STRING
	__Parses[icode.ANYS] = _ANYS

	// 运算指令
	__Parses[icode.Expr] = _Expr
	__Parses[icode.DUP] = _DUP

	// 逻辑指令
	__Parses[icode.SOME] = _SOME

	// 模式指令
	__Parses[icode.MODEL] = _MODEL
	__Parses[icode.ValPick] = _ValPick
	__Parses[icode.Wildnum] = _Wildnum
	__Parses[icode.Wildpart] = _Wildpart
	__Parses[icode.Wildlist] = _Wildlist
	__Parses[icode.TypeIs] = _TypeIs
	__Parses[icode.WithinInt] = _WithinInt
	__Parses[icode.WithinFloat] = _WithinFloat
	__Parses[icode.RE] = _RE
	__Parses[icode.RePick] = _RePick

	// 环境指令
	__Parses[icode.ENV] = _ENV
	__Parses[icode.OUT] = _OUT
	__Parses[icode.IN] = _IN
	__Parses[icode.INOUT] = _INOUT
	__Parses[icode.XFROM] = _XFROM
	__Parses[icode.VAR] = _VAR
	__Parses[icode.SETVAR] = _SETVAR
	__Parses[icode.SOURCE] = _SOURCE
	__Parses[icode.MULSIG] = _MULSIG

	// 工具指令
	__Parses[icode.KEYVAL] = _KEYVAL
	__Parses[icode.MATCH] = _MATCH
	__Parses[icode.SUBSTR] = _SUBSTR
	__Parses[icode.REPLACE] = _REPLACE
	__Parses[icode.CMPFLO] = _CMPFLO
	__Parses[icode.RANGE] = _RANGE

	// 系统指令
	__Parses[icode.SYS_TIME] = _SYS_TIME

	// 函数指令
	__Parses[icode.FN_CHECKSIG] = _FN_CHECKSIG
	__Parses[icode.FN_MCHECKSIG] = _FN_MCHECKSIG
	__Parses[icode.FN_HASH224] = _FN_HASH224
	__Parses[icode.FN_HASH256] = _FN_HASH256
	__Parses[icode.FN_HASH384] = _FN_HASH384
	__Parses[icode.FN_HASH512] = _FN_HASH512
	__Parses[icode.FN_X] = _FN_X

	// 模块指令
	__Parses[icode.MO_RE] = _MO_RE
	__Parses[icode.MO_TIME] = _MO_TIME
	__Parses[icode.MO_MATH] = _MO_MATH
	__Parses[icode.MO_CRYPT] = _MO_CRYPT
	__Parses[icode.MO_X] = _MO_X

	// 扩展指令
	__Parses[icode.EX_FN] = _EX_FN
	__Parses[icode.EX_INST] = _EX_INST
	__Parses[icode.EX_PRIV] = _EX_PRIV
}

// 指令原始字节提取器集。
func init() {
	// 值指令
	__Pickes[icode.Uint8n] = instData1
	__Pickes[icode.Uint8] = instData1
	__Pickes[icode.Uint63n] = instDataX
	__Pickes[icode.Uint63] = instDataX
	__Pickes[icode.Byte] = instData1
	__Pickes[icode.Rune] = instData4
	__Pickes[icode.Float32] = instData4
	__Pickes[icode.Float64] = instData8
	__Pickes[icode.DATE] = instDataX
	__Pickes[icode.BigInt] = instArg1Bytes
	__Pickes[icode.DATA8] = instArg1Bytes
	__Pickes[icode.DATA16] = instArg2Bytes
	__Pickes[icode.TEXT8] = instArg1Bytes
	__Pickes[icode.TEXT16] = instArg2Bytes
	__Pickes[icode.RegExp] = instArg1Bytes
	__Pickes[icode.CODE] = instArg1Bytes

	// 截取指令
	__Pickes[icode.ScopeVal] = instArg1
	__Pickes[icode.LoopVal] = instArg1

	// 栈操作指令
	__Pickes[icode.SHIFT] = instArg1
	__Pickes[icode.CLONE] = instArg1
	__Pickes[icode.POPS] = instArg1
	__Pickes[icode.TOPS] = instArg1
	__Pickes[icode.PEEKS] = instArg1

	// 集合指令
	__Pickes[icode.MAP] = instArg1Bytes
	__Pickes[icode.FILTER] = instArg1Bytes

	// 交互指令
	__Pickes[icode.INPUT] = instArg1
	__Pickes[icode.BUFDUMP] = instArg1

	// 结果指令
	__Pickes[icode.GOTO] = instArg4_4_2
	__Pickes[icode.JUMP] = instArg4_4_2

	// 流程指令
	__Pickes[icode.IF] = instArg1Bytes
	__Pickes[icode.ELSE] = instArg1Bytes
	__Pickes[icode.SWITCH] = instArgXBytes
	__Pickes[icode.CASE] = instArg1Bytes
	__Pickes[icode.DEFAULT] = instArg1Bytes
	__Pickes[icode.EACH] = instArg1Bytes
	__Pickes[icode.BLOCK] = instArgXBytes

	// 转换指令
	__Pickes[icode.STRING] = instArg1
	__Pickes[icode.ANYS] = instArg1

	// 运算指令
	__Pickes[icode.Expr] = instArg1Bytes
	__Pickes[icode.DUP] = instArg1

	// 逻辑指令
	__Pickes[icode.SOME] = instArg1

	// 模式指令
	__Pickes[icode.MODEL] = instModel
	__Pickes[icode.ValPick] = instArg1
	__Pickes[icode.Wildnum] = instArg1
	__Pickes[icode.Wildpart] = instArg1
	__Pickes[icode.Wildlist] = instArg1
	__Pickes[icode.TypeIs] = instArg1
	__Pickes[icode.WithinInt] = withinInt
	__Pickes[icode.WithinFloat] = withinFloat
	__Pickes[icode.RE] = instArg1_1Bytes
	__Pickes[icode.RePick] = instArg1

	// 环境指令
	__Pickes[icode.ENV] = instArg1
	__Pickes[icode.OUT] = instArg2_1
	__Pickes[icode.IN] = instArg1
	__Pickes[icode.INOUT] = instArg1
	__Pickes[icode.XFROM] = instArg1
	__Pickes[icode.VAR] = instArg1
	__Pickes[icode.SETVAR] = instArg1
	__Pickes[icode.SOURCE] = instArg1
	__Pickes[icode.MULSIG] = instArg1

	// 工具指令
	__Pickes[icode.KEYVAL] = instArg1
	__Pickes[icode.MATCH] = instArg1
	__Pickes[icode.SUBSTR] = instArg2
	__Pickes[icode.REPLACE] = instArg1
	__Pickes[icode.CMPFLO] = instArg1
	__Pickes[icode.RANGE] = instArg2

	// 系统指令
	__Pickes[icode.SYS_TIME] = instArg1

	// 函数指令
	__Pickes[icode.FN_CHECKSIG] = instArg1
	__Pickes[icode.FN_MCHECKSIG] = instArg1
	__Pickes[icode.FN_HASH224] = instArg1
	__Pickes[icode.FN_HASH256] = instArg1
	__Pickes[icode.FN_HASH384] = instArg1
	__Pickes[icode.FN_HASH512] = instArg1
	__Pickes[icode.FN_X] = instArg1

	// 模块指令
	__Pickes[icode.MO_RE] = instArg1
	__Pickes[icode.MO_TIME] = instArg1
	__Pickes[icode.MO_MATH] = instArg1
	__Pickes[icode.MO_CRYPT] = instArg1
	__Pickes[icode.MO_X] = moxInstor

	// 扩展指令
	__Pickes[icode.EX_FN] = instArg2
	__Pickes[icode.EX_INST] = extenInstor
	__Pickes[icode.EX_PRIV] = privInstor
}
