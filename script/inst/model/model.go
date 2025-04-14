// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package model 模式指令的实现。
package model

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"

	"github.com/cxio/suite/cbase"
	"github.com/cxio/suite/cbase/chash"
	"github.com/cxio/suite/locale"
	"github.com/cxio/suite/script/ibase"
	"github.com/cxio/suite/script/icode"
	"github.com/cxio/suite/script/instor"
)

// 函数便捷引用。
var (
	_T = locale.GetText
)

// 基本消息定义。
var (
	neverToHere   = ibase.ErrToHere
	modelMatchBan = _T("模式指令本身不能作为普通指令构造匹配")
	typeBadnum    = _T("类型值定义错误")
)

// 段指令通配错误。
var errLump = fmt.Errorf(_T("段指令通配（...）的目标脚本长度不足"))

const (
	// 默认处理器索引
	defaultIndex = -1

	// 关联数据哈希长度
	HashSize = chash.Size160
)

// 引用：整数类型
type Int = instor.Int

// 引用：浮点数类型
type Float = instor.Float

// 引用：正则表达式
type RegExp = instor.RegExp

// 引用：指令信息包（已解析）
type Insted = instor.Insted

// 引用：指令信息包（原始）
type Instor = instor.Instor

// 创建一个指令的原始信息包。
// 注：明确字段名称指定。
func newInstor(c int, args [][]byte, data []byte, size int) *Instor {
	return &Instor{
		Code: c,
		Args: args,
		Data: data,
		Size: size,
	}
}

// 模式匹配状态
type State struct {
	last    []byte // 源脚本当前片段暂存
	matched []any  // 正则匹配结果暂存（RE{} for &）
	buffer  []any  // 取值存储区
	ver     int    // 版本信息
}

// 当前指令段暂存。
func (s *State) SetLast(b []byte) {
	s.last = b
}

// 获取最近一个匹配指令的长度。
func (s *State) Last() []byte {
	return s.last
}

// 设置匹配结果。
func (s *State) SetMatched(data []any) {
	s.matched = data
}

// 获取匹配结果成员。
// 容错超出范围的检索，返回nil而非抛出异常（宽容）。
func (s *State) Matched(i int) any {
	if i >= len(s.matched) {
		return nil
	}
	return s.matched[i]
}

// 向存储区添加数据。
func (s *State) PushData(data ...any) {
	s.buffer = append(s.buffer, data...)
}

// 获取提取的值集。
func (s *State) Data() []any {
	return s.buffer
}

// 指令取值指示：
// - 0000_0001 	单纯指令码。(1)
// - 0000_0010 	第1个附参。(2)
// - 0000_0100 	第2个附参。(4)
// - 0000_1000 	第3个附参。(8)
// - 0001_0000 	第4个附参。(16)
// - 0010_0000 	第5个附参。(32)
// - 0100_0000 	关联数据。(64)
// - 1000_0000 	完整指令，含附参和关联数据。(128)
type instpick int

// 是否为获取指令码。
func (i instpick) forCode() bool {
	return i&1 != 0
}

// 是否为取值第n个附参。
// 注：从1开始计数。
func (i instpick) forArg(n int) bool {
	return i&(1<<n) != 0
}

// 是否为取关联数据。
func (i instpick) forData() bool {
	return i&0b0100_0000 != 1
}

// 是否为取完整指令。
func (i instpick) withAll() bool {
	return i&0b1000_0000 != 0
}

// 获取标记位序范围。
// 标记位从零位开始计数，高位为上边界（不含）。
// 返回值：低位, 高位界
func (instpick) argBits() (int, int) {
	return 1, 6
}

// 局部通配标识
// 注：模式指令 ?(1)
type wildpart int

// 是否为指令可选（有|无）
// 置位：首位定义（低）。
func (w wildpart) isOption() bool {
	return w&1 != 0
}

// 是否第n个附参通配。
// 注：从1开始计数。
func (w wildpart) wildArg(n int) bool {
	return w&(1<<n) != 0
}

// 是否关联数据通配。
// 置位：第7位定义。
func (w wildpart) wildData() bool {
	return w&0b0100_0000 != 1
}

// 是否采用哈希匹配。
// 置位：高1位定义。
func (w wildpart) inHash() bool {
	return w&0b1000_0000 != 0
}

// 匹配捡取器。
// 从模式区匹配指令中提取指令原始字节信息。
// 规则：
// - 某附参或关联数据通配时，其位即不存在（节省空间）。
// - 如果附参通配，除非哈希匹配模式，否则数据必然通配。
type Matcher func([]byte, wildpart) *Instor

// 捡取器配置集
var __Matches [256]Matcher

// 模式处理器。
// s 为源脚本字节序列。
// m 为模式脚本字节序列。
// 返回值：
// (源脚本指令总长，模式指令总长，匹配成功与否)
type Modeler func(_ *State, s, m []byte) (int, int, bool)

// 模式处理器集。
// 模式区内的各个模式功能指令配置。
var __Process map[int]Modeler

// 类型匹配检查配置。
var __typeChecks = map[int]func(int) bool{
	instor.TypeisBool:   _isBool,
	instor.TypeisInt:    _isInt,
	instor.TypeisByte:   _isByte,
	instor.TypeisRune:   _isRune,
	instor.TypeisBigInt: _isBigInt,
	instor.TypeisFloat:  _isFloat,
	instor.TypeisBytes:  _isBytes,
	instor.TypeisString: _isString,
	instor.TypeisRegExp: _isRegExp,
	instor.TypeisTime:   _isTime,
	instor.TypeisScript: _isScript,
	instor.TypeisNumber: _isNumber,
	instor.TypeisModel:  _isModel,
}

// 指令段匹配测试器。
// m 为模式脚本片段，从 ... 指令之后至下一个 ... 之前为止。
// s 为源脚本片段，从当前位置开始截取。
type lumpTester func(m, s []byte) (int, int, bool)

// 片段通配（...）测试器集。
// 适用 ... 片段比较的定制版。
var __lumpProcess map[int]lumpTester

/*
 * 模式指令（处理器）
 ******************************************************************************
 */

// 指令：#(1) 指令取值
// 附参：1 byte，目标值标识。
func _ValPick(t *State, s, m []byte) (int, int, bool) {
	ins1 := instor.Get(m)
	flag := ins1.Args[0].(int)

	ins0 := instor.Get(t.Last())
	t.PushData(instValue(ins0, instpick(flag))...)

	return 0, ins1.Size, true
}

// 指令：_ 指令通配
// 附参：无。
func _Wildcard(_ *State, s, m []byte) (int, int, bool) {
	ins0 := instor.Raw(s)
	ins1 := instor.Raw(m)
	// 无条件通过
	return ins0.Size, ins1.Size, true
}

// 指令：_(1) 指令段通配
// 附参：1 byte，忽略的指令数量。
func _Wildnum(_ *State, s, m []byte) (int, int, bool) {
	ins1 := instor.Get(m)
	n := ins1.Args[0].(int)

	var size int
	_s := instor.NewScript(s)

	for i := 0; i < n; i++ {
		len := instor.Raw(_s.Bytes()).Size
		_s.Next(len)
		size += len
	}
	return size, ins1.Size, true
}

// 指令：?(1) 指令局部通配
// 附参：1 byte，位置标识。
func _Wildpart(t *State, s, m []byte) (int, int, bool) {
	ins1 := instor.Get(m)
	flag := wildpart(ins1.Args[0].(int))

	// 后阶模式指令
	m = m[ins1.Size:]

	return test(instor.Raw(s), modelInstor(m, flag), flag, t.ver)
}

// 指令：?(1){} 指令序列可选
// 附参：1 byte，指令序列长度。
func _Wildlist(_ *State, s, m []byte) (int, int, bool) {
	ins1 := instor.Get(m)
	size := ins1.Args[0].(int)
	b0 := s[size:]

	if bytes.Equal(b0, ins1.Data.([]byte)) {
		// 一起跳过
		return size, ins1.Size, true
	}
	// 源原地维持
	return 0, ins1.Size, true
}

// 指令：!{Type}(1) 类型匹配
// 附参：1 byte，类型标识值。
func _TypeIs(_ *State, s, m []byte) (int, int, bool) {
	ins1 := instor.Get(m)
	fchk := __typeChecks[ins1.Args[0].(int)]

	if fchk == nil {
		panic(typeBadnum)
	}
	ins0 := instor.Raw(s)

	return ins0.Size, ins1.Size, fchk(ins0.Code)
}

// 指令：!{}(~,~) 整数值范围匹配
// 附参1：下边界值，变长整数，包含。
// 附参2：上边界值，变长整数，不包含。
func _WithinInt(_ *State, s, m []byte) (int, int, bool) {
	ins1 := instor.Get(m)
	low := ins1.Args[0].(Int)
	up := ins1.Args[1].(Int)

	ins0 := instor.Get(s)
	v := ins0.Data.(Int)

	return ins0.Size, ins1.Size, low <= v && v < up
}

// 指令：!{}(8,8,4) 浮点数值范围匹配
// 附参1：下边界值，包含。
// 附参2：上边界值，不包含。
// 附参3：下边界相等误差（不超过视为相等）。
func _WithinFloat(_ *State, s, m []byte) (int, int, bool) {
	ins1 := instor.Get(m)
	a := ins1.Args[0].(Float)
	z := ins1.Args[1].(Float)
	d := ins1.Args[2].(Float)

	ins0 := instor.Get(s)
	v := ins0.Data.(Float)

	return ins0.Size, ins1.Size, (a < v || cbase.FloatEqual(a, v, d)) && v < z
}

// 指令：RE{!/.../gG}(1,1) 正则匹配
// 附参1：1 byte，匹配标识值（g|G|!）。
// 附参2：1 byte，正则匹配式文本的长度。
// 注：
// 附参1高位（1000_0000）标记通关性检查，置标时匹配非空才成功。
func _RE(t *State, s, m []byte) (int, int, bool) {
	ins1 := instor.Get(m)
	fg := ins1.Args[0].(int)
	re := ins1.Data.(*RegExp)

	ins0 := instor.Get(s)
	var data []any

	switch fg &^ 0b1000_0000 {
	case 'g':
		data = cbase.MatchAll(ins0.Data, re)
	case 'G':
		data = cbase.MatchEvery(ins0.Data, re)
	default:
		data = cbase.Match(ins0.Data, re)
	}
	t.SetMatched(data)

	// 无通关性标记时空匹配也为成功。
	return ins0.Size, ins1.Size, fg&0b1000_0000 == 0 || len(data) > 0
}

// 指令：&(1) 正则匹配取值
// 附参：1 byte，正则匹配的取值序位。
func _RePick(t *State, s, m []byte) (int, int, bool) {
	ins1 := instor.Get(m)
	i := ins1.Args[0].(int)
	t.PushData(t.Matched(i))

	return 0, ins1.Size, true
}

// 指令：... 指令序列段通配（同级）
// 附参：无。
func _WildLump(_ *State, s, m []byte) (int, int, bool) {
	size, ok := lumpAll(
		lumpBytes(m),
		s,
	)
	return size, instor.Raw(m).Size, ok
}

// 模式区其它普通指令默认比较。
func _Default(t *State, s, m []byte) (int, int, bool) {
	return test(instor.Raw(s), instor.Raw(m), 0, t.ver)
}

// 结构块指令的递进处理。
// 代码块作为一个独立的脚本片段被匹配测试，
// 这使得跨层级的取值和段通配不可行（有意的隔离）。
func _BlockCheck(t *State, s, m []byte) (int, int, bool) {
	ins0 := instor.Raw(s)
	ins1 := instor.Raw(m)
	var ok bool
	var data []any

	if ins0.Code == ins1.Code {
		data, ok = Check(ins0.Data, ins1.Data, t.ver)
		t.PushData(data...)
	}
	return ins0.Size, ins1.Size, ok
}

/*
 * ... 模式比较定制
 * 用于 ... 指令序列段匹配，支持模式能力但无需执行某些功能（如取值）。
 ******************************************************************************
 */

// 指令：#(1) 指令取值
// 附参：1 byte，目标值标识。
// 处理：简单跳过忽略。
func _lumpValPick(m, _ []byte) (int, int, bool) {
	ins := instor.Raw(m)
	return 0, ins.Size, true
}

// 指令：_ 指令通配
// 附参：无。
// 处理：正常执行任意匹配。
func _lumpWildcard(m, s []byte) (int, int, bool) {
	return _Wildcard(nil, s, m)
}

// 指令：_(1) 指令段通配
// 附参：1 byte，忽略的指令数量。
// 处理：正常执行目标通配。
func _lumpWildnum(m, s []byte) (int, int, bool) {
	return _Wildnum(nil, s, m)
}

// 指令：?(1) 指令局部通配
// 附参：1 byte，位置标识。
// 处理：正常执行局部通配匹配。
func _lumpWildpart(m, s []byte) (int, int, bool) {
	return _Wildpart(nil, s, m)
}

// 指令：?(1){} 指令序列可选
// 附参：1 byte，指令序列长度。
// 处理：正常执行序列可选。
func _lumpWildlist(m, s []byte) (int, int, bool) {
	return _Wildlist(nil, s, m)
}

// 指令：!{Type}(1) 类型匹配
// 附参：1 byte，类型标识值。
// 处理：正常执行类型匹配。
func _lumpTypeIs(m, s []byte) (int, int, bool) {
	return _TypeIs(nil, s, m)
}

// 指令：!{}(~,~) 整数值范围匹配
// 附参1：下边界值，变长整数，包含。
// 附参2：上边界值，变长整数，不包含。
// 处理：正常执行范围测试。
func _lumpWithinInt(m, s []byte) (int, int, bool) {
	return _WithinInt(nil, s, m)
}

// 指令：!{}(8,8) 浮点数值范围匹配
// 附参1：下边界值，包含。
// 附参2：上边界值，不包含。
// 处理：正常执行范围测试。
func _lumpWithinFloat(m, s []byte) (int, int, bool) {
	return _WithinFloat(nil, s, m)
}

// 指令：RE{!/.../gG}(1,1) 正则匹配
// 附参1：1 byte，匹配标识值（g|G）。
// 附参2：1 byte，正则匹配式文本的长度。
// 处理：
// 附参1高位置标通关检查位，如果置标则匹配测试，否则简单通配（同 _）。
// 注：匹配结果无需保存。
func _lumpRE(m, s []byte) (int, int, bool) {
	ins1 := instor.Raw(m)
	fg := ins1.Args[0][0]

	if fg&0b1000_0000 == 0 {
		// 任意跳过，
		// 目标合法性待正式匹配时处理。
		return instor.Raw(s).Size, ins1.Size, true
	}
	re := regexp.MustCompile(string(ins1.Data))
	ins0 := instor.Get(s)
	var data []any

	switch fg &^ 0b1000_0000 {
	case 'g':
		data = cbase.MatchAll(ins0.Data, re)
	case 'G':
		data = cbase.MatchEvery(ins0.Data, re)
	default:
		data = cbase.Match(ins0.Data, re)
	}
	// 匹配必须有结果。
	return ins0.Size, ins1.Size, len(data) > 0
}

// 指令：&(1) 正则匹配取值
// 附参：1 byte，正则匹配的取值序位。
// 处理：简单跳过忽略。
func _lumpRePick(m, _ []byte) (int, int, bool) {
	ins1 := instor.Raw(m)
	return 0, ins1.Size, true
}

// 指令：... 指令序列段通配（同级）
// 附参：无。
// 注记：
// 段通配测试中递进处理的子块内依然可能存在 ...，此时会抵达至此。
// 但处理逻辑与正常的 _WildLump 相同。
func _lumpWildLump(m, s []byte) (int, int, bool) {
	return _WildLump(nil, s, m)
}

// 模式区其它普通指令默认比较。
// 处理：同正常处理。
func _lumpDefault(m, s []byte) (int, int, bool) {
	return _Default(nil, s, m)
}

// 结构块指令的片段通配。
// 注：递进入内部独立适配。
func _lumpBlockCheck(m, s []byte) (int, int, bool) {
	ins0 := instor.Raw(s)
	ins1 := instor.Raw(m)

	return ins0.Size, ins1.Size, ins0.Code == ins1.Code && lumpBlockTest(ins0.Data, ins1.Data)
}

/*
 * 值类型判断
 * for !{Type}(1)
 * 参数：
 * c 为目标源脚本指令的指令码。
 ******************************************************************************
 */

func _isBool(c int) bool {
	return c == icode.TRUE || c == icode.FALSE
}

func _isInt(c int) bool {
	return icode.Uint8n <= c && c <= icode.Uint63
}

func _isByte(c int) bool {
	return c == icode.Byte
}

func _isRune(c int) bool {
	return c == icode.Rune
}

func _isBigInt(c int) bool {
	return c == icode.BigInt
}

func _isFloat(c int) bool {
	return c == icode.Float32 || c == icode.Float64
}

func _isBytes(c int) bool {
	return c == icode.DATA8 || c == icode.DATA16
}

func _isString(c int) bool {
	return c == icode.TEXT8 || c == icode.TEXT16
}

func _isRegExp(c int) bool {
	return c == icode.RegExp
}

func _isTime(c int) bool {
	return c == icode.DATE
}

func _isScript(c int) bool {
	return c == icode.CODE
}

func _isNumber(c int) bool {
	return _isInt(c) || _isFloat(c)
}

func _isModel(c int) bool {
	return c == icode.MODEL
}

//
// 工具函数
///////////////////////////////////////////////////////////////////////////////

// 获取模式测试器。
// k 为测试器的存储位置键（指令码）。
func modeler(k int) Modeler {
	chk := __Process[k]

	if chk != nil {
		return chk
	}
	return __Process[defaultIndex]
}

// 获取段通配测试器。
// k 为测试器的存储位置键（指令码）。
func tester(k int) lumpTester {
	chk := __lumpProcess[k]

	if chk != nil {
		return chk
	}
	return __lumpProcess[defaultIndex]
}

// 模式匹配校验。
// 返回值：（取值集, 是否匹配成功）
func Check(s, m []byte, ver int) ([]any, bool) {
	_s := instor.NewScript(s)
	_m := instor.NewScript(m)
	_t := &State{ver: ver}

	for !_m.End() {
		c := _m.Code()
		s := _s.Bytes()
		m := _m.Bytes()
		n1, n2, ok := modeler(c)(_t, s, m)

		_s.Next(n1)
		_m.Next(n2)

		if !ok || _s.End() {
			return _t.Data(), ok && _m.End()
		}
		// 前阶暂存。
		_t.SetLast(s)
	}
	// 需完整结束。
	return _t.Data(), _s.End()
}

// 结构块内容的段通配测试。
func lumpBlockTest(s, m []byte) bool {
	_s := instor.NewScript(s)
	_m := instor.NewScript(m)

	for !_m.End() {
		c := _m.Code()
		n1, n2, ok := tester(c)(_m.Bytes(), _s.Bytes())

		_s.Next(n1)
		_m.Next(n2)

		if !ok || _s.End() {
			return ok && _m.End()
		}
	}
	return _s.End() // 完整结束
}

// 段通配测试（单轮）。
// 抛出异常时，表示整个匹配测试应当终止。
func lumpOne(m, s []byte) bool {
	// offset: 0
	_m := instor.NewScript(m)
	_s := instor.NewScript(s)

	for !_m.End() {
		fn := tester(_m.Code())
		n1, n2, ok := fn(_m.Bytes(), _s.Bytes())

		_s.Next(n1)
		_m.Next(n2)

		// 需先做长度检查。
		if _s.End() {
			if ok && _m.End() {
				break
			}
			// 源更短，不可持续。
			// 源等长，但不匹配（可结束）。
			panic(errLump)
		}
		if !ok {
			return false
		}
	}
	return true
}

// 段通配测试（轮询）。
// m 为模式序列，从...之后至下一个...（或末尾）之前的指令段。
// s 为目标源脚本片段，从当前位置开始之后全部。
// 返回值：（跨源段长度，成功与否）
func lumpAll(m, s []byte) (size int, ok bool) {
	defer func() {
		switch e := recover(); e {
		case nil:
		case errLump:
			size = 0
			ok = false
		default:
			panic(e)
		}
	}()
	for !lumpOne(m, s) {
		n := instor.Raw(s).Size
		s = s[n:]
		size += n
	}
	return size, true
}

// 获取模式脚本指令信息包。
// code 为模式脚本片段（从当前位置开始）。
// flag 为局部通配指令标识。
func modelInstor(code []byte, flag wildpart) *Instor {
	n := int(code[0])
	f := __Matches[n]

	if f != nil {
		return f(code, flag)
	}
	// 单指令通用构造。
	return newInstor(n, nil, nil, 1)
}

// 获取哈希匹配时的指令码信息包。
// code 为从指令开始的脚本片段。
// 注意：
// 仅适用单个附参定义数据或子块长度的指令。
// 因为用哈希对比，这里的单附参本身被忽略（标准行为）。
func hashData(code []byte) *Instor {
	c := int(code[0])
	len := HashSize + 1

	return newInstor(c, nil, code[1:len], len)
}

// 通用匹配测试。
// a 为源脚本的指令信息包。
// z 为模式指令的信息包。
// flag 为局部通配标识（适用 ?(1) 指令）。
// ver 为版本信息。
func test(a, z *Instor, flag wildpart, ver int) (int, int, bool) {
	if a.Code != z.Code {
		return 0, z.Size, flag.isOption()
	}
	// 指令相同时，可选不排除比较。
	return a.Size, z.Size, argsEqual(a.Args, z.Args) && dataEqual(a.Data, z.Data, flag.inHash(), ver)
}

// 附参集相等比较。
// aa 为源脚本指令的附参序列，nil 表示没有附参。
// zz 为当前匹配要求（目标），nil 表示没有附参或全部附参通配。
// 注：
// 两个实参的长度一样，这由调用者保证。
// 约定：
// 如果target附参序列为nil，表示附参整体忽略。
// 如果target里的附参成员为nil，表示该附参被通配忽略。
// 注记：
// 附参值都是可直接比较的类型。
func argsEqual(aa, zz [][]byte) bool {
	if zz == nil {
		return true
	}
	for i := range aa {
		if !argEqual(aa[i], zz[i]) {
			return false
		}
	}
	return true
}

// 附参比较。
// a 为源脚本中指令的附参项。
// z 为匹配脚本中指令的附参项，nil 表示通配。
// 注：
// 附参字节片长度一样，这由同一指令的解析逻辑保证。
func argEqual(a, z []byte) bool {
	if z == nil {
		return true
	}
	if len(z) == 1 {
		return a[0] == z[0]
	}
	return bytes.Equal(a, z)
}

// 关联数据相等比较。
// target 为目标源脚本指令的关联数据。
// script 为当前匹配要求，nil 表示忽略（通配）。
// hash 是否为哈希比较。
// ver 为版本信息。
func dataEqual(target, script []byte, hash bool, ver int) bool {
	if script == nil {
		return true
	}
	if hash {
		target = chash.Sum160(ver, target)
	}
	return bytes.Equal(script, target)
}

// 获取指令信息。
// 外部定义的附参置位不可超出指令拥有的附参数量。
// 当取多个部分时，各成员组成为一个切片返回。
// 当取完整指令时，返回3成员切片。其中附参和数据可能为nil。
// 注记：
// 返回值会被自动展开存放。
func instValue(x *Insted, flag instpick) []any {
	// 取完整指令
	if flag.withAll() {
		return []any{x.Code, x.Args, x.Data}
	}
	var buf []any

	if flag.forCode() {
		buf = append(buf, x.Code)
	}
	a, z := flag.argBits()

	for i := 0; i < z-a; i++ {
		if flag.forArg(a) {
			buf = append(buf, x.Args[i])
		}
		a++
	}
	if flag.forData() {
		buf = append(buf, x.Data)
	}
	return buf
}

// 提取 指令段匹配（...）跟随指令序列。
// m 起始于当前 ... 指令位置之后。
// 范围截止于下一个...之前或到达末尾（如果没有下一个...）。
func lumpBytes(m []byte) []byte {
	var size int
	tmp := m

	for len(tmp) > 0 {
		ins := instor.Raw(tmp)
		if ins.Code == icode.WildLump {
			break
		}
		size += ins.Size
		tmp = tmp[ins.Size:]
	}
	return m[:size]
}

//
// 指令信息提取
// 仅分解出原始字节或字节序列。
//-----------------------------------------------------------------------------

// 数据单附参（1）
// 附参：1 byte 数据值。
// 注记：
// 附参和数据为同一目标，因此兼容附参或数据任一通配。
// 支持哈希匹配目标数据，这可以提供隐藏匹配目标的能力（通常没必要）。
// 下同。
func instData1(code []byte, flag wildpart) *Instor {
	if flag.inHash() {
		return hashData(code)
	}
	var v []byte
	size := 1

	if !flag.wildData() && !flag.wildArg(1) {
		size++
		v = code[1:2]
	}
	return newInstor(int(code[0]), nil, v, size)
}

// 数据单附参（2）
// 附参：2 bytes 数据值。
func instData2(code []byte, flag wildpart) *Instor {
	if flag.inHash() {
		return hashData(code)
	}
	var v []byte
	size := 1

	if !flag.wildData() && !flag.wildArg(1) {
		size += 2
		v = code[1:size]
	}
	return newInstor(int(code[0]), nil, v, size)
}

// 数据单附参（4）
// 附参：4 bytes 数据值。
func instData4(code []byte, flag wildpart) *Instor {
	if flag.inHash() {
		return hashData(code)
	}
	var v []byte
	size := 1

	if !flag.wildData() && !flag.wildArg(1) {
		size += 4
		v = code[1:size]
	}
	return newInstor(int(code[0]), nil, v, size)
}

// 数据单附参（8）
// 附参：8 bytes 数据值。
func instData8(code []byte, flag wildpart) *Instor {
	if flag.inHash() {
		return hashData(code)
	}
	var v []byte
	size := 1

	if !flag.wildData() && !flag.wildArg(1) {
		size += 8
		v = code[1:size]
	}
	return newInstor(int(code[0]), nil, v, size)
}

// 数据单附参（n）
// 附参：n bytes 变长整数值。
func instDataX(code []byte, flag wildpart) *Instor {
	if flag.inHash() {
		return hashData(code)
	}
	var v []byte
	size := 1

	if !flag.wildData() && !flag.wildArg(1) {
		// 仅取字节数 Uvarint/Varint 同
		_, n := binary.Uvarint(code[1:])
		size += n
		v = code[1:size]
	}
	return newInstor(int(code[0]), nil, v, size)
}

// 通用单附参（1）
// 附参：1 byte。
// 数据：无。
func instArg1(code []byte, flag wildpart) *Instor {
	var a []byte
	size := 1

	if !flag.wildArg(1) {
		a = code[1:2]
		size++
	}
	return newInstor(int(code[0]), [][]byte{a}, nil, size)
}

// 通用单附参（2）
// 附参：2 bytes。
// 数据：无。
func instArg2(code []byte, flag wildpart) *Instor {
	var a []byte
	size := 1

	if !flag.wildArg(1) {
		a = code[1:3]
		size += 2
	}
	return newInstor(int(code[0]), [][]byte{a}, nil, size)
}

// 通用单附参+数据。
// 附参：1 byte，数据长度。
// 注：
// 附参决定了数据，附参和数据为递进关系。
// 数据可独立通配。
// 下同。
func instArg1Bytes(code []byte, flag wildpart) *Instor {
	if flag.inHash() {
		return hashData(code)
	}
	var a, v []byte
	size := 1

	if !flag.wildArg(1) {
		n := int(code[1])
		size++

		if !flag.wildData() {
			v = code[size : size+n]
			size += n
		}
		a = code[1:2]
	}
	return newInstor(int(code[0]), [][]byte{a}, v, size)
}

// 通用单附参（2）+数据。
// 附参：2 byte，数据长度。
func instArg2Bytes(code []byte, flag wildpart) *Instor {
	if flag.inHash() {
		return hashData(code)
	}
	var a, v []byte
	size := 1

	if !flag.wildArg(1) {
		n := int(binary.BigEndian.Uint16(code[1:]))
		size += 2

		if !flag.wildData() {
			v = code[size : size+n]
			size += n
		}
		a = code[1:3]
	}
	return newInstor(int(code[0]), [][]byte{a}, v, size)
}

// 通用单附参（~）+数据。
// 附参：变长字节数，数据长度。
func instArgXBytes(code []byte, flag wildpart) *Instor {
	if flag.inHash() {
		return hashData(code)
	}
	var a, v []byte
	size := 1

	if !flag.wildArg(1) {
		n, len := binary.Uvarint(code[1:])
		size += len

		if !flag.wildData() {
			v = code[size : size+int(n)]
			size += int(n)
		}
		a = code[1 : 1+len]
	}
	return newInstor(int(code[0]), [][]byte{a}, v, size)
}

// 模式指令专项构造。
// 无条件忽略内部的模式指令段，即附参&内容通配，但支持哈希模式匹配。
// func instModel(code []byte, flag wildpart) *Instor {
// 	if flag.inHash() {
// 		return hashData(code)
// 	}
// 	return newInstor(int(code[0]), nil, nil, 1)
// }
// 后记：
// 需支持内容的全等匹配，故此取消。

// 跳转/嵌入指令。
// 各通配位附参维持初始nil值以表达通配。
// 附参1：4 bytes, 区块高度。
// 附参2：4 bytes, 交易序位。
// 附参3：2 bytes, 输出偏移。
func instArg4_4_2(code []byte, flag wildpart) *Instor {
	var buf [3][]byte
	len := 1

	if !flag.wildArg(1) {
		buf[0] = code[len : len+4]
		len += 4
	}
	if !flag.wildArg(2) {
		buf[1] = code[len : len+4]
		len += 4
	}
	if !flag.wildArg(3) {
		buf[2] = code[len : len+2]
		len += 2
	}
	return newInstor(int(code[0]), buf[:], nil, len)
}

// 脚本输出项取值。
// 附参1：2 bytes，输出项序位。
// 附参2：1 byte，输出项中的成员的标识。
func instArg2_1(code []byte, flag wildpart) *Instor {
	var buf [2][]byte
	len := 1

	if !flag.wildArg(1) {
		buf[0] = code[len : len+2]
		len += 2
	}
	if !flag.wildArg(2) {
		buf[1] = code[len : len+1]
		len++
	}
	return newInstor(int(code[0]), buf[:], nil, len)
}

// 自由扩展类指令定制（1）。
// 附参：1 byte，扩展目标索引。
// 数据：扩展目标自身作为数据，长度未知（由实现决定）。
// 注：
// 数据只是扩展目标定义，不支持哈希匹配。
func instExten1(code []byte, flag wildpart) *Instor {
	var a, v []byte
	size := 1

	if !flag.wildArg(1) {
		size++

		if !flag.wildData() {
			ins := instor.Raw(code)
			v = ins.Data
			size = ins.Size
		}
		a = code[1:2]
	}
	return newInstor(int(code[0]), [][]byte{a}, v, size)
}

// 自由扩展类指令定制（2）。
// 附参：2 bytes，扩展目标索引。
// 数据：扩展目标自身作为数据，长度未知（由实现决定）。
// 注：
// 数据只是扩展目标定义，不支持哈希匹配。
func instExten2(code []byte, flag wildpart) *Instor {
	var a, v []byte
	size := 1

	if !flag.wildArg(1) {
		size += 2

		if !flag.wildData() {
			ins := instor.Raw(code)
			v = ins.Data
			size = ins.Size
		}
		a = code[1:3]
	}
	return newInstor(int(code[0]), [][]byte{a}, v, size)
}

// 模式区内模式指令禁止作为普通指令构造。
// 即：模式指令不能被其它模式指令修饰（flag 通配构造）。
func modelPanic(_ []byte, flag wildpart) *Instor {
	panic(modelMatchBan)
}

//
// 初始化：
// 按指令值对应下标赋值调用器。
///////////////////////////////////////////////////////////////////////////////

// 模式处理器
func init() {
	__Process[icode.ValPick] = _ValPick
	__Process[icode.Wildcard] = _Wildcard
	__Process[icode.Wildnum] = _Wildnum
	__Process[icode.Wildpart] = _Wildpart
	__Process[icode.Wildlist] = _Wildlist
	__Process[icode.TypeIs] = _TypeIs
	__Process[icode.WithinInt] = _WithinInt
	__Process[icode.WithinFloat] = _WithinFloat
	__Process[icode.RE] = _RE
	__Process[icode.RePick] = _RePick
	__Process[icode.WildLump] = _WildLump
	__Process[defaultIndex] = _Default

	// 结构块处理（不含 MODEL）
	// 注：MODEL 内容视为普通字节数据。
	__Process[icode.MAP] = _BlockCheck
	__Process[icode.FILTER] = _BlockCheck
	__Process[icode.IF] = _BlockCheck
	__Process[icode.ELSE] = _BlockCheck
	__Process[icode.SWITCH] = _BlockCheck
	__Process[icode.CASE] = _BlockCheck
	__Process[icode.DEFAULT] = _BlockCheck
	__Process[icode.EACH] = _BlockCheck
	__Process[icode.BLOCK] = _BlockCheck
	__Process[icode.Expr] = _BlockCheck
}

// 模式定制处理器（适用 ...）
func init() {
	__lumpProcess[icode.ValPick] = _lumpValPick
	__lumpProcess[icode.Wildcard] = _lumpWildcard
	__lumpProcess[icode.Wildnum] = _lumpWildnum
	__lumpProcess[icode.Wildpart] = _lumpWildpart
	__lumpProcess[icode.Wildlist] = _lumpWildlist
	__lumpProcess[icode.TypeIs] = _lumpTypeIs
	__lumpProcess[icode.WithinInt] = _lumpWithinInt
	__lumpProcess[icode.WithinFloat] = _lumpWithinFloat
	__lumpProcess[icode.RE] = _lumpRE
	__lumpProcess[icode.RePick] = _lumpRePick
	__lumpProcess[icode.WildLump] = _lumpWildLump
	__lumpProcess[defaultIndex] = _lumpDefault

	// 结构块处理（不含 MODEL）
	__lumpProcess[icode.MAP] = _lumpBlockCheck
	__lumpProcess[icode.FILTER] = _lumpBlockCheck
	__lumpProcess[icode.IF] = _lumpBlockCheck
	__lumpProcess[icode.ELSE] = _lumpBlockCheck
	__lumpProcess[icode.SWITCH] = _lumpBlockCheck
	__lumpProcess[icode.CASE] = _lumpBlockCheck
	__lumpProcess[icode.DEFAULT] = _lumpBlockCheck
	__lumpProcess[icode.EACH] = _lumpBlockCheck
	__lumpProcess[icode.BLOCK] = _lumpBlockCheck
	__lumpProcess[icode.Expr] = _lumpBlockCheck
}

// 捡取器配置集。
func init() {
	// 值指令
	__Matches[icode.Uint8n] = instData1
	__Matches[icode.Uint8] = instData1
	__Matches[icode.Uint63n] = instDataX
	__Matches[icode.Uint63] = instDataX
	__Matches[icode.Byte] = instData1
	__Matches[icode.Rune] = instData4
	__Matches[icode.Float32] = instData4
	__Matches[icode.Float64] = instData8
	__Matches[icode.DATE] = instDataX
	__Matches[icode.BigInt] = instArg1Bytes
	__Matches[icode.DATA8] = instArg1Bytes
	__Matches[icode.DATA16] = instArg2Bytes
	__Matches[icode.TEXT8] = instArg1Bytes
	__Matches[icode.TEXT16] = instArg2Bytes
	__Matches[icode.RegExp] = instArg1Bytes
	__Matches[icode.CODE] = instArg1Bytes

	// 截取指令
	__Matches[icode.ScopeVal] = instArg1
	__Matches[icode.LoopVal] = instArg1

	// 栈操作指令
	__Matches[icode.SHIFT] = instArg1
	__Matches[icode.CLONE] = instArg1
	__Matches[icode.POPS] = instArg1
	__Matches[icode.TOPS] = instArg1
	__Matches[icode.PEEKS] = instArg1

	// 集合指令
	__Matches[icode.MAP] = instArg1Bytes
	__Matches[icode.FILTER] = instArg1Bytes

	// 交互指令
	__Matches[icode.INPUT] = instArg1
	__Matches[icode.BUFDUMP] = instArg1

	// 结果指令
	__Matches[icode.GOTO] = instArg4_4_2
	__Matches[icode.JUMP] = instArg4_4_2

	// 流程指令
	__Matches[icode.IF] = instArg1Bytes
	__Matches[icode.ELSE] = instArg1Bytes
	__Matches[icode.SWITCH] = instArgXBytes
	__Matches[icode.CASE] = instArg1Bytes
	__Matches[icode.DEFAULT] = instArg1Bytes
	__Matches[icode.EACH] = instArg1Bytes
	__Matches[icode.BLOCK] = instArgXBytes

	// 转换指令
	__Matches[icode.STRING] = instArg1
	__Matches[icode.ANYS] = instArg1

	// 运算指令
	__Matches[icode.Expr] = instArg1Bytes
	__Matches[icode.DUP] = instArg1

	// 逻辑指令
	__Matches[icode.SOME] = instArg1

	// 模式指令
	__Matches[icode.MODEL] = instArg2Bytes
	__Matches[icode.ValPick] = modelPanic
	__Matches[icode.Wildcard] = modelPanic
	__Matches[icode.Wildnum] = modelPanic
	__Matches[icode.Wildpart] = modelPanic
	__Matches[icode.Wildlist] = modelPanic
	__Matches[icode.TypeIs] = modelPanic
	__Matches[icode.WithinInt] = modelPanic
	__Matches[icode.WithinFloat] = modelPanic
	__Matches[icode.RE] = modelPanic
	__Matches[icode.RePick] = modelPanic
	__Matches[icode.WildLump] = modelPanic

	// 环境指令
	__Matches[icode.ENV] = instArg1
	__Matches[icode.OUT] = instArg2_1
	__Matches[icode.IN] = instArg1
	__Matches[icode.INOUT] = instArg1
	__Matches[icode.XFROM] = instArg1
	__Matches[icode.VAR] = instArg1
	__Matches[icode.SETVAR] = instArg1
	__Matches[icode.SOURCE] = instArg1
	__Matches[icode.MULSIG] = instArg1

	// 工具指令
	__Matches[icode.KEYVAL] = instArg1
	__Matches[icode.MATCH] = instArg1
	__Matches[icode.SUBSTR] = instArg2
	__Matches[icode.REPLACE] = instArg1
	__Matches[icode.CMPFLO] = instArg1
	__Matches[icode.RANGE] = instArg2

	// 系统指令
	__Matches[icode.SYS_TIME] = instArg1

	// 函数指令
	__Matches[icode.FN_CHECKSIG] = instArg1
	__Matches[icode.FN_MCHECKSIG] = instArg1
	__Matches[icode.FN_HASH224] = instArg1
	__Matches[icode.FN_HASH256] = instArg1
	__Matches[icode.FN_HASH384] = instArg1
	__Matches[icode.FN_HASH512] = instArg1
	__Matches[icode.FN_X] = instArg1

	// 模块指令
	__Matches[icode.MO_RE] = instArg1
	__Matches[icode.MO_TIME] = instArg1
	__Matches[icode.MO_MATH] = instArg1
	__Matches[icode.MO_CRYPT] = instArg1
	__Matches[icode.MO_X] = instExten1

	// 扩展指令
	__Matches[icode.EX_FN] = instArg2
	__Matches[icode.EX_INST] = instExten2
	__Matches[icode.EX_PRIV] = instExten2
}
