// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package ibase 脚本指令集处理基础性支持。
// 提炼出公共的部分，供不同子包使用（避免循环依赖）。
package ibase

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cxio/suite/cbase/paddr"
	"github.com/cxio/suite/locale"
	"github.com/cxio/suite/script/instor"
	"golang.org/x/tools/container/intsets"
)

// 便捷引用。
var (
	_T        = locale.GetText   // 本地化文本获取。
	newScript = instor.NewScript // 脚本对象创建
)

var (
	ErrToHere = errors.New(_T("执行流不可能抵达这里，请检查源码"))
)

// 基本限制配置。
const (
	ScopeMax = 128 // 局部域大小
	StackMax = 256 // 数据栈大小
	GotoMax  = 3   // 跳转次数限额（包含）
	JumpMax  = 9   // 嵌入次数限额（包含）
	ExprEnd  = -1  // 表达式结束标志
)

// 3个存值区标识值。
const (
	StackFlag int = iota // 数据栈（默认）
	ArgsFlag             // 实参空间
	ScopeFlag            // 当前局部域
)

// 提示信息定义。
var (
	jumpsOver  = errors.New(_T("JUMP 嵌入次数超出上限"))
	gotosOver  = errors.New(_T("GOTO 跳转次数超出上限"))
	argsAmount = errors.New(_T("实参区数据量与指令需求不匹配"))
)

// 脚本类型
type Script = instor.Script

// 多重签名序位集。
// 注：用于 MULSIG 指令。
type SigIdSet = intsets.Sparse

// 公钥类型引用。
type PubKey = ed25519.PublicKey

// 中间数据体
// 脚本内数据（缓存）和外部世界的中间媒介。
type Middler struct {
	ID   []byte // 脚本标识ID
	N    int    // 转出指令（BUFDUMP）序位
	Code []byte // 脚本源码副本
	Data []any  // 导出数据
}

// 系统环境封装。
// - 缓存环境指令需要的数据，惰性载入。
// - 设置环境基础条件。
type Envs struct {
	env     map[int]any   // ENV
	outs    []map[int]any // OUTs
	in      map[int]any   // IN
	inout   map[int]any   // INOUT
	mulSigs *SigIdSet     // MULSIG
	pkaddr  []byte        // 公钥地址
}

// 创建一个环境对象。
// 初始化内部存储空间，部分成员默认值即可。
// size 为当前交易输出集大小。
// 注记：
// 简单数据初始即赋值，复杂数据惰性处理。
func NewEnvs(pkaddr []byte, size int) *Envs {
	return &Envs{
		env:    make(map[int]any),
		outs:   make([]map[int]any, size),
		in:     make(map[int]any),
		inout:  make(map[int]any),
		pkaddr: pkaddr,
	}
}

// 获取公钥地址。
func (e *Envs) PubKeyAddr() []byte {
	return e.pkaddr
}

// 环境变量条目获取。
// n 为条目标识值（0-255）。
// 注：条目值惰性获取。
func (e *Envs) EnvItem(n int) any {
	v, ok := e.env[n]
	if ok {
		return v
	}
	// 未完待续
	// 即时调用系统接口获取
	// e.env[n] = v
	return v
}

// 获取交易输出信息。
// i 为输出脚本序位（从0开始）。
// n 为输出项成员标识值。
// 注：条目值惰性获取。
func (e *Envs) TxOutItem(i, n int) any {
	out := e.outs[i]

	if out == nil {
		out = make(map[int]any)
		e.outs[i] = out
	}
	v, ok := out[n]
	if ok {
		return v
	}
	// 未完待续
	// 即时调用系统接口获取
	// outs[n] = v
	return v
}

// 获取交易输入信息。
// n 为输入项成员标识值。
// 注：条目值惰性获取。
func (e *Envs) TxInItem(n int) any {
	v, ok := e.in[n]
	if ok {
		return v
	}
	// 未完待续
	// 即时调用系统接口获取
	// e.in[n] = v
	return v
}

// 获取交易输入的源输出项信息。
// n 为输出项成员标识值。
// 注：条目值惰性获取。
func (e *Envs) TxInOutItem(n int) any {
	v, ok := e.inout[n]
	if ok {
		return v
	}
	// 未完待续
	// 即时调用系统接口获取
	// e.inout[n] = v
	return v
}

// 设置多重签名序位。
// ns 签名的公钥地址在多重公钥列表中的序位集。
// 注：
// 不同的签名集各自独立，因此每次都会新建一个存储集。
func (e *Envs) SetMulSig(ns ...int) {
	e.mulSigs = new(SigIdSet)

	for _, n := range ns {
		e.mulSigs.Insert(n)
	}
}

// 检查目标序位是否签名。
func (e *Envs) MulSigN(n int) bool {
	return e.mulSigs.Has(n)
}

// GOTO 进入。
func (e *Envs) GotoIn() {
	e.env[instor.EnvInGoto] = true
}

// JUMP 进入。
func (e *Envs) JumpIn() {
	e.env[instor.EnvInJump] = true
}

/*
 * 指令调用器。
 * 封装实际指令的各自的功能。
 * 外部传递指令的附参、关联数据和所需的实参，执行指令调用。
 * Actuator:
 * 	脚本执行器，提供独立的共享区（友好并发），记录一些状态供各指令协调操作。
 * 	注：并发是以脚本为基本单元。
 * []any:
 *	指令附参序列。
 * any:
 *	指令关联数据。
 * ...any:
 *	指令所需的不定数量实参序列。
 *
 * 返回值：
 * 切片，应当被展开，以提供不定数量返回值的逻辑。其中：
 * - nil    无返回值
 * - [1]    单个返回值，展开
 * - [...]  多个返回值，同上展开
 ******************************************************************************
 */
type Wrapper func(*Actuator, []any, any, ...any) []any

// 指令配置器。
type Instx struct {
	Call Wrapper // 指令调用器
	Argn int     // 指令实参数量
}

// 脚本执行器
// 会作为脚本执行的实参传递，获得以脚本为单元的并发安全。
// 此处的ID用于唯一性地标识一段脚本。
type Actuator struct {
	Ver      int         // 版本信息
	ID       []byte      // 脚本标识ID
	Ifs      *bool       // IF 状态值（nil, false, true）
	Script               // 脚本对象
	state                // 状态记录
	scope                // 当前局部域
	*Envs                // 系统环境
	*spaces              // 综合存值对象
	*countx              // 跳转/嵌入计数器
	*switchX             // SWITCH 对象
	*loopVar             // 循环变量区
	inExpr   *int        // 在表达式内（增减表达深度）
	xfrom    map[int]any // 来源脚本信息集
	global   map[int]any // 全局变量区（VAR/SETVAR 指令用）
}

// 创建全新执行器
// 仅在顶层脚本执行时才需要全新创建。
// id   脚本的唯一性标识（4-4-2）。
// code 脚本指令序列，应当为顶层全脚本。
// ch   缓存区输入输出通道，由外部多Goroutines共享。
// env  外部环境变量取值区。
func NewActuator(id, code []byte, ch chan Middler, envs *Envs, ver int) *Actuator {
	// 部分成员零值即可。
	return &Actuator{
		Ver:    ver,
		ID:     id,
		Script: *newScript(code),
		Envs:   envs,
		spaces: &spaces{Ch: ch},
		countx: newCountx(),
		inExpr: new(int),
		global: make(map[int]any),
		// xfrom: nil,
	}
}

// 跳转源脚本信息集构造。
// src 为前阶源脚本。
// 注记：
// 保留 a 实例用来构造其它信息（待定）。
func (a *Actuator) fromScript(src Script) map[int]any {
	buf := map[int]any{}

	buf[instor.XFromSource] = src.New().Past()
	buf[instor.XFromOffset] = src.Offset()
	//... 后续添加

	return buf
}

// 子块执行器创建。
// 用于普通的子代码块，如：IF, ELSE，以及循环内的每次迭代。
// 最少的环境条件重置。
// code 为子块指令序列。
func (a *Actuator) BlockNew(code []byte) *Actuator {
	return &Actuator{
		Ver:     a.Ver,
		ID:      a.ID,
		Envs:    a.Envs,
		spaces:  a.spaces,
		countx:  a.countx,
		global:  a.global,
		xfrom:   a.xfrom,
		loopVar: a.loopVar,
		// 重置：
		Script: *newScript(code),
		inExpr: new(int),
	}
}

// switch块执行器创建。
// code 为 switch 块指令序列。
// target 为 switch 对比标的值。
// cases 为 case 分支值序列。
func (a *Actuator) SwitchNew(code []byte, target any, cases []any) *Actuator {
	return &Actuator{
		Ver:     a.Ver,
		ID:      a.ID,
		Envs:    a.Envs,
		spaces:  a.spaces,
		countx:  a.countx,
		global:  a.global,
		loopVar: a.loopVar,
		xfrom:   a.xfrom,
		// 重置：
		Script:  *newScript(code),
		switchX: newSwitch(target, cases),
		inExpr:  new(int),
	}
}

// case块执行器创建。
func (a *Actuator) CaseNew(code []byte) *Actuator {
	return &Actuator{
		Ver:     a.Ver,
		ID:      a.ID,
		Envs:    a.Envs,
		spaces:  a.spaces,
		countx:  a.countx,
		global:  a.global,
		loopVar: a.loopVar,
		xfrom:   a.xfrom,
		// 重置：
		Script:  *newScript(code),
		switchX: a.switchX.caseIn(),
		inExpr:  new(int),
	}
}

// 私有域执行器创建。
// 用于 MAP, FILTER 和 EVAL 需要私有环境的指令。
// code 为私有域指令代码序列。
// 环境：
// - 独立的数据栈和实参区。
// - 禁止 GOTO 跳转和 JUMP 嵌入。
func (a *Actuator) ScopeNew(code []byte) *Actuator {
	return &Actuator{
		Ver:    a.Ver,
		ID:     a.ID,
		Envs:   a.Envs,
		global: a.global,
		xfrom:  a.xfrom,
		// 重置：
		Script: *newScript(code),
		spaces: a.spaces.scopeNew(),
		inExpr: new(int),
		// loopVar:  nil,
		// countx:  nil,
	}
}

// 循环块执行器创建（EACH）。
// 约束：
// - 循环内禁止 GOTO 跳转，但允许 JUMP。
// - 相同 JUMP 的迭代不重复计量，但总的次数不得超出限额。
// - 初始化循环迭代变量空间（[4]any）。
func (a *Actuator) LoopNew(code []byte) *Actuator {
	return &Actuator{
		Ver:    a.Ver,
		ID:     a.ID,
		Envs:   a.Envs,
		spaces: a.spaces,
		global: a.global,
		xfrom:  a.xfrom,
		// 重置：
		Script:  *newScript(code),
		countx:  a.jumpNew(),
		loopVar: new(loopVar),
		inExpr:  new(int),
	}
}

// 独立脚本执行器创建。
// 用于 GOTO 到的外部脚本的环境隔离。
// 环境：
// 数据栈、实参区、全局变量区独立。
func (a *Actuator) ScriptNew(id []byte, code []byte) *Actuator {
	return &Actuator{
		Ver:    a.Ver,
		Envs:   a.Envs,
		countx: a.countx,
		// 重置：
		ID:     id,
		Script: *newScript(code),
		spaces: a.spaces.scopeNew(),
		inExpr: new(int),
		global: make(map[int]any),
		xfrom:  a.fromScript(a.Script),
	}
}

// 嵌入脚本状态集创建。
// 用于共享主体环境的 JUMP 脚本，但有自己的标识ID。
// 环境：
// - 与主体代码共享各种数据空间。
// - 不支持引用所在循环的迭代变量。
func (a *Actuator) EmbedNew(id []byte, code []byte) *Actuator {
	return &Actuator{
		Ver:    a.Ver,
		Envs:   a.Envs,
		spaces: a.spaces,
		countx: a.countx,
		global: a.global,
		// 重置：
		ID:     id,
		Script: *newScript(code),
		inExpr: new(int),
		xfrom:  a.fromScript(a.Script),
		// loopVar:  nil,
	}
}

// 创建 EVAL 代码执行器。
// 环境：
// - 独立的数据栈、实参区和全局变量区。
// - 禁止 GOTO 跳转和 JUMP 嵌入。
// 注记：
// 因为无法从普通字节序列转换为脚本类型，所以目标不会从外部来，
// 只能是源脚本中的 CODE{} 创建，故id不变。
func (a *Actuator) EvalNew(code []byte) *Actuator {
	return &Actuator{
		Ver:  a.Ver,
		ID:   a.ID,
		Envs: a.Envs,
		// 重置：
		Script: *newScript(code),
		spaces: a.spaces.scopeNew(),
		inExpr: new(int),
		global: make(map[int]any),
		xfrom:  a.fromScript(a.Script),
		// countx:  nil,
		// loopVar:  nil,
	}
}

// 表达式片段状态集。
// 环境：
// - 与主体代码共享各种数据空间。
// - 禁止 GOTO 跳转和 JUMP 嵌入。
func (a *Actuator) ExprNew(code []byte) *Actuator {
	return &Actuator{
		Ver:     a.Ver,
		ID:      a.ID,
		Envs:    a.Envs,
		spaces:  a.spaces,
		loopVar: a.loopVar,
		inExpr:  a.inExpr,
		global:  a.global,
		xfrom:   a.xfrom,
		// 重置：
		Script: *newScript(code),
		// countx:  nil,
	}
}

// 是否在表达式内。
func (a *Actuator) InExpr() bool {
	return *a.inExpr > 0
}

// 表达式递进计数。
func (a *Actuator) ExprIn() {
	*a.inExpr++
}

// 表达式退出计数。
func (a *Actuator) ExprOut() {
	*a.inExpr--
}

// 获取源脚本信息条目。
func (a *Actuator) XFrom(i int) any {
	return a.xfrom[i]
}

// 设置全局变量。
func (a *Actuator) GlobalSet(i int, v any) {
	a.global[i] = v
}

// 获取全局变量值。
func (a *Actuator) GlobalValue(i int) any {
	return a.global[i]
}

// 获取实参序列。
// n 为指令所需实参数量：
// - 0   无需求
// - n   特定数量（n个实参）
// - -1  不定数量（不适用实参直取）
// 返回值：
// nil	无需求
// []	n个实参的切片（上级展开）
func (a *Actuator) Arguments(n int) []any {
	if n == 0 {
		return nil
	}
	// 不定数量，忽略.FromStack
	if n < 0 {
		return a.args.take()
	}
	// 实参直取或实参区无值
	if a.FromStack || a.args.size() == 0 {
		return a.StackPops(n)
	}
	// 实参区有值
	if a.args.size() != n {
		panic(argsAmount)
	}
	return a.args.take()
}

// 构造签名消息。
// flag 签名消息类别。
func (a *Actuator) SpentMsg(flag int) []byte {
	// 未完待续
	return nil
}

// 返回值放置。
// 根据前置取值状态，放在3个不同的地方：
// - 添加到数据栈（默认）。
// - 添加到实参区。
// - 添加到局部域。
// vs:
// - nil 指令无返回值，简单忽略。
// - []	 包含成员的切片，应展开放置。
func (a *Actuator) ReturnPut(to int, vs []any) {
	if vs == nil {
		return
	}
	switch to {
	case StackFlag:
		a.StackPush(vs...)
	case ArgsFlag:
		a.PutArgs(vs...)
	case ScopeFlag:
		a.scope.add(vs...)
	default:
		panic(ErrToHere)
	}
}

/*
 * 接口函数
 ******************************************************************************
 */

// 提取多重签名的公钥集。
// 即去除脚本中提供的公钥上前置的序位标识。
// 返回：序位集，公钥集。
func MulPubKeys(pbks [][]byte) ([]int, []PubKey) {
	n := len(pbks)
	ids := make([]int, n)
	pks := make([]PubKey, n)

	for i, pk := range pbks {
		ids[i] = int(pk[0])
		// 直接引用，
		// 因为单脚本验证为顺序执行，无并发被修改的风险。
		pks[i] = PubKey(pk[1:])
	}
	return ids, pks
}

// 兑奖检查。
// 返回合法兑奖的数量（聪）。
func CheckAward(h int) int {
	//...
	return 0
}

// 单签名验证。
// ver 为版本值。便于安全升级。
// 当前采用ed25519签名认证。
func CheckSig(ver int, pubkey PubKey, msg, sig []byte) bool {
	// ver: 1
	return ed25519.Verify(pubkey, msg, sig)
}

// 多签名验证。
// ver 为版本值。便于安全升级。
// 当前采用ed25519签名认证。
func CheckSigs(ver int, pubkeys []PubKey, msg []byte, sigs [][]byte) bool {
	// ver: 1
	for i, pk := range pubkeys {
		if !ed25519.Verify(pk, msg, sigs[i]) {
			return false
		}
	}
	return true
}

// 系统内置验证（单签名）。
// 解锁数据：
// - ver 为版本值。
// - pubkey 用户的签名公钥。
// - msg 签名的消息：脚本ID（4+4+2）。
// - sig 用户的签名数据。
// - pkaddr 付款者的公钥地址。
// 注记：
// 需要对比目标公钥地址和计算出来的是否相同。
// 不含金额的合法性检查，它们在前阶环节执行。
func SingleCheck(ver int, pubkey PubKey, msg, sig, pkaddr []byte) bool {
	pka := paddr.Hash([]byte(pubkey), nil)

	if !bytes.Equal(pka, pkaddr) {
		return false
	}
	return CheckSig(ver, pubkey, msg, sig)
}

// 系统内置验证（多重签名）。
// 公钥条目和公钥地址条目都已前置1字节的序位值（在公钥地址清单中的位置）。
// 解锁数据：
// - ver 为版本值。
// - msg 签名消息。
// - sigs 签名数据集。
// - pks 签名公钥集（与签名集成员一一对应）。
// - pkhs 未签名公钥地址集。
// - pkaddr 多重签名公钥地址（付款者）。
// - env 环境对象引用（添加信息）。
// 注记：
// 需要先对比两个来源的公钥地址是否相同。
// 不含金额的合法性检查。
func MultiCheck(ver int, msg []byte, sigs, pks, pkhs [][]byte, pkaddr []byte, env *Envs) (bool, error) {
	pka, err := paddr.MulHash(pks, pkhs)

	if err != nil {
		return false, err
	}
	// 已含前置n/T配比对比。
	if !bytes.Equal(pka, pkaddr) {
		return false, nil
	}
	ids, _pks := MulPubKeys(pks)
	// 环境赋值
	env.SetMulSig(ids...)

	return CheckSigs(ver, _pks, msg, sigs), nil
}

//
// 工具辅助
///////////////////////////////////////////////////////////////////////////////

// 数据栈
// 8位空间固定大小限制。
type stack []any

// 压入成员。
// 注记：
// 超出上界时引发恐慌，因为这种行为不该发生。
func (s *stack) push(vs ...any) {
	n := len(*s) + len(vs)

	if n > StackMax {
		panic(fmt.Errorf(_T("%d 超出数据栈高度限制（<=%d）"), n, StackMax))
	}
	*s = append(*s, vs...)
}

// 弹出栈顶1项。
// 严格：向空栈取数据抛出异常。
func (s *stack) pop() any {
	i := len(*s) - 1
	if i < 0 {
		panic(errors.New(_T("数据栈高度已为零")))
	}
	v := (*s)[i]
	*s = (*s)[:i]

	return v
}

// 弹出栈顶多项。
// 注记：
// 因为栈空间动态变化，所以取片需要复制。
func (s *stack) pops(n int) []any {
	i := len(*s) - n
	if i < 0 {
		panic(fmt.Errorf(_T("%d 太大已超出数据栈高度（%d）"), n, len(*s)))
	}
	buf := make([]any, n)
	copy(buf, (*s)[i:])

	*s = (*s)[:i]

	return buf
}

// 引用栈顶1项。
// 严格：向空栈取数据抛出异常。
func (s stack) top() any {
	i := len(s) - 1

	if i < 0 {
		panic(errors.New(_T("数据栈高度已为零")))
	}
	return s[i]
}

// 引用栈顶多项。
func (s stack) tops(n int) []any {
	h := len(s)

	if h < n {
		panic(fmt.Errorf(_T("%d 太大已超出数据栈高度（%d）"), n, h))
	}
	buf := make([]any, n)
	copy(buf, s[h-n:])

	return buf
}

// 获取任意位置条目。
// 从栈底开始，支持负数从末尾算起。
func (s stack) item(i int) any {
	if i < 0 {
		i += len(s)
	}
	return s[i]
}

// 获取任意位置段条目。
// i 起始位置，支持负数从栈顶算起。
// n 获取条目数，正整数。
func (s stack) items(i, n int) []any {
	if i < 0 {
		i += len(s)
	}
	buf := make([]any, n)
	copy(buf, s[i:i+n])

	return buf
}

// 实参空间
// 无大小限制，顺序添加，一次性取出。
type args []any

// 放入实参数据。
func (a *args) put(vs ...any) {
	*a = append(*a, vs...)
}

// 提取实参区内容（全部）
// 返回一个切片，需由上级展开获取实参序列。
// 注记：
// 提取后重置为nil，使得每次新添加都是一个新空间。
func (a *args) take() []any {
	vs := *a
	*a = nil
	return vs
}

// 返回实参区条目数。
func (a *args) size() int {
	return len(*a)
}

// 局部域
// 底层为7位空间，支持负数从末尾算起。
// 序列结构，先入在前，只进不出。
type scope []any

// 获取局部域条目。
// 支持负数从末尾算起。越界时由系统（Go语言实现）抛出异常。
func (s scope) ScopeItem(i int) any {
	if i < 0 {
		i += len(s)
	}
	return s[i]
}

// 添加局部域成员。
// 超出上界时引发恐慌结束验证（不通过）。
func (s *scope) add(vs ...any) {
	n := len(*s) + len(vs)

	if n > ScopeMax {
		panic(fmt.Errorf(_T("%d 超出局部域范围（<=%d）"), n, ScopeMax))
	}
	*s = append(*s, vs...)
}

// 缓存区（导入|导出）
// 队列结构先进先出（FIFO）。
type buffer []any

// 从缓存区提取数据
// 额定n条数据，条目数不足视为失败（严格）。
// n为零时表示读取全部内容。
// 用于：
// - 脚本从导入缓存区提取数据。
// - 导出缓存区向往转出数据。
func (b *buffer) pick(n int) []any {
	if n == 0 {
		return b.take()
	}
	if n > len(*b) {
		panic(fmt.Errorf(_T("缓存大小为 %d（期待为 %d）"), len(*b), n))
	}
	v := (*b)[:n]
	*b = (*b)[n:]

	return v
}

// 提取缓存区全部数据。
func (b *buffer) take() []any {
	v := *b
	*b = nil
	return v
}

// 向缓存区压入数据。
// 用于：
// - 脚本向导出缓存区添加数据。
// - 外部向导入缓存区填充数据。
func (b *buffer) push(vs ...any) {
	*b = append(*b, vs...)
}

// 循环域变量
// 4个成员值存储在4个位置：
// - [0]  ${Value} 当前值
// - [1]  ${Key}   当前下标或键名
// - [2]  ${Data}  集合自身
// - [3]  ${Size}  集合大小
type loopVar [4]any

// 设置循环变量值。
func (l *loopVar) LoopSet(k, v, d any, size int) {
	(*l)[instor.LoopValue] = v
	(*l)[instor.LoopKey] = k
	(*l)[instor.LoopData] = d
	(*l)[instor.LoopSize] = size
}

// 提取循环变量成员。
func (l *loopVar) LoopItem(i int) any {
	return (*l)[i]
}

// 存值集合体。
// 打包几个全局存值结构，各个层级共享。
// 注记：
// 此打包结构仅为方便管理。
type spaces struct {
	Ch     chan<- Middler // 缓存区对外通道
	stack                 // 数据栈
	args                  // 实参区
	bufin  buffer         // 导入缓存区
	bufout buffer         // 导出缓存区
}

// 独立域存值体创建。
// 注：数据栈和实参区独立出来。
func (s *spaces) scopeNew() *spaces {
	return &spaces{
		Ch:     s.Ch,
		bufin:  s.bufin,
		bufout: s.bufout,
	}
}

// 数据栈添加条目。
func (s *spaces) StackPush(vs ...any) {
	s.stack.push(vs...)
}

// 弹出栈顶项。
func (s *spaces) StackPop() any {
	return s.stack.pop()
}

// 弹出栈顶多项。
func (s *spaces) StackPops(n int) []any {
	return s.stack.pops(n)
}

// 引用栈顶项。
func (s *spaces) StackTop() any {
	return s.stack.top()
}

// 引用栈顶多项。
func (s *spaces) StackTops(n int) []any {
	return s.stack.tops(n)
}

// 获取栈内目标位置条目。
// i 为位置下标，从栈底开始计数。
func (s *spaces) StackItem(i int) any {
	return s.stack.item(i)
}

// 获取栈内目标位置段条目集。
func (s *spaces) StackItems(i, n int) []any {
	return s.stack.items(i, n)
}

// 返回数据栈大小。
func (s *spaces) StackSize() int {
	return len(s.stack)
}

// 提取数据栈成员。
// 新建一个切片以获得简洁空间（节省内存）。
func (s *spaces) StackData() []any {
	buf := make([]any, len(s.stack))
	copy(buf, s.stack)
	return buf
}

// 放置实参条目。
func (s *spaces) PutArgs(vs ...any) {
	s.args.put(vs...)
}

// 向导入缓存区填充数据。
// 注意：
// 如果脚本中存在INPUT指令，外部用户需预先调用本接口灌入数据，
// 否则验证会因没有数据而结束（失败）。
func (s *spaces) Input(vs ...any) {
	s.bufin.push(vs...)
}

// 导入缓存区是否为空。
func (s *spaces) InputNil() bool {
	return len(s.bufin) == 0
}

// 导出缓存区是否为空。
func (s *spaces) OutputNil() bool {
	return len(s.bufout) == 0
}

// 从导入缓存区提取数据。
func (s *spaces) BufinPick(n int) []any {
	return s.bufin.pick(n)
}

// 提取导出缓存区全部数据。
func (s *spaces) BufoutTake() []any {
	return s.bufout.take()
}

// 向导出缓存区添加数据。
func (s *spaces) BufoutPush(vs ...any) {
	s.bufout.push(vs...)
}

// 即时状态器。
// 暂存一个脚本执行时的一些状态。
// 上级解析器根据这些状态执行相应的操作。
type state struct {
	BackTo    int  // 返回值存放区标识
	FromStack bool // 直接从数据栈取实参
	changed   bool // 是否状态改变（后续需恢复常态）
}

// 恢复为常态。
// 主要针对几个特殊指令对运行状态的改变。
// 注意：
// 上级调用管理器需要先获取状态，然后调用目标指令处理其返回值。
// 因为目标指令会在返回前调用此函数恢复常态。
func (s *state) Revert() {
	if !s.changed {
		return
	}
	s.BackTo = StackFlag
	s.FromStack = false
	s.changed = false
}

// 标记状态改变。
func (s *state) Change() {
	s.changed = true
}

// 外部依赖计数。
// 仅适用 GOTO、JUMP 指令逻辑。
type countx struct {
	gotos *int // 跳转计数
	jumps *int // 嵌入计数
}

// 新建一个计数器。
func newCountx() *countx {
	return &countx{
		new(int),
		new(int),
	}
}

// JUMP 延续创建。
// 注：禁止 GOTO 指令执行。
func (c *countx) jumpNew() *countx {
	return &countx{jumps: c.jumps}
}

// 增加一次 GOTO 计数。
func (c *countx) IncrGoto() {
	if *c.gotos >= GotoMax {
		panic(gotosOver)
	}
	*c.gotos++
}

// 增加一次 JUMP 计数。
func (c *countx) IncrJump() {
	if *c.jumps >= JumpMax {
		panic(jumpsOver)
	}
	*c.jumps++
}

// 获取嵌入计数。
func (c *countx) Gotos() int {
	return *c.gotos
}

// 获取嵌入计数。
func (c *countx) Jumps() int {
	return *c.jumps
}

// 嵌入计数直接设置。
// 注：主要用于循环块内的JUMP计数处理。
func (c *countx) SetJumps(n int) {
	*c.jumps = n
}

// 分支选择区
type switchX struct {
	target  any   // 标的值
	cases   []any // case 分支对比值序列
	through *bool // fallthrough，由下级CASE块逆向标记
}

// 新建一个 switch 分支比较器。
func newSwitch(target any, cases []any) *switchX {
	return &switchX{
		target:  target,
		cases:   cases,
		through: new(bool),
	}
}

// CASE分支进入。
// 引用原 through 指针供块内设置。
// switch/case比较值区置零，预防case子块非法嵌套。
func (sc *switchX) caseIn() *switchX {
	return &switchX{nil, nil, sc.through}
}

// 分支测试。
// 按CASE顺序比较，成功则表示可进入该分支。
// 注：比较一项移除一项。
func (sc *switchX) CasePass() bool {
	v := sc.cases[0]
	sc.cases = sc.cases[1:]

	return v == sc.target
}

// 设置 Case fallthrough 状态。
func (sc *switchX) CaseThrough(v bool) {
	*sc.through = v
}

// 检查是否穿越。
func (sc *switchX) Fallthrough() bool {
	return *sc.through
}

// Swtich 重置。
// 预防 Default 分支之后的非法 Case。
func (sc *switchX) SwitchReset() {
	sc.target = nil
	sc.cases = nil
	sc.through = nil
}
