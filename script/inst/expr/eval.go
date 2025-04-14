// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package expr 表达式指令的实现。
// 作为脚本系统的一个子指令，与上级指令处理有着较为紧密的关系，
// 因此这里直接抛出异常而非返回错误（包编码规约）。
// 而作为一个子包实现，是为了尽可能分离逻辑耦合，优化编码条理。
package expr

import (
	"fmt"

	"github.com/cxio/suite/locale"
	"github.com/cxio/suite/script/ibase"
	"github.com/cxio/suite/script/icode"
)

// 本地化文本获取。
var _T = locale.GetText

// 操作符指令码配置。
const (
	_Mul = icode.Mul // *
	_Div = icode.Div // /
	_Add = icode.Add // +
	_Sub = icode.Sub // -
)

// 表达式结束标志。
const exprEnd = ibase.ExprEnd

// 表达式单元接口
// 统一采用float64计算以保持精度。
type _Expr interface {
	Eval() float64
}

// 单操作数操作
// op: + - 码值
type unary struct {
	op int
	x  _Expr
}

func (u unary) Eval() float64 {
	switch u.op {
	case _Add: // +
		return +u.x.Eval()
	case _Sub: // -
		return -u.x.Eval()
	}
	panic(fmt.Sprintf(_T("不被支持的一元操作符: %q"), u.op))
}

// 双操作数四则运算
// op: * / + - 码值
type binary struct {
	op   int
	x, y _Expr
}

func (b binary) Eval() float64 {
	switch b.op {
	case _Mul:
		return b.x.Eval() * b.y.Eval()
	case _Div:
		return b.x.Eval() / b.y.Eval()
	case _Add:
		return b.x.Eval() + b.y.Eval()
	case _Sub:
		return b.x.Eval() - b.y.Eval()
	}
	panic(fmt.Sprintf(_T("不被支持的二元操作符: %q"), b.op))
}

// 储值操作。
// 普通指令调用后的返回值存储。
type value float64

func (v value) Eval() float64 {
	return float64(v)
}

/*
 * 解析执行器
 * 用法：
 * 每一段小括号封装的表达式（或优先级分组）都需创建一个执行器并执行（.Run()）。
 * 表达式内的优先级分组返回的值自然参与计算。
 * 顶级根表达式的运算结果则返回到执行流（上级调用者）。
 ******************************************************************************
 */

// 表达式执行器。
// call() 会步进执行每一个指令，返回指令码值和指令执行后的原始返回值。
// 当表达式执行完后，再次调用 call() 返回 (-1, nil)。
// 注记：
// 如果表达式内调用的指令返回nil或空值，则这里的值存储为0。
// 如果表达式内指令返回多于1个值，则抛出错误。
type Calculor struct {
	call func() (int, []any) // 指令调用器
	n    int                 // 指令码
	v    float64             // 指令返回值
}

// 创建一个计算器。
// expr 为待执行的指令序列片段（小括号包围的部分）。
// call 为上级提供的指令调用步进器。
func Calculator(call func() (int, []any)) *Calculor {
	return &Calculor{call: call}
}

// 执行器运行。
func (c *Calculor) Calc() float64 {
	c.next()
	e := parseExpr(c)

	if c.code() != exprEnd {
		panic(fmt.Sprintf(_T("未知语法错误: %q"), c.value()))
	}
	return e.Eval()
}

// 步进执行一个指令。
// 如果步进已结束，置标指令码并返回false。
func (c *Calculor) next() bool {
	n, vs := c.call()

	if n < 0 && vs == nil {
		c.n = exprEnd
		return false
	}
	c.n, c.v = n, 0

	if len(vs) > 1 {
		panic(_T("表达式内指令的返回值太多"))
	}
	if len(vs) == 1 {
		switch x := vs[0].(type) {
		case float64:
			c.v = x
		case byte:
			c.v = float64(x)
		case rune:
			c.v = float64(x)
		case int64:
			c.v = float64(x)
		case float32:
			c.v = float64(x)
		default:
			panic(_T("表达式内指令的返回值类型无效"))
		}
	}
	return true
}

// 获取当前指令码。
// 注：在 .next() 执行之后更新。
func (c *Calculor) code() int {
	return c.n
}

// 获取当前指令执行返回值。
// 注：同上在 .next() 执行之后更新。
func (c *Calculor) value() float64 {
	return c.v
}

// 优先级权重。
func precedence(op int) int {
	switch op {
	case _Mul, _Div:
		return 2
	case _Add, _Sub:
		return 1
	}
	return 0
}

// 解析表达式。
func parseExpr(a *Calculor) _Expr {
	return parseBinary(a, 1)
}

// 解析二元操作。
// 注：修改自 gopl.io/ch7/eval/parse.go
func parseBinary(a *Calculor, prec1 int) _Expr {
	lhs := parseUnary(a)

	for prec := precedence(a.code()); prec >= prec1; prec-- {
		for precedence(a.code()) == prec {
			op := a.code()
			if !a.next() {
				panic(_T("二元操作缺少跟随的操作数"))
			}
			rhs := parseBinary(a, prec+1)
			lhs = binary{op, lhs, rhs}
		}
	}
	return lhs
}

// 解析一元操作。
func parseUnary(a *Calculor) _Expr {
	c := a.code()

	if c == _Add || c == _Sub {
		if !a.next() {
			panic(_T("一元操作缺少跟随的操作数"))
		}
		return unary{c, parseUnary(a)}
	}
	return parsePrimary(a)
}

// 解析主要操作。
// 即执行非运算符的指令，可能为表达式内最后一个指令。
func parsePrimary(a *Calculor) _Expr {
	if a.code() != exprEnd {
		v := a.value()
		a.next()
		return value(v)
	}
	panic(_T("表达式已结束，不可继续执行"))
}
