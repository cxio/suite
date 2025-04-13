// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

package mox

// MOX:Example
// 示例模块方法指令配置集。
var __moxSetExample = make(mapInst)

// 示例扩展模块。
type Example struct {
	//
}

// 创建Example模块对象。
// vs 为模块方法需要的实参序列。
// 附参：无。
// 上级实际会传递本模块在 MO_X 中的索引。
// 数据：无。
// 上级实际会传递本方法在本模块中的索引。
func _Create(a *Actuator, _ []any, _ any, vs ...any) []any {
	//...
	return []any{new(Example)}
}

//
// 初始化
///////////////////////////////////////////////////////////////////////////////

func init() {
	__moxSetExample[MOXExample_Create] = Instx{Call: _Create, Argn: 0}
	// ...
}
