// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package instex 通用扩展指令（EX_INST）包。
// 扩展的指令自身自由，指令本身的定义数据作为上级 EX_INST 的数据。
// 注：暂以模块逻辑对待。
package instex

import "github.com/cxio/script/ibase"

// 指令配置对引用。
type Instx = ibase.Instx

// 脚本执行器引用。
type Actuator = ibase.Actuator

// 映射指令集。
type mapInst = map[int]Instx

// 获取扩展目标的指令配置集。
// i 为扩展目标索引。
// data 为扩展目标自身定义数据。
func GetInstx(i int, data any) Instx {
	return __instExtens[i][data.(int)]
}

// 通用扩展配置清单。
// 注：参考 mox 实现。
var __instExtens = map[int]mapInst{
	EXInstExample: __exiSetExample,
	// ...
}

// 示例：
// 应当在另一个独立的文件中定义&实现。
var __exiSetExample = make(mapInst)

//
// EX_INST{...}
// 扩展目标的方法名称与标识值定义。
///////////////////////////////////////////////////////////////////////////////

// 目标索引。
const (
	EXInstExample = iota
	// ...
)

// 目标名清单。
var EXInstNames = []string{
	EXInstExample: "Example",
	// ...
}

/*
 * EXI: Example
 ******************************************************************************
 */

// Example: 方法标识值。
const (
	EXInstExample_Create = iota
	// ...
)

// Example: 方法名清单。
var EXInstExampleMethod = []string{
	EXInstExample_Create: "Create",
	// ...
}
