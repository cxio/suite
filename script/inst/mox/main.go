// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package mox 扩展模块（MO_X）
// 作为单独一个子包编码，更便于灵活定制。
package mox

import (
	"github.com/cxio/suite/script/ibase"
)

// 指令配置对引用。
type Instx = ibase.Instx

// 脚本执行器引用。
type Actuator = ibase.Actuator

// 映射指令集。
// 注记：
// 内部类型，实际上可以改用更节省&高效的结构（比如数组）。
type mapInst = map[int]Instx

// 获取扩展模块的指令配置集。
// i 为扩展模块索引。
// data 为扩展模块自身定义（默认1字节定义方法）。
func GetInstx(i int, data any) Instx {
	return __moxExtens[i][data.(int)]
}

// 扩展模块清单配置。
// - 键：模块索引。
// - 值：映射指令配置集。
// 注记：
// 子模块索引为1字节空间，可改用更有效率的数组/切片结构。
var __moxExtens = map[int]mapInst{
	MOXExample: __moxSetExample,
	// ...
}

//
// MO_X{...}
// 扩展模块方法名称与标识值定义。
///////////////////////////////////////////////////////////////////////////////

// 模块集索引。
const (
	MOXExample = iota
	// ...
)

// 模块名定义。
var MOXNames = []string{
	MOXExample: "Example",
	// ...
}

/*
 * MOX: Example
 ******************************************************************************
 */

// Example: 方法标识值。
const (
	MOXExample_Create = iota
	// ...
)

// Example: 方法名清单。
var MOXExampleMethod = []string{
	MOXExample_Create: "Create",
	// ...
}
