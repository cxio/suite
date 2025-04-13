// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package ipriv 私有扩展区（EX_PRIV）。
// 默认实现：
// 按直接扩展指令对待，索引目标即为指令本身。
package ipriv

import "github.com/cxio/script/ibase"

// 指令配置器引用。
type Instx = ibase.Instx

// 获取目标指令配置对。
// i 为扩展目标索引。
// data 为扩展目标关联数据。
// 注：
// 默认实现为直接指令扩展，data为nil（无意义）。
func GetInstx(i int, data any) Instx {
	return __exprivSet[i]
}

// 扩展指令配置集。
// - 键：目标指令索引。
// - 值：目标指令配置对。
var __exprivSet = make(map[int]Instx)

//
// 方法名称与标识值定义。
///////////////////////////////////////////////////////////////////////////////

// 目标标识值。
// 即 EX_PRIV[] 下标值，定位目标指令。
const (
	PrivHello = iota
	// ...
)

// 目标（函数）名定义。
var ExPrivNames = []string{
	PrivHello: "Hello",
	// ...
}

//
// 初始化
///////////////////////////////////////////////////////////////////////////////

func init() {
	__exprivSet[PrivHello] = Instx{}
	// ...
}
