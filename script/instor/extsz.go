// Copyright 2023 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

package instor

//
// 注记：
// 该文件定义三个扩展类指令的扩展大小设定。它们需在基础包（本包）内以避免循环导入。
// 扩展指令本身的实现在相应的 inst/... 子包内。
///////////////////////////////////////////////////////////////////////////////

// 返回扩展模块自身占用长度。
// i 为扩展模块索引（MO_X[i]）。
// 注：
// 当前统一仅占用1字节用于方法索引。
// 指令本身的实现在 ../inst/mox 子包内。
func MoxSize(i int) int {
	return 1
}

// 返回扩展指令自身占用长度。
// i 为扩展模块索引（EX_INST[i]）。
// 注：
// 仿模块逻辑，当前仅统一占用1字节定义。
// 指令本身的实现在 ../inst/instex 子包内。
func ExtSize(i int) int {
	return 1
}

// 返回私有扩展自身占用的大小。
// i 为私有扩展指令索引（EX_PRIV[i]）。
// 注：
// 暂以直接指令扩展，因此不占用额外空间。
// 指令本身的实现在 ../inst/ipriv 子包内。
func PrivSize(i int) int {
	return 0
}
