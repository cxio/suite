// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package cbase 基础公共集，一些全局的变量、常量和函数等。
package cbase

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"

	"github.com/cxio/suite/script/instor"
)

// 切片成员类型约束
type Itemer = instor.Itemer

// 构造脚本ID。
// 脚本ID用于唯一性地标识一段脚本。
// 构成：
// - h 理想块高度（4字节）
// - n 交易ID在区块中的序位（4字节）
// - i 脚本序位（2字节）
// 返回：ID的字节序列。
func KeyID(h, n, i int) []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, uint32(h))
	binary.Write(&buf, binary.BigEndian, uint32(n))
	binary.Write(&buf, binary.BigEndian, uint16(i))

	return buf.Bytes()
}

/*
 * 基本工具
 ******************************************************************************
 */

// 浮点数相等比较。
// d 为 x 和 y 之间的误差值，不超过则视为相等。
// 注：
// 如果d为零，就是严格相等了。
func FloatEqual(x, y, d float64) bool {
	return math.Abs(x-y) <= d
}

// 将特定类型的切片转为any切片。
// 确定会返回一个切片，空切片非nil。
func ToAnys[T Itemer](data []T) []any {
	buf := make([]any, len(data))

	for i, v := range data {
		buf[i] = v
	}
	return buf
}

// 查找首个正则匹配。
// 返回一个切片，其中首个成员为完整匹配，后续为可能有的子匹配。
// 目标 target 支持字符串或字节序列。
func Match(target any, re *regexp.Regexp) []any {
	if x, ok := target.(string); ok {
		return ToAnys(re.FindStringSubmatch(x))
	}
	return ToAnys(re.FindSubmatch(target.([]byte)))
}

// 查找全部匹配。
// 仅查找完整匹配的结果，子匹配会被简单忽略。
// 目标 target 支持字符串或字节序列。
func MatchAll(target any, re *regexp.Regexp) []any {
	if x, ok := target.(string); ok {
		return ToAnys(re.FindAllString(x, -1))
	}
	return ToAnys(re.FindAll(target.([]byte), -1))
}

// 查找所有的匹配。
// 会检查每一个匹配的子匹配，返回包含每组匹配的子匹配的一个二维切片。
// 如果子匹配式本身就不存在，每组匹配依然是一个切片结果（即整体依然为二维）。
// 目标 target 支持字符串或字节序列。
func MatchEvery(target any, re *regexp.Regexp) []any {
	if x, ok := target.(string); ok {
		return ToAnys(re.FindAllStringSubmatch(x, -1))
	}
	return ToAnys(re.FindAllSubmatch(target.([]byte), -1))
}

//
// 友好辅助
///////////////////////////////////////////////////////////////////////////////

// 每年的区块数量。
// 按恒星年（Sidereal year），每6分钟一个块计算。
const SY6BLOCKS = 87661

// 原始铸币终止线。
// 即每块低于 3币 后终止。
const MINTENDLINE = 3e8

// 奖励总量计算&打印。
// base 初始每块币量（单位：币）。
// rate 前阶比率（千分值），如 900 表示 90%。
// 返回：累计总量（单位：聪）。
func AwardTotal(base, rate int64) int64 {
	if rate >= 1000 {
		panic("比率设置错误")
	}
	var sum int64
	y := 0
	// 1币 = 1亿聪
	base *= 1e8

	fmt.Println("年次\t累计\t\t\t（年计）\t\t币量/块")
	fmt.Println("----------------------------------------------------------------------")

	for {
		// 低于 3币/块 时止
		if base < MINTENDLINE {
			break
		}
		ysum := base * SY6BLOCKS
		sum += ysum
		y++
		fmt.Printf("%d\t%d \t(%d)\t%d\n", y, sum, ysum, base)

		base = base * rate / 1000
	}
	return sum
}
