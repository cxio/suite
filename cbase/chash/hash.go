// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package chash 系统内使用的一些哈希函数及基本工具。
package chash

import (
	"crypto/sha256"

	"golang.org/x/crypto/blake2b"
)

const (
	// 160位哈希字节数。
	Size160 = 20

	// 192位哈希字节数。
	Size192 = 24

	// 224位哈希字节数。
	Size224 = 28
)

// BLAKE2b 哈希计算（224位）
// 返回值：28 字节切片。
// 注记：
// golang.org/x/crypto/blake2b 没有 Sum224()
func BlakeSum224(data []byte) []byte {
	hash, _ := blake2b.New(Size224, nil)
	hash.Write(data)
	return hash.Sum(nil)
}

// BLAKE2b 哈希计算（192位）
// pfix 为哈希前置的命名字节序列，通常为nil。
// 返回值：24 字节切片。
// 注意：
// 外部需保证key长度合法，否则 nil.Write() 抛出异常。
func BlakeSum192(data, key, pfix []byte) []byte {
	// 忽略 error
	hash, _ := blake2b.New(Size192, key)
	hash.Write(data)
	return hash.Sum(pfix)
}

// BLAKE2b 哈希计算（160位）
// pfix 为哈希前置的命名字节序列。
// 返回值：20 字节切片。
// 注意：
// 外部需保证key长度合法（<=64）。
func BlakeSum160(data, key, pfix []byte) []byte {
	// 忽略 error
	hash, _ := blake2b.New(Size160, key)
	hash.Write(data)
	return hash.Sum(pfix)
}

// 封装：160位哈希运算。
// - 模式匹配中关联数据的哈希计算。
// - 哈希校验树的枝干哈希计算。
// 返回值：20字节切片。
// 注记：
// ver 版本信息为便于升级维护。
// 嵌入一层SHA2运算作为密钥强化安全。
func Sum160(ver int, data []byte) []byte {
	// ver: 1
	k := sha256.Sum256(data)
	return BlakeSum160(data, k[:Size160], nil)
}

// 封装：256位哈希运算。
// 返回：32字节切片。
// 注记：ver 版本信息为便于升级维护。
func Sum256(ver int, data []byte) []byte {
	// ver: 1
	b := blake2b.Sum256(data)
	return b[:]
}
