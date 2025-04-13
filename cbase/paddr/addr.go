// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package paddr 账户公钥相关的一些操作。
package paddr

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/cxio/cbase/base58"
	"github.com/cxio/cbase/chash"
	"github.com/cxio/locale"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// 便捷引用。
var _T = locale.GetText

const (
	// 地址前缀分隔符。
	// 固定标识，可用于剥离前缀。
	Delimiter = ':'

	// 公钥哈希地址长度。
	HashSize = chash.Size160

	// 多重签名数量最大值。
	MulSigMaxN = 0xff
)

var (
	// 多重签名条目数错误。
	ErrMSigSize = errors.New(_T("多重签名条目数超出上限（255）"))

	// 多重签名公钥序位错误。
	ErrMSigIndex = errors.New(_T("多重签名公钥序位空缺错误"))

	// 前缀分隔符错误。
	ErrDelimMissing = errors.New(_T("账户地址无标识前缀分隔符"))

	// 校验错误。
	ErrChecksum = errors.New(_T("地址校验错误"))

	// 无效格式。
	ErrInvalidFormat = errors.New(_T("无效的格式：缺失校验码"))
)

// 公钥地址。
// 20 或 22 字节长。
type PKAddr []byte

// Hash 构造公钥哈希地址。
// 并不检查字节序列长度是否规范，即：支持任意字节数据。
// 比如构造多重签名公钥地址时，有前置n/T配比字节（此时prefix就有用了）。
// 返回值：公钥地址。
// 注记：
// 嵌套不同的哈希算法以强化安全，如某个算法被攻破也问题不大。
// 有限数量人类个体使用20字节的地址空间已经足够，
// 即便亿亿万一发生碰撞，两个地址应当已相距百年千年，不太可能被盗用。
func Hash(pubKey, prefix []byte) PKAddr {
	h := sha3.Sum256(pubKey)
	k := sha256.Sum256(h[:])
	return PKAddr(chash.BlakeSum160(h[:], k[:HashSize], prefix))
}

// MulHash 构造多重签名公钥地址。
// - pks 为签名公钥集。
// - pkhs 为剩余未签名公钥地址集。
// 规则：
// 两个集合中字节序列成员内的首字节为位置序号。
// n/T 配比各占1字节，参与哈希构造，放置在公钥地址清单前端。
// 返回的总公钥地址也前置 n/T 配比（明码）。
// 注：
// 详情参考系统设计文档中多重签名地址说明部分。
func MulHash(pks [][]byte, pkhs [][]byte) (PKAddr, error) {
	n := len(pks)
	t := len(pkhs) + n

	if t > MulSigMaxN {
		return nil, ErrMSigSize
	}
	all := make([][]byte, t)

	for _, pk := range pks {
		all[int(pk[0])] = Hash(pk[1:], nil)
	}
	for _, pkh := range pkhs {
		all[int(pkh[0])] = pkh[1:]
	}

	return hashMPKH(all, n)
}

// Encode 公钥地址编码为账户地址。
// 采用 Base58 编码，标识前缀与后段地址之间以冒号分隔。
// - pkh 为公钥地址。
// - prefix 为标识前缀。
// 编码：
// 1. 公钥地址添加识别前缀，即“前缀+公钥地址”。
// 2. 对其执行两次哈希运算，取末尾4字节为校验码。
// 3. 在公钥地址之后附上校验码（此时无前缀），编码为文本地址。
// 4. 附上识别前缀，即“前缀:文本地址”即为账户地址。
// 注：
// 前缀分隔符（:）为系统设置。
func Encode(pkh []byte, prefix string) string {
	pf := []byte(prefix)

	// 前缀+公钥地址
	b := nbytes(len(pkh)+4, pf...)
	b = append(b, pkh...)
	chsum := checksum(b)

	// 文本地址
	buf := bytes.NewBuffer(pf)
	buf.WriteByte(Delimiter)

	buf.WriteString(base58.Encode(
		// 公钥地址（无前缀）+校验码
		append(b[len(pf):], chsum[:]...),
	))
	return buf.String()
}

// Decode 账户地址解码为公钥地址。
// 1. 提取识别前缀和文本地址。
// 2. 将文本地址解码为字节序列。末尾4字节为校验码，前段为公钥地址。
// 3. 公钥地址前置识别前缀（即“前缀+公钥地址”），执行两次哈希运算取末尾4字节为校验码。
// 4. 比较上面两个校验码，相同则地址合法。
func Decode(addr string) ([]byte, string, error) {
	// 前缀提取
	i := strings.IndexByte(addr, Delimiter)
	if i < 0 {
		return nil, "", ErrDelimMissing
	}
	pf, at := addr[:i], addr[i+1:]
	// 解码
	bs := base58.Decode(at)
	if len(bs) < 5 {
		return nil, "", ErrInvalidFormat
	}
	// 校验码处理
	pkh := bs[:len(bs)-4]
	var cksum [4]byte
	copy(cksum[:], bs[len(bs)-4:])

	// 验证码验证
	if checksum(append([]byte(pf), pkh...)) != cksum {
		return nil, "", ErrChecksum
	}
	return nbytes(0, pkh...), pf, nil
}

//
// 私有辅助
///////////////////////////////////////////////////////////////////////////////

// 创建一个新字节序列。
// n 为额外空间（除bs外）。
// bs 为立即添加的字节数据。
// 用途：
// - 返回新的空间占用刚好的字节序列。
// - 初始即创建大小刚好的空间。
func nbytes(n int, bs ...byte) []byte {
	b := make([]byte, 0, n+len(bs))
	return append(b, bs...)
}

// 获取地址编码校验码。
// 取“前缀+公钥地址”两次哈希后末尾4字节。
func checksum(fpkh []byte) (cksum [4]byte) {
	h1 := sha256.Sum256(fpkh)
	h2 := blake2b.Sum256(h1[:])
	copy(cksum[:], h2[len(h2)-4:])
	return
}

// 计算多重签名总的公钥哈希。
// pkhs 为公钥地址集，以按需要的顺序排列。
// n 为需要的最少签名数量。
// 各公钥地址串联，前置 n/T 配比后计算哈希。
// 返回值：总公钥哈希。
func hashMPKH(pkhs [][]byte, n int) (PKAddr, error) {
	t := len(pkhs)
	_n := byte(n)
	_t := byte(t)
	buf := nbytes(t*HashSize, _n, _t)

	for _, pkh := range pkhs {
		if pkh == nil {
			return nil, ErrMSigIndex
		}
		buf = append(buf, pkh...)
	}
	// 前置 n/T 明码友好
	return Hash(buf, []byte{_n, _t}), nil
}
