// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package tx 交易操作包封装交易的关联操作。
package tx

import (
	"github.com/cxio/suite/cbase"
	"github.com/cxio/suite/cbase/paddr"
)

const (
	// 输入源索引长度
	InIDSize = cbase.KeyIDSize
)

// 公钥地址引用
type PKAddr = paddr.PKAddr

// Header 交易头信息。
// TxID: Hash(Header)
type Header struct {
	Version   int32    // 版本
	Timestamp int64    // 交易时间戳（毫秒）
	BlockLink [20]byte // 主链绑定
	Minter    PKAddr   // 铸造地址
	Scale     uint8    // 收益地址分成（n/100）
	Staker    PKAddr   // 收益地址，可选
	HashBody  []byte   // 交易数据体哈希（32）
}

// Vin 输入项。
type Vin [InIDSize]byte

// 输出：币金类。
type Coin struct {
	Receiver PKAddr // 接收者
	Amount   int64  // 币金
	Script   []byte // 锁定脚本
}

// 输出：凭信类。
// 与币金一样，需要有可验证的接收者。
type Credit struct {
	Receiver    PKAddr // 接收者
	Creator     []byte // 凭信创建者
	Description []byte // 凭信描述
	Script      []byte // 锁定脚本
	Attachment  []byte // 附件ID，可行
}

// 输出：证据类。
type Evidence struct {
	Title      []byte // 证据标题
	Content    []byte // 证据内容
	Script     []byte // 识别脚本
	Attachment []byte // 附件ID，可行
}

// Vout 输出项。
// 综合包含三种信元数据。
type Vout struct {
	coin     *Coin     // 币金类
	credit   *Credit   // 凭信类
	evidence *Evidence // 证据类
}

// Body 交易体结构。
type Body struct {
	vins  []Vin  // 输入集
	vouts []Vout // 输出集
}
