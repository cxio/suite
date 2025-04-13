// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package xpool 第三方脚本片段集存储与检索。
// 用于 GOTO、JUMP 指令快速获取第三方脚本。在所有Goroutines之间共享，并发安全。
package xpool

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cxio/cbase"
)

// 池大小。
// 超出的量会被监控服务器定期削平（随机移除）。
const Size = 1 << 14

const (
	// 池检查间隔时间。
	chkTime = 30 * time.Minute
)

// 池服务是否已经运行。
var serving = false

// 脚本池。
// key:   string 由区块高度、交易ID和脚本序位构成。
// value: []byte 脚本序列。
var pool sync.Map

// 获取目标脚本。
// 参数：
// h 交易所在区块高度。
// n 交易ID在其区块中的序位，从0开始。
// i 脚本在输出集中的序位，从0开始。
func Get(h, n, i int) []byte {
	k := cbase.KeyID(h, n, i)

	if v, ok := pool.Load(k); ok {
		return v.([]byte)
	}
	var code []byte
	//?...
	// 向外获取目标脚本（blockqs）

	pool.Store(k, code)
	return code
}

// 创建一个池服务。
// 主要用于监控池大小是否超出限定，
// 在到达limit时间后检查，超出多少即移除多少（恢复到限定水平）。
// 注意：
// 应当仅被调用一次，此函数自身并非并发安全。
// 服务启动后会一直执行，直到程序自身停止运行。
func Serve(limit int) {
	if serving {
		fmt.Fprintln(os.Stderr, "The xpool service is already running")
		return
	}
	if limit <= 0 {
		limit = Size
	}
	go func() {
		tick := time.Tick(chkTime)
		for {
			<-tick
			shear(limit)
		}
	}()
	serving = true
}

// 削去多余的量，维持一定规模。
// 注记：
// sync.Map 不支持获取条目数量，只能完整迭代。
// 因此执行一次应当间隔足够长的时间，避免浪费。
func shear(max int) {
	len := 0
	pool.Range(func(k, _ any) bool {
		len++
		if len > max {
			pool.Delete(k)
		}
		return true
	})
}
