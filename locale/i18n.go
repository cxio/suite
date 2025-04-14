// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package locale 国际化&本地化处理包。
// 主要用于提取源码中原语种对应某应用语种的字符串翻译。
package locale

// 本地化文本存储集。
// 键：源码中原语种字符串。
// 值：目标应用语种相应翻译的字符串。
var __Texts = make(map[string]string)

// 获取本地化文本。
// k 为代码中引用的源文本，不一定是英文。
// 如果不存在翻译文本，返回原始引用文本。
// 注意：
// 外部应当在程序运行前配置完成，以获得并发安全。
func GetText(k string) string {
	if s, ok := __Texts[k]; ok {
		return s
	}
	return k
}

//
// 初始准备
// 载入本地化翻译文本集。外部可能用JSON格式定义。
///////////////////////////////////////////////////////////////////////////////

func init() {
	//
}
