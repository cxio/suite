// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

// Package icode 指令码值定义。
// 命名：
// 全大写为命名指令，仅首字母大写的为符号指令。
package icode

// 值指令：[0-19] 20
const (
	NIL     = 0 + iota
	TRUE    // 1
	FALSE   // 2
	Uint8n  // 3
	Uint8   // 4
	Uint63n // 5
	Uint63  // 6
	Byte    // 7
	Rune    // 8
	Float32 // 9
	Float64 // 10
	DATE    // 11
	BigInt  // 12
	DATA8   // 13
	DATA16  // 14
	TEXT8   // 15
	TEXT16  // 16
	RegExp  // 17
	CODE    // 18
	// 19 未用
)

// 取值指令：[22-26] 5
const (
	Capture  = 20 + iota
	Bring    // 21
	ScopeAdd // 22
	ScopeVal // 23
	LoopVal  // 24
)

// 栈操作指令：[25-34] 10
const (
	NOP   = 25 + iota
	PUSH  // 26
	SHIFT // 27
	CLONE // 28
	POP   // 29
	POPS  // 30
	TOP   // 31
	TOPS  // 32
	PEEK  // 33
	PEEKS // 34
)

// 集合类指令：[35-45] 11
const (
	SLICE   = 35 + iota
	REVERSE // 36
	MERGE   // 37
	EXPAND  // 38
	GLUE    // 39
	SPREAD  // 40
	ITEM    // 41
	SET     // 42
	SIZE    // 43
	MAP     // 44
	FILTER  // 45
)

// 交互指令：[46-50] 5
const (
	INPUT   = 46 + iota
	OUTPUT       // 47
	BUFDUMP      // 48
	PRINT   = 50 // 49 未用
)

// 结果指令：[51-56] 6
const (
	PASS   = 51 + iota
	FAIL   // 52
	GOTO   // 53
	JUMP   // 54
	EXIT   // 55
	RETURN // 56
)

// 流程指令：[57-66] 10
const (
	IF          = 57 + iota
	ELSE        // 58
	SWITCH      // 59
	CASE        // 60
	DEFAULT     // 61
	EACH        // 62
	CONTINUE    // 63
	BREAK       // 64
	FALLTHROUGH // 65
	BLOCK       // 66
)

// 转换指令：[67-79] 13
const (
	BOOL   = 67 + iota
	BYTE   // 68
	RUNE   // 69
	INT    // 70
	BIGINT // 71
	FLOAT  // 72
	STRING // 73
	BYTES  // 74
	RUNES  // 75
	TIME   // 76
	REGEXP // 77
	ANYS   // 78
	DICT   // 79
)

// 运算指令：[80-103] 24
const (
	Expr   = 80 + iota
	Mul    // 81
	Div    // 82
	Add    // 83
	Sub    // 84
	MUL    // 85
	DIV    // 86
	ADD    // 87
	SUB    // 88
	POW    // 89
	MOD    // 90
	LMOV   // 91
	RMOV   // 92
	AND    // 93
	ANDX   // 94
	OR     // 95
	XOR    // 96
	NEG    // 97
	NOT    // 98
	DIVMOD // 99
	DUP    // 100
	DEL    // 101
	CLEAR  // 102
	_      // 103 未用
)

// 比较指令：[104-111] 8
const (
	EQUAL  = 104 + iota
	NEQUAL // 105
	LT     // 106
	LTE    // 107
	GT     // 108
	GTE    // 109
	ISNAN  // 110
	WITHIN // 111
)

// 逻辑指令：[112-115] 4
const (
	BOTH   = 112 + iota
	EVERY  // 113
	EITHER // 114
	SOME   // 115
)

// 模式指令：[116-127] 12
const (
	MODEL       = 116 + iota
	ValPick     // 117
	Wildcard    // 118
	Wildnum     // 119
	Wildpart    // 120
	Wildlist    // 121
	TypeIs      // 122
	WithinInt   // 123
	WithinFloat // 124
	RE          // 125
	RePick      // 126
	WildLump    // 127
)

// 环境指令：[128-137] 10
const (
	ENV    = 128 + iota
	OUT    // 129
	IN     // 130
	INOUT  // 131
	XFROM  // 132
	VAR    // 133
	SETVAR // 134
	SOURCE // 135
	MULSIG // 136
	_      // 137 未用
)

// 工具指令：[138-163] 26
const (
	EVAL    = 138 + iota
	COPY          // 139
	DCOPY         // 140
	KEYVAL        // 141
	MATCH         // 142
	SUBSTR        // 143
	REPLACE       // 144
	SRAND         // 145
	RANDOM        // 146
	QRANDOM       // 147
	CMPFLO        // 148
	RANGE   = 155 // 149-154 未用
	_             // 保留区 [156-163] 8
)

// 系统指令：[164-169] 6
const (
	SYS_TIME = 164 + iota
	SYS_AWARD
	SYS_NULL = 169 // 166-168 未用
)

// 函数指令：[170-209] 40
const (
	FN_BASE58    = 170 + iota
	FN_BASE32          // 171
	FN_BASE64          // 172
	FN_PUBHASH         // 173
	FN_MPUBHASH        // 174
	FN_ADDRESS         // 175
	FN_CHECKSIG        // 176
	FN_MCHECKSIG       // 177
	FN_HASH224         // 178
	FN_HASH256         // 179
	FN_HASH384         // 180
	FN_HASH512         // 181
	FN_PRINTF    = 208 // 182-207 未用
	FN_X         = 209
)

// 模块指令：[210-249] 40
const (
	MO_RE    = 210 + iota
	MO_TIME        // 211
	MO_MATH        // 212
	MO_CRYPT       // 213
	MO_X     = 249 // 214-248 未用
)

// 扩展指令：[250-254] 5
const (
	EX_FN   = 250
	EX_INST = 251
	EX_PRIV = 253 // 252 未用
	// 254 未用
	// 255 系统保留

)
