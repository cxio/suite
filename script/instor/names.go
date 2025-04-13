// Copyright 2022 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.

package instor

// 循环域4个成员位置标识
const (
	LoopValue int = iota // 值（any）
	LoopKey              // 键（int|string）
	LoopData             // 数据集（any）
	LoopSize             // 集合大小（int）
)

// 循环变量名定义。
// 用于 ${}(1) 循环域变量引用指令。
var LoopNames = []string{
	LoopValue: "Value",
	LoopKey:   "Key",
	LoopData:  "Data",
	LoopSize:  "Size",
}

// 切片成员类型支持。
// 栈脚本仅支持如下6种切片类型。
const (
	ItemAny    = iota // []any
	ItemByte          // Bytes
	ItemRune          // Runes
	ItemInt           // []Int
	ItemFloat         // []Float
	ItemString        // []String
)

// 切片成员类型名定义。
// 注意大小写，用于 ANYS(1) 转换。
var SliceItemNames = []string{
	ItemAny:    "any", // 默认，无需书写
	ItemByte:   "Byte",
	ItemRune:   "Rune",
	ItemInt:    "Int",
	ItemFloat:  "Float",
	ItemString: "String",
}

// 类型匹配支持
// for !{Type}(1)
const (
	TypeisBool   = iota // 布尔值
	TypeisInt           // 整数
	TypeisByte          // 字节
	TypeisRune          // 字符
	TypeisFloat         // 浮点数
	TypeisTime          // 时间戳
	TypeisBigInt        // 大整数
	TypeisBytes         // 字节序列
	TypeisString        // 文本串
	TypeisRegExp        // 正则表达式
	TypeisScript        // 脚本
	TypeisNumber        // 数值（Int|Float）
	TypeisModel         // 模式区
)

// 类型匹配名称定义。
// 用于模式指令 !{Type}(1) 中的类型书写。
var TypeNames = []string{
	TypeisBool:   "Bool",
	TypeisInt:    "Int",
	TypeisByte:   "Byte",
	TypeisRune:   "Rune",
	TypeisFloat:  "Float",
	TypeisTime:   "Time",
	TypeisBigInt: "BigInt",
	TypeisBytes:  "Bytes",
	TypeisString: "String",
	TypeisRegExp: "RegExp",
	TypeisScript: "Script",
	TypeisNumber: "Number",
	TypeisModel:  "Model",
}

// 环境变量条目标识值。
const (
	EnvHeight      = iota // 理想块高度（按时间戳算）
	EnvTime               // 理想块时间戳
	EnvRealHeight         // 交易打包进的实际区块的高度
	EnvTxID               // 交易ID
	EnvTimestamp          // 交易时间戳
	EnvInSize             // 输入项总数
	EnvInAmout            // 输入总金额
	EnvOutSize            // 输出项总数
	EnvOutAmount          // 输出总金额
	EnvInGoto             // 是否在 GOTO 跳转的脚本中
	EnvInJump             // 是否在 JUMP 引入的脚本中
	EnvGotos              // 当前 GOTO 跳转计数
	EnvJumps              // 当前 Jump 嵌入计数
	EnvBlockHeight        // 区块链当前最新高度
	EnvBlockTime          // 当前最新区块创建的时间戳
	EnvLimitStack         // 栈高度上限（256）
	EnvLimitScope         // 局部变量域上限（128）
)

// 环境变量名称定义。
// 用于环境指令 ENV 中的目标定位。
var EnvNames = []string{
	EnvHeight:      "Height",
	EnvTime:        "Time",
	EnvRealHeight:  "RealHeight",
	EnvTxID:        "TxID",
	EnvTimestamp:   "Timestamp",
	EnvInSize:      "InSize",
	EnvInAmout:     "InAmout",
	EnvOutSize:     "OutSize",
	EnvOutAmount:   "OutAmount",
	EnvInGoto:      "InGoto",
	EnvInJump:      "InJump",
	EnvGotos:       "Gotos",
	EnvJumps:       "Jumps",
	EnvBlockHeight: "BlockHeight",
	EnvBlockTime:   "BlockTime",
	EnvLimitStack:  "LimitStack",
	EnvLimitScope:  "LimitScope",
}

// 脚本输出项标识值。
// 用于 OUT/INOUT 两个指令。
const (
	OutAmount      = iota // 币金数量
	OutReceiver           // 接收者
	OutCreator            // 凭信创建者
	OutDescription        // 凭信描述
	OutCount              // 凭信转移计数
	OutTitle              // 证据标题
	OutContent            // 证据内容
	OutAttachment         // 附件ID
	OutSource             // 输出脚本引用
	OutTimestamp          // 源交易的创建时间（仅适用 INOUT）
)

// 脚本输出项名称定义。
// 用于环境指令 OUT/INOUT 中的目标条目定位。
var OutNames = []string{
	OutAmount:      "Amount",
	OutReceiver:    "Receiver",
	OutCreator:     "Creator",
	OutDescription: "Description",
	OutCount:       "Count",
	OutTitle:       "Title",
	OutContent:     "Content",
	OutAttachment:  "Attachment",
	OutSource:      "Source",
	OutTimestamp:   "Timestamp",
}

// 脚本输入项标识值。
// 用于 IN 指令。
const (
	InIndex   = iota // 当前输入在输入集内的偏移（索引）
	InAmount         // 当前输入币金数量（币金类才有）
	InAccount        // 当前输入账户（公钥地址）
	InAddress        // 当前输入地址（文本地址）
	InPayType        // 当前输入的类型（币金|凭信）
	InSigs           // 当前输入已签名数量（>= 0）
	InCanSigs        // 当前输入能够签名的数量（>1时为多重签名账户）
	InSigType        // 当前输入的签名类型
	InSource         // 当前输入脚本（含解锁部分），注：INOUT/Source 为不含解锁部分
)

// 脚本输入项名称定义。
var InNames = []string{
	InIndex:   "Index",
	InAmount:  "Amount",
	InAccount: "Account",
	InAddress: "Address",
	InPayType: "PayType",
	InSigs:    "Sigs",
	InCanSigs: "CanSigs",
	InSigType: "SigType",
	InSource:  "Source",
}

// 源脚本信息成员。
// 注：
// 仅适用 GOTO/JUMP 跳转到的目标脚本。
const (
	XFromSource    = iota // 源脚本指令序列
	XFromOffset           // 跳转/嵌入点在源脚本中的偏移位置
	XFromInSize           // 源交易输入集大小（项数）
	XFromInAmount         // 源交易输入总金额
	XFromOutSize          // 源交易输出集大小（项数）
	XFromOutAmount        // 源交易输出总金额
	XFromTxID             // 源交易的ID
	XFromHeight           // 理想块高度
	XFromTime             // 理想块时间戳
	XFromTimestamp        // 源交易的创建时间戳
	XFromAmount           // 源输入币金数量（币金类才有）
	XFromAccount          // 源输入账户（公钥地址）
	XFromAddress          // 源输入地址（文本地址）
	XFromPayType          // 源输入的类型（币金|凭信）
)

// 源脚本信息名称定义。
// 用于环境指令 XFROM 中定位成员目标。
var XFromNames = []string{
	XFromSource:    "Source",
	XFromOffset:    "Offset",
	XFromInSize:    "InSize",
	XFromInAmount:  "InAmount",
	XFromOutSize:   "OutSize",
	XFromOutAmount: "OutAmount",
	XFromTxID:      "TxID",
	XFromHeight:    "Height",
	XFromTime:      "Time",
	XFromTimestamp: "Timestamp",
	XFromAmount:    "Amount",
	XFromAccount:   "Account",
	XFromAddress:   "Address",
	XFromPayType:   "PayType",
}

// 时间成员码值定义。
const (
	TimeDefault     = iota // 默认（Time）
	TimeStamp              // 时间戳（毫秒数）
	TimeYear               // 年次（4）
	TimeMonth              // 月次（1-12）
	TimeYearDay            // 年日次（1-365/366）
	TimeDay                // 月日次
	TimeWeekDay            // 周日次
	TimeHour               // 时数/日（0-23）
	TimeMinute             // 分钟数/时（0-59）
	TimeSecond             // 秒数/分钟（0-59）
	TimeMillisecond        // 毫秒数/秒（0-999）
	TimeMicrosecond        // 微秒数/秒（0-999999）
)

// 时间成员名称定义。
// 用于系统指令 SYS_TIME 中定位时间的条目。
var TimeNames = []string{
	TimeStamp:       "Stamp",
	TimeYear:        "Year",
	TimeMonth:       "Month",
	TimeYearDay:     "YearDay",
	TimeDay:         "Day",
	TimeWeekDay:     "WeekDay",
	TimeHour:        "Hour",
	TimeMinute:      "Minute",
	TimeSecond:      "Second",
	TimeMillisecond: "Millisecond",
	TimeMicrosecond: "Microsecond",
}

// 哈希算法标识值。
const (
	HashSHA3 = iota
	HashSHA2
	HashBLAKE2
)

// 哈希算法名称集。
var HashAlgo = []string{
	HashSHA3:   "sha3",
	HashSHA2:   "sha2",
	HashBLAKE2: "blake2",
}

//
// 指令扩展区
// 统一对成员名称和索引作定义，便于外部解析采用。
///////////////////////////////////////////////////////////////////////////////

// FN_X:
// 函数扩展指令标识值 [0-255]
const (
// FNX...
)

// 函数扩展指令：函数名定义。
var FnXNames = []string{
	//
}

// EX_FN:
// 扩展函数指令标识值
const (
// EXF...
)

// 扩展函数集：函数名定义。
var ExFnNames = []string{
	//
}

/*
 * 模块区（不含 MO_X）
 ******************************************************************************
 */

// MO_RE:
// 正则表达式模块：方法标识值 [0-255]
const (
	MORE_Create = iota
	MORE_Match
	// ...
)

// 正则表达式模块：方法名清单。
var MOREMethod = []string{
	//
}

// MO_TIME:
// 时间模块：方法标识值 [0-255]
const (
	MOTimeCreate = iota
	// MOTime...
)

// 时间模块：方法名清单。
var MOTimeMethod = []string{
	//
}
