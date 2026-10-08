package webui

import "nethub/internal/engine"

// GetRuntimeStatus 引擎自述的当前状态（诊断页「接管状态」卡）。
//
// 与日志的分工：日志回答“发生过什么”，这张卡回答“现在是什么样” ——
// 所以它**不能有**时间戳、不能是一串追加的行（那就成了第二份日志）。
// 界面上用指标行 + 状态点/徽章呈现，数值原地更新。
func (b *Backend) GetRuntimeStatus() engine.RuntimeStatus {
	return b.a.Engine.RuntimeStatus()
}

// GetKernelDetail 内核层的原始材料：覆盖的网段区间 + 两条过滤器原文。
//
// 单独一个方法、**按需**调用：原文是 3 KB 一行的条件串，不能跟着状态轮询走。
func (b *Backend) GetKernelDetail() engine.KernelDetail {
	return b.a.Engine.KernelDetail()
}
