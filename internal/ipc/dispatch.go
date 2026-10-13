package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

var errType = reflect.TypeOf((*error)(nil)).Elem()
var ctxType = reflect.TypeOf((*context.Context)(nil)).Elem()

// dispatch 反射调用 target 上名为 method 的方法：参数从 JSON 解，结果编成 JSON。
//
// 为什么用反射而不是给每个方法写一行转发：webui.Backend 有 80 多个导出方法，
// 手抄一遍既费事又会长期漂移（加了方法忘了加转发 = 界面上那个按钮永远报错）。
//
// 安全边界：只允许调用**导出**方法。名字是前端传来的字符串，如果私有方法可达，
// 就等于开了一条远程调内部函数的门（比如 setReadOnly 能把界面直接切进只读态）。
func dispatch(target any, method string, args []json.RawMessage) (json.RawMessage, error) {
	if target == nil {
		return nil, errors.New("ipc: 没有可派发的目标")
	}
	if method == "" || !isExported(method) {
		return nil, fmt.Errorf("ipc: 不认识的调用 %q", method)
	}
	m := reflect.ValueOf(target).MethodByName(method)
	if !m.IsValid() {
		return nil, fmt.Errorf("ipc: 引擎上没有方法 %q", method)
	}
	t := m.Type()
	if t.IsVariadic() {
		return nil, fmt.Errorf("ipc: 方法 %s 是可变参数，不能远程调用", method)
	}
	if t.NumIn() != len(args) {
		return nil, fmt.Errorf("ipc: 方法 %s 需要 %d 个参数，收到 %d 个", method, t.NumIn(), len(args))
	}
	in := make([]reflect.Value, t.NumIn())
	for i := range in {
		pt := t.In(i)
		if pt == ctxType {
			// Wails 的生命周期钩子（OnStartup 之类）长这样；它们本来就该由界面进程
			// 自己处理，不走管道。
			return nil, fmt.Errorf("ipc: 方法 %s 带 context 入参，不支持远程调用", method)
		}
		pv := reflect.New(pt)
		if len(args[i]) > 0 {
			if err := json.Unmarshal(args[i], pv.Interface()); err != nil {
				return nil, fmt.Errorf("ipc: 方法 %s 的第 %d 个参数解析失败: %w", method, i+1, err)
			}
		}
		in[i] = pv.Elem()
	}

	out := m.Call(in)

	// 返回值约定（与 Wails bindings 一致）：可选的一个结果 + 结尾可选的 error。
	if n := len(out); n > 0 && out[n-1].Type() == errType {
		if last := out[n-1]; !last.IsNil() {
			return nil, last.Interface().(error)
		}
		out = out[:n-1]
	}
	switch len(out) {
	case 0:
		return json.RawMessage("null"), nil
	case 1:
		b, err := json.Marshal(out[0].Interface())
		if err != nil {
			return nil, fmt.Errorf("ipc: 方法 %s 的结果无法序列化: %w", method, err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("ipc: 方法 %s 返回了 %d 个值，最多支持 1 个", method, len(out))
	}
}

// isExported 判断首字符是不是 ASCII 大写字母（Go 的导出性就是这么定的）。
func isExported(name string) bool {
	if name == "" {
		return false
	}
	c := name[0]
	return c >= 'A' && c <= 'Z'
}
