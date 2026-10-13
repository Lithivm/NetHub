package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

type demoView struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type demo struct {
	mu    sync.Mutex
	calls []string
}

func (d *demo) note(s string) {
	d.mu.Lock()
	d.calls = append(d.calls, s)
	d.mu.Unlock()
}

func (d *demo) Echo(s string, n int) (string, error) {
	d.note("Echo")
	return fmt.Sprintf("%s/%d", s, n), nil
}

func (d *demo) Sum(xs []int) int {
	total := 0
	for _, x := range xs {
		total += x
	}
	return total
}

func (d *demo) View() demoView { return demoView{Name: "nethub", Count: 7} }

func (d *demo) Nothing() {}

func (d *demo) Boom() error { return errors.New("炸了") }

// private 故意留着：远程调用必须够不着它。
func (d *demo) private() string { return "不该被调到" }

func testPipe(t *testing.T) string {
	t.Helper()
	return PipeName(fmt.Sprintf("test-%d-%d", os.Getpid(), time.Now().UnixNano()%100000))
}

func startServer(t *testing.T, target any) *Server {
	t.Helper()
	srv := NewServer(testPipe(t), target)
	if err := srv.Start(); err != nil {
		t.Fatalf("起服务端失败: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func dialServer(t *testing.T, srv *Server) *Client {
	t.Helper()
	c, err := Dial(srv.name, 3*time.Second)
	if err != nil {
		t.Fatalf("连管道失败: %v", err)
	}
	t.Cleanup(c.Close)
	// Dial 只保证"客户端连上了"；服务端发现自己被连上是异步的，等它一下再往下走
	deadline := time.Now().Add(2 * time.Second)
	for !srv.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("服务端迟迟没发现界面连上")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return c
}

func callString(t *testing.T, c *Client, method string, args ...any) string {
	t.Helper()
	raw, err := c.Call(context.Background(), method, args...)
	if err != nil {
		t.Fatalf("调 %s 失败: %v", method, err)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("调 %s 的结果不是字符串: %v (%s)", method, err, raw)
	}
	return s
}

func TestCallDispatch(t *testing.T) {
	d := &demo{}
	srv := startServer(t, d)
	c := dialServer(t, srv)

	if got := callString(t, c, "Echo", "hi", 3); got != "hi/3" {
		t.Fatalf("Echo 结果不对: %q", got)
	}

	raw, err := c.Call(context.Background(), "Sum", []int{1, 2, 3})
	if err != nil {
		t.Fatalf("Sum 失败: %v", err)
	}
	if string(raw) != "6" {
		t.Fatalf("Sum 结果不对: %s", raw)
	}

	raw, err = c.Call(context.Background(), "View")
	if err != nil {
		t.Fatalf("View 失败: %v", err)
	}
	var v demoView
	if err := json.Unmarshal(raw, &v); err != nil || v.Name != "nethub" || v.Count != 7 {
		t.Fatalf("View 结构不对: %v %s", err, raw)
	}

	// 无返回值的方法：结果应该是 null
	if raw, err = c.Call(context.Background(), "Nothing"); err != nil || string(raw) != "null" {
		t.Fatalf("Nothing 应该成功且返回 null，实际 %s / %v", raw, err)
	}

	// error 要能原样传回前端（前端的 catch 靠它显示人话）
	if _, err = c.Call(context.Background(), "Boom"); err == nil || err.Error() != "炸了" {
		t.Fatalf("Boom 的错误没有传回来: %v", err)
	}

	// 私有方法 / 不存在的方法 / 参数个数不对，都必须被挡住
	for _, tc := range []struct {
		method string
		args   []any
	}{
		{"private", nil},
		{"NoSuchMethod", nil},
		{"Echo", []any{"只有一个参数"}},
	} {
		if _, err := c.Call(context.Background(), tc.method, tc.args...); err == nil {
			t.Fatalf("%s 本该被拒绝", tc.method)
		}
	}
}

func TestEventAndReverseRequest(t *testing.T) {
	srv := startServer(t, &demo{})
	c := dialServer(t, srv)

	var (
		gotEvent string
		evMu     sync.Mutex
	)
	c.SetEventHandler(func(name string, data json.RawMessage) {
		evMu.Lock()
		gotEvent = name + ":" + string(data)
		evMu.Unlock()
	})
	c.SetRequestHandler(func(op string, args []json.RawMessage) (any, error) {
		if op != "openFile" {
			return nil, fmt.Errorf("不认识 %s", op)
		}
		return `C:\tmp\a.yaml`, nil
	})

	if err := srv.Emit("log", map[string]any{"line": "hello"}); err != nil {
		t.Fatalf("推事件失败: %v", err)
	}

	// 事件是异步的，等一下
	deadline := time.Now().Add(2 * time.Second)
	for {
		evMu.Lock()
		got := gotEvent
		evMu.Unlock()
		if got != "" {
			if got != `log:{"line":"hello"}` {
				t.Fatalf("事件内容不对: %s", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("没收到事件")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 反向请求：引擎问界面要一个路径
	res, err := srv.Request(context.Background(), "openFile", map[string]any{"title": "选配置"})
	if err != nil {
		t.Fatalf("反向请求失败: %v", err)
	}
	var path string
	if err := json.Unmarshal(res, &path); err != nil || path != `C:\tmp\a.yaml` {
		t.Fatalf("反向请求结果不对: %s (%v)", res, err)
	}

	// 界面不认识的操作要如实报错，不能假装成功
	if _, err := srv.Request(context.Background(), "noSuchOp"); err == nil {
		t.Fatal("不认识的反向操作本该报错")
	}
}

func TestNoUIAndDisconnect(t *testing.T) {
	srv := startServer(t, &demo{})

	// 没有界面时：推事件返回 ErrNoUI（引擎不该因此崩），反向请求当场失败
	if err := srv.Emit("log", nil); !errors.Is(err, ErrNoUI) {
		t.Fatalf("没有界面时 Emit 应该返回 ErrNoUI，实际 %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := srv.Request(ctx, "openFile"); !errors.Is(err, ErrNoUI) {
		t.Fatalf("没有界面时 Request 应该返回 ErrNoUI，实际 %v", err)
	}

	// 界面连上再断开：服务端要能发现，并且能重新接上下一个界面
	c1 := dialServer(t, srv)
	c1.Close()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("界面断开后服务端还认为它连着")
		}
		time.Sleep(10 * time.Millisecond)
	}

	c2, err := Dial(srv.name, 3*time.Second)
	if err != nil {
		t.Fatalf("界面重连失败: %v", err)
	}
	defer c2.Close()
	if got := callString(t, c2, "Echo", "again", 1); got != "again/1" {
		t.Fatalf("重连后调用失败: %q", got)
	}
}
