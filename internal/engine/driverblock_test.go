package engine

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/imgk/divert-go"
	"golang.org/x/sys/windows"
)

// 「驱动被安全软件拦」的判定与报错文案。
//
// 为什么值得为它写测试：这个错误码（1450 系统资源不足）字面把人往内存/权限上带，
// 我们自己也照着查了一整天（内核池健康、管理员权限、服务条目干净、签名有效）。
// 判错方向的代价是现场白折腾，所以判定要按错误码写死，文案里不许再出现“重启系统试试”。
func TestIsDriverBlocked(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		// 火绒 6.0 的「漏洞驱动拦截」拦 WinDivert64.sys 时回的就是这个码
		{"1450 系统资源不足", divert.Error(windows.ERROR_NO_SYSTEM_RESOURCES), true},
		// WinDivert 文档里点名的“被安全软件拦”
		{"1275 驱动被拦", divert.Error(windows.ERROR_DRIVER_BLOCKED), true},
		// 真·其他原因，不能被误判成杀软
		{"2 文件找不到", divert.Error(windows.ERROR_FILE_NOT_FOUND), false},
		{"5 权限不够", divert.Error(windows.ERROR_ACCESS_DENIED), false},
		{"87 过滤器非法", divert.Error(windows.ERROR_INVALID_PARAMETER), false},
		{"577 签名无效", divert.Error(windows.ERROR_INVALID_IMAGE_HASH), false},
		{"包了一层仍然是 1450", fmt.Errorf("打开失败: %w", divert.Error(windows.ERROR_NO_SYSTEM_RESOURCES)), true},
		// 错误码拿不到时的兜底：Windows 的英文原文（这就是日志里真实出现过的那句）
		{"兜底: 英文原文",
			errors.New("Insufficient system resources exist to complete the requested service."), true},
		{"兜底: 不相关的消息", errors.New("配置不合法：routes[0] 端口越界"), false},
	}
	for _, c := range cases {
		if got := isDriverBlocked(c.err); got != c.want {
			t.Errorf("%s：isDriverBlocked = %v，期望 %v（err=%v）", c.name, got, c.want, c.err)
		}
	}
}

// 报错必须能被上层用 errors.Is 认出来（界面据此挂常驻告警条，而不是去正则匹配中文），
// 而且文案里不许再劝人“重启系统”—— 真因是杀软时那句话会把人带偏。
func TestDriverBlockedErrorCarriesHint(t *testing.T) {
	lastErr := divert.Error(windows.ERROR_NO_SYSTEM_RESOURCES)
	err := fmt.Errorf("%w（已重试 6 次）: %v\n%s", ErrDriverBlocked, lastErr, driverBlockHint())

	if !errors.Is(err, ErrDriverBlocked) {
		t.Fatalf("errors.Is 认不出 ErrDriverBlocked：%v", err)
	}
	s := err.Error()
	if strings.Contains(s, "重启系统") {
		t.Error("文案里还有“重启系统即可恢复”—— 那是错的（真因是杀软，重启也不会好）")
	}
	for _, want := range []string{"漏洞驱动拦截", "例外驱动", "WinDivert64.sys"} {
		if !strings.Contains(s, want) {
			t.Errorf("文案里缺少“%s”—— 现场照着这句话做，缺一步就白跑：\n%s", want, s)
		}
	}
	// 驱动路径要带上当前程序目录，否则现场不知道该把哪个文件加进例外
	if !strings.Contains(s, driverSysPath()) {
		t.Errorf("文案里没有完整驱动路径（%s）：\n%s", driverSysPath(), s)
	}
}
