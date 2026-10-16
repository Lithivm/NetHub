package upstream

import (
	"encoding/binary"
	"fmt"
	"net"
)

// 目标地址的线格式有**两族**，别串（串了只会表现为"连不上"，最难查）：
//
//	【A 族：SOCKS5 风格】ATYP | ADDR | PORT        —— socks5 / shadowsocks / trojan
//	    ATYP: 0x01 IPv4 / 0x03 域名(1B 长度) / 0x04 IPv6   ← 域名是 0x03
//	【B 族：xray 风格】 PORT(2B 大端) | AT | ADDR     —— vless / vmess
//	    AT:   0x01 IPv4 / 0x02 域名(1B 长度) / 0x03 IPv6   ← 域名是 0x02，**端口在最前**
//
// 两处都不同（端口位置、域名类型码），所以这里两族各给一对函数，谁也别借谁的。
// KB:资源/代理/上游协议线格式规格.md 第七节专门记过这一条坑。

// ── A 族（SOCKS5 风格）──

// appendAddr 编一个 IPv4 目标（A 族）。
func appendAddr(dst []byte, ip net.IP, port uint16) ([]byte, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", ip)
	}
	dst = append(dst, atypIPv4)
	dst = append(dst, v4...)
	return binary.BigEndian.AppendUint16(dst, port), nil
}

// appendAddrHost 编一个**域名**目标（A 族，交给上游解析）。
func appendAddrHost(dst []byte, host string, port uint16) ([]byte, error) {
	if err := checkHostLen(host); err != nil {
		return nil, err
	}
	dst = append(dst, atypDomain, byte(len(host)))
	dst = append(dst, host...)
	return binary.BigEndian.AppendUint16(dst, port), nil
}

// ── B 族（xray 风格）──

// appendAddrXray 编一个 IPv4 目标（B 族：**端口在前**）。
func appendAddrXray(dst []byte, ip net.IP, port uint16) ([]byte, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4 目标: %v", ip)
	}
	dst = binary.BigEndian.AppendUint16(dst, port)
	dst = append(dst, atypXrayIPv4)
	return append(dst, v4...), nil
}

// appendAddrHostXray 编一个**域名**目标（B 族：端口在前、域名类型码是 0x02）。
func appendAddrHostXray(dst []byte, host string, port uint16) ([]byte, error) {
	if err := checkHostLen(host); err != nil {
		return nil, err
	}
	dst = binary.BigEndian.AppendUint16(dst, port)
	dst = append(dst, atypXrayDomain, byte(len(host)))
	return append(dst, host...), nil
}

const (
	// A 族（SOCKS5 / shadowsocks / trojan）
	atypIPv4   = 0x01
	atypDomain = 0x03
	// B 族（vless / vmess）：域名是 0x02 —— 与 A 族**不同**
	atypXrayIPv4   = 0x01
	atypXrayDomain = 0x02
)

func checkHostLen(host string) error {
	if len(host) == 0 || len(host) > 255 {
		return fmt.Errorf("域名长度需在 1-255 字节: %q", host)
	}
	return nil
}
