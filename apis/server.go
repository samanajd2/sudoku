/*
Copyright (C) 2025 by ふたい <contact me via issue>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
*/
package apis

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/saba-futai/sudoku/internal/protocol"
	"github.com/saba-futai/sudoku/pkg/crypto"
	"github.com/saba-futai/sudoku/pkg/obfs/httpmask"
)

// bufferedConn 这是一个内部辅助结构，用于将 bufio 多读的数据传递给后续层
// 必须实现 net.Conn
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}

// ServerHandshake 执行 Sudoku 服务端握手逻辑
// 输入: rawConn (刚 Accept 的 TCP 连接)
// 输出:
//  1. tunnelConn: 解密后的透明连接，可直接用于应用层数据传输
//  2. targetAddr: 客户端想要访问的目标地址
//  3. error: 如果是 *HandshakeError 类型，包含了用于 Fallback 的完整数据
//
// 握手过程分为多个层次：
//  1. HTTP 伪装层：验证 HTTP POST 请求头
//  2. Sudoku 混淆层：解码 Sudoku 谜题
//  3. AEAD 加密层：解密并验证数据
//  4. 协议层：验证时间戳握手、读取目标地址
//
// 任何层次失败都会返回 HandshakeError，其中包含该层及之前所有层读取的数据
func ServerHandshake(rawConn net.Conn, cfg *ProtocolConfig) (net.Conn, string, error) {
	if cfg == nil {
		return nil, "", fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("invalid config: %w", err)
	}

	conn, fail, err := serverHandshakeCore(rawConn, cfg)
	if err != nil {
		return nil, "", err
	}

	// 4. 读取目标地址
	targetAddr, _, _, err := protocol.ReadAddress(conn)
	if err != nil {
		conn.Close()
		return nil, "", fail(fmt.Errorf("read target address failed: %w", err))
	}

	return conn, targetAddr, nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// ServerHandshakeFlexible upgrades the connection and leaves payload parsing (address or UoT) to the caller.
// The returned fail function wraps errors into HandshakeError with recorded data for fallback handling.
func ServerHandshakeFlexible(rawConn net.Conn, cfg *ProtocolConfig) (net.Conn, func(error) error, error) {
	return serverHandshakeCore(rawConn, cfg)
}

func serverHandshakeCore(rawConn net.Conn, cfg *ProtocolConfig) (net.Conn, func(error) error, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid config: %w", err)
	}

	deadline := time.Now().Add(time.Duration(cfg.HandshakeTimeoutSeconds) * time.Second)
	rawConn.SetReadDeadline(deadline)

	bufReader := bufio.NewReader(rawConn)
	shouldConsumeMask := false
	var httpHeaderData []byte

	if !cfg.DisableHTTPMask {
		if peekBytes, err := bufReader.Peek(4); err == nil && string(peekBytes) == "POST" {
			shouldConsumeMask = true
		}
	}

	if shouldConsumeMask {
		var err error
		httpHeaderData, err = httpmask.ConsumeHeader(bufReader)
		if err != nil {
			rawConn.SetReadDeadline(time.Time{})
			return nil, nil, &HandshakeError{
				Err:            fmt.Errorf("invalid http header: %w", err),
				RawConn:        rawConn,
				HTTPHeaderData: httpHeaderData,
				ReadData:       nil,
			}
		}
	}

	bConn := &bufferedConn{Conn: rawConn, r: bufReader}
	sConn, obfsConn := buildServerObfsConn(bConn, cfg, true)

	fail := func(originalErr error) error {
		rawConn.SetReadDeadline(time.Time{})
		badData := sConn.GetBufferedAndRecorded()
		return &HandshakeError{
			Err:            originalErr,
			RawConn:        rawConn,
			HTTPHeaderData: httpHeaderData,
			ReadData:       badData,
		}
	}

	cConn, err := crypto.NewAEADConn(obfsConn, cfg.Key, cfg.AEADMethod)
	if err != nil {
		return nil, nil, fail(fmt.Errorf("crypto setup failed: %w", err))
	}

	handshakeBuf := make([]byte, 16)
	if _, err := io.ReadFull(cConn, handshakeBuf); err != nil {
		cConn.Close()
		return nil, nil, fail(fmt.Errorf("read handshake failed: %w", err))
	}

	ts := int64(binary.BigEndian.Uint64(handshakeBuf[:8]))
	now := time.Now().Unix()
	if abs(now-ts) > 60 {
		cConn.Close()
		return nil, nil, fail(fmt.Errorf("timestamp skew/replay detected: server_time=%d client_time=%d", now, ts))
	}

	sConn.StopRecording()

	modeBuf := []byte{0}
	if _, err := io.ReadFull(cConn, modeBuf); err != nil {
		cConn.Close()
		return nil, nil, fail(fmt.Errorf("read downlink mode failed: %w", err))
	}
	if modeBuf[0] != downlinkMode(cfg) {
		cConn.Close()
		return nil, nil, fail(fmt.Errorf("downlink mode mismatch: client=%d server=%d", modeBuf[0], downlinkMode(cfg)))
	}

	rawConn.SetReadDeadline(time.Time{})
	return cConn, fail, nil
}
