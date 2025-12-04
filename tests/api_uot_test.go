package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/saba-futai/sudoku/apis"
	"github.com/saba-futai/sudoku/pkg/obfs/sudoku"
)

func TestAPIPackedDownlinkEcho(t *testing.T) {
	table := sudoku.NewTable("api-packed-seed", "prefer_ascii")
	cfg := &apis.ProtocolConfig{
		ServerAddress:           "",
		TargetAddress:           "",
		Key:                     "api-packed-key",
		AEADMethod:              "chacha20-poly1305",
		Table:                   table,
		PaddingMin:              8,
		PaddingMax:              16,
		EnablePureDownlink:      false,
		HandshakeTimeoutSeconds: 5,
		DisableHTTPMask:         false,
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer l.Close()
	addr := l.Addr().String()

	serverCfg := *cfg
	serverCfg.ServerAddress = addr
	serverCfg.TargetAddress = ""

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tun, _, err := apis.ServerHandshake(c, &serverCfg)
				if err != nil {
					return
				}
				defer tun.Close()
				io.Copy(tun, tun)
			}(conn)
		}
	}()

	clientCfg := *cfg
	clientCfg.ServerAddress = addr
	clientCfg.TargetAddress = "example.com:80"

	conn, err := apis.Dial(context.Background(), &clientCfg)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("api packed downlink echo")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: %q vs %q", msg, buf)
	}
}

func TestAPIUoT(t *testing.T) {
	table := sudoku.NewTable("api-uot-seed", "prefer_entropy")
	cfg := &apis.ProtocolConfig{
		Key:                     "api-uot-key",
		AEADMethod:              "aes-128-gcm",
		Table:                   table,
		PaddingMin:              5,
		PaddingMax:              12,
		EnablePureDownlink:      true,
		HandshakeTimeoutSeconds: 5,
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer l.Close()
	addr := l.Addr().String()

	udpEcho, udpPort, err := startUDPEchoServer()
	if err != nil {
		t.Fatalf("udp echo failed: %v", err)
	}
	defer udpEcho.Close()

	errCh := make(chan error, 4)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tun, fail, err := apis.ServerHandshakeFlexible(c, cfg)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				isUoT, tuned, err := apis.DetectUoT(tun)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				if !isUoT {
					select {
					case errCh <- fail(io.ErrUnexpectedEOF):
					default:
					}
					return
				}
				if err := apis.HandleUoT(tuned); err != nil {
					select {
					case errCh <- err:
					default:
					}
				}
			}(conn)
		}
	}()

	clientCfg := *cfg
	clientCfg.ServerAddress = addr
	clientCfg.TargetAddress = "0.0.0.0:0" // placeholder for validation

	t.Log("dialing UoT client")
	conn, err := apis.DialUDPOverTCP(context.Background(), &clientCfg)
	if err != nil {
		t.Fatalf("dial uot failed: %v", err)
	}
	defer conn.Close()

	target := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", udpPort))
	payload := []byte("api uot ping")

	t.Log("sending datagram")
	if err := apis.WriteUoTDatagram(conn, target, payload); err != nil {
		t.Fatalf("write uot datagram failed: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	t.Log("waiting for response")
	addrStr, data, err := apis.ReadUoTDatagram(conn)
	if err != nil {
		t.Fatalf("read uot datagram failed: %v", err)
	}
	if addrStr != target {
		t.Fatalf("unexpected addr: %s", addrStr)
	}
	if string(data) != string(payload) {
		t.Fatalf("unexpected payload: %q", data)
	}

	select {
	case err := <-errCh:
		t.Fatalf("server side error: %v", err)
	default:
	}
}
