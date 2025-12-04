package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/saba-futai/sudoku/internal/config"
	"github.com/saba-futai/sudoku/pkg/crypto"
	"github.com/saba-futai/sudoku/pkg/obfs/httpmask"
	"github.com/saba-futai/sudoku/pkg/obfs/sudoku"
)

const (
	HandshakeTimeout = 5 * time.Second
)

var (
	// bufferPool for general IO operations
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
)

// BufferedConn wraps net.Conn and bufio.Reader
type BufferedConn struct {
	net.Conn
	r          *bufio.Reader
	recorder   *bytes.Buffer
	recordLock sync.Mutex
}

func (bc *BufferedConn) Read(p []byte) (n int, err error) {
	n, err = bc.r.Read(p)
	if n > 0 && bc.recorder != nil {
		bc.recordLock.Lock()
		bc.recorder.Write(p[:n])
		bc.recordLock.Unlock()
	}
	return n, err
}

// PreBufferedConn for Split detection peek
type PreBufferedConn struct {
	net.Conn
	buf []byte
}

// NewPreBufferedConn replays the provided bytes before reading from the underlying connection.
func NewPreBufferedConn(conn net.Conn, preRead []byte) net.Conn {
	return &PreBufferedConn{Conn: conn, buf: preRead}
}

func (p *PreBufferedConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	if p.Conn == nil {
		return 0, io.EOF
	}
	return p.Conn.Read(b)
}

// GetBufferedAndRecorded returns all data that has been consumed and buffered
func (bc *BufferedConn) GetBufferedAndRecorded() []byte {
	if bc == nil {
		return nil
	}

	bc.recordLock.Lock()
	defer bc.recordLock.Unlock()

	var recorded []byte
	if bc.recorder != nil {
		recorded = bc.recorder.Bytes()
	}

	// Also get any buffered data that hasn't been read yet
	buffered := bc.r.Buffered()
	if buffered > 0 {
		peeked, _ := bc.r.Peek(buffered)
		full := make([]byte, len(recorded)+len(peeked))
		copy(full, recorded)
		copy(full[len(recorded):], peeked)
		return full
	}
	return recorded
}

// SuspiciousError indicates a potential attack or protocol violation
type SuspiciousError struct {
	Err  error
	Conn net.Conn // The connection at the state where error occurred (for fallback/logging)
}

func (e *SuspiciousError) Error() string {
	return e.Err.Error()
}

// HandshakeAndUpgrade wraps the raw connection with Sudoku/Crypto and performs handshake.
func HandshakeAndUpgrade(rawConn net.Conn, cfg *config.Config, table *sudoku.Table) (net.Conn, error) {
	// 0. HTTP Header Check
	bufReader := bufio.NewReader(rawConn)
	rawConn.SetReadDeadline(time.Now().Add(HandshakeTimeout))

	shouldConsumeMask := false
	var consumed []byte
	var err error

	if !cfg.DisableHTTPMask {
		peekBytes, _ := bufReader.Peek(4) // Ignore error, if peek fails, we assume no mask or let subsequent read handle it
		if len(peekBytes) == 4 && string(peekBytes) == "POST" {
			shouldConsumeMask = true
		}
	}

	if shouldConsumeMask {
		consumed, err = httpmask.ConsumeHeader(bufReader)
		if err != nil {
			rawConn.SetReadDeadline(time.Time{})
			// Return rawConn wrapped in BufferedConn so caller can handle fallback
			// Enable recording to capture all consumed data for fallback replay
			recorder := new(bytes.Buffer)
			if len(consumed) > 0 {
				recorder.Write(consumed)
			}
			badConn := &BufferedConn{
				Conn:     rawConn,
				r:        bufReader,
				recorder: recorder,
			}
			return nil, &SuspiciousError{Err: fmt.Errorf("invalid http header: %w", err), Conn: badConn}
		}
	}
	rawConn.SetReadDeadline(time.Time{})

	bConn := &BufferedConn{Conn: rawConn, r: bufReader}

	// 1. Sudoku Layer
	if !cfg.EnablePureDownlink && cfg.AEAD == "none" {
		return nil, fmt.Errorf("enable_pure_downlink=false requires AEAD")
	}
	sConn, obfsConn := buildObfsConnForServer(bConn, table, cfg, true)

	// 2. Crypto Layer
	cConn, err := crypto.NewAEADConn(obfsConn, cfg.Key, cfg.AEAD)
	if err != nil {
		return nil, fmt.Errorf("crypto setup failed: %w", err)
	}

	// 3. Handshake
	handshakeBuf := make([]byte, 16)
	rawConn.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	_, err = io.ReadFull(cConn, handshakeBuf)
	rawConn.SetReadDeadline(time.Time{})

	if err != nil {
		return nil, &SuspiciousError{Err: fmt.Errorf("handshake read failed: %w", err), Conn: sConn}
	}

	ts := int64(binary.BigEndian.Uint64(handshakeBuf[:8]))
	if abs(time.Now().Unix()-ts) > 60 {
		return nil, &SuspiciousError{Err: fmt.Errorf("time skew/replay"), Conn: sConn}
	}

	sConn.StopRecording()

	// 4. Downlink mode negotiation
	modeBuf := make([]byte, 1)
	rawConn.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	if _, err := io.ReadFull(cConn, modeBuf); err != nil {
		cConn.Close()
		return nil, fmt.Errorf("read downlink mode failed: %w", err)
	}
	rawConn.SetReadDeadline(time.Time{})
	if modeBuf[0] != downlinkModeByte(cfg) {
		cConn.Close()
		return nil, &SuspiciousError{Err: fmt.Errorf("downlink mode mismatch: client=%d server=%d", modeBuf[0], downlinkModeByte(cfg)), Conn: sConn}
	}

	return cConn, nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
