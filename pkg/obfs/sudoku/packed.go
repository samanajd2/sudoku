package sudoku

import (
	"bufio"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"sync"
)

const (
	// 每次从 RNG 获取批量随机数的缓存大小，减少 RNG 函数调用开销
	RngBatchSize = 128
)

// PackedConn 优化版：
// 1. 使用 3字节->4组 的块处理优化 Write。
// 2. 使用整数递减计数器替代浮点数概率判断来处理 Padding。
type PackedConn struct {
	net.Conn
	table  *Table
	reader *bufio.Reader

	// 读缓冲
	rawBuf      []byte
	pendingData []byte // 解码后尚未被 Read 取走的字节

	// 写缓冲与状态
	writeMu  sync.Mutex
	writeBuf []byte
	bitBuf   uint64 // 暂存的位数据
	bitCount int    // 暂存的位数

	// 读状态
	readBitBuf uint64
	readBits   int

	// 随机数与填充控制
	rng          *rand.Rand
	padInterval  int // 平均多少个字节插入一个 padding
	padCountdown int // 倒计数，减到 0 时插入 padding
	padMarker    byte
	padPool      []byte
}

func NewPackedConn(c net.Conn, table *Table, pMin, pMax int) *PackedConn {
	var seedBytes [8]byte
	if _, err := crypto_rand.Read(seedBytes[:]); err != nil {
		binary.BigEndian.PutUint64(seedBytes[:], uint64(rand.Int63()))
	}
	seed := int64(binary.BigEndian.Uint64(seedBytes[:]))
	localRng := rand.New(rand.NewSource(seed))

	// 计算平均填充间隔。例如 rate=0.05 (5%)，则平均间隔 20 个字节。
	// 避免在热路径中使用浮点数。
	avgRate := float32(pMin+pMax) / 200.0 // /200是因为pMin是百分比
	interval := 10000
	if avgRate > 0.0001 {
		interval = int(1.0 / avgRate)
	}

	pc := &PackedConn{
		Conn:         c,
		table:        table,
		reader:       bufio.NewReaderSize(c, IOBufferSize),
		rawBuf:       make([]byte, IOBufferSize),
		pendingData:  make([]byte, 0, 4096),
		writeBuf:     make([]byte, 0, 4096),
		rng:          localRng,
		padInterval:  interval,
		padCountdown: localRng.Intn(interval + 1),
	}
	if table.IsASCII {
		pc.padMarker = 0x3F
		for _, b := range table.PaddingPool {
			if b != pc.padMarker {
				pc.padPool = append(pc.padPool, b)
			}
		}
	} else {
		pc.padMarker = 0x80
		for _, b := range table.PaddingPool {
			if b != pc.padMarker {
				pc.padPool = append(pc.padPool, b)
			}
		}
	}
	if len(pc.padPool) == 0 {
		pc.padPool = append(pc.padPool, pc.padMarker)
	}
	return pc
}

// Write 极致优化版
func (pc *PackedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	// 1. 预分配内存，避免 append 导致的多次扩容
	// 预估：原数据 * 1.34 (4/3) + 填充余量
	needed := len(p) + len(p)/3 + len(p)/pc.padInterval + 16
	if cap(pc.writeBuf) < needed {
		pc.writeBuf = make([]byte, 0, needed)
	}
	out := pc.writeBuf[:0]

	i := 0
	n := len(p)

	// 2. 头部对齐处理 (Slow Path)
	// 如果之前有残留的 bit (bitCount != 0)，先逐字节处理直到凑齐 6 bit 发送，
	// 或者凑齐字节对齐。为了简单且兼容，如果 bitCount > 0，我们先逐个处理直到 bitCount 归零
	// 通常 bitCount 只会是 0, 2, 4 (因为输入是 8bit，输出消耗 6bit)
	for pc.bitCount > 0 && i < n {
		b := p[i]
		i++
		pc.bitBuf = (pc.bitBuf << 8) | uint64(b)
		pc.bitCount += 8
		for pc.bitCount >= 6 {
			pc.bitCount -= 6
			group := byte(pc.bitBuf >> pc.bitCount)
			// 清理已使用的位，防止 bitBuf 过大（虽然 uint64 很大，但保持干净更好）
			// 这里的 mask 其实不是必须的，只要 shift 逻辑对即可，但为了逻辑严谨：
			if pc.bitCount == 0 {
				pc.bitBuf = 0
			} else {
				pc.bitBuf &= (1 << pc.bitCount) - 1
			}

			// 插入填充检查
			if pc.padCountdown--; pc.padCountdown <= 0 {
				out = append(out, pc.getPaddingByte())
				pc.padCountdown = pc.rng.Intn(pc.padInterval) + 1
			}
			out = append(out, pc.encodeGroup(group&0x3F))
		}
	}

	// 3. 极速块处理 (Fast Path)
	// 现在的状态是：pc.bitCount == 0 (或非常接近0，但在上述逻辑中我们尽量让其清空)
	// 我们可以每次处理 3 个字节 -> 生成 4 个编码组
	// 这样完全避免了 bitCount 的加减判断循环
	for i+2 < n {
		// 检查填充：为了不打断 4 字节的连续写入带来的性能优势，
		// 我们在这里检查一次，如果需要填充，就在这组 4 个字节之前插入。
		if pc.padCountdown <= 0 {
			out = append(out, pc.getPaddingByte())
			pc.padCountdown = pc.rng.Intn(pc.padInterval) + 1
		}
		// 每次处理 3 个字节消耗 24 bits，产生 4 个输出字节，倒计时减 4
		pc.padCountdown -= 4

		// 读取 3 个字节组合成 24 位整数
		// b1(8) | b2(8) | b3(8)
		b1, b2, b3 := p[i], p[i+1], p[i+2]

		// 提取 4 个 6-bit 组
		// Group 1: b1 高 6 位
		g1 := (b1 >> 2) & 0x3F
		// Group 2: b1 低 2 位 + b2 高 4 位
		g2 := ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)
		// Group 3: b2 低 4 位 + b3 高 2 位
		g3 := ((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)
		// Group 4: b3 低 6 位
		g4 := b3 & 0x3F

		out = append(out,
			pc.encodeGroup(g1),
			pc.encodeGroup(g2),
			pc.encodeGroup(g3),
			pc.encodeGroup(g4),
		)

		i += 3
	}

	// 4. 尾部处理 (Tail Path)
	// 处理剩余的 1 或 2 个字节
	for ; i < n; i++ {
		b := p[i]
		pc.bitBuf = (pc.bitBuf << 8) | uint64(b)
		pc.bitCount += 8
		for pc.bitCount >= 6 {
			pc.bitCount -= 6
			group := byte(pc.bitBuf >> pc.bitCount)
			if pc.bitCount == 0 {
				pc.bitBuf = 0
			} else {
				pc.bitBuf &= (1 << pc.bitCount) - 1
			}

			if pc.padCountdown--; pc.padCountdown <= 0 {
				out = append(out, pc.getPaddingByte())
				pc.padCountdown = pc.rng.Intn(pc.padInterval) + 1
			}
			out = append(out, pc.encodeGroup(group&0x3F))
		}
	}

	if pc.bitCount > 0 {
		if pc.padCountdown--; pc.padCountdown <= 0 {
			out = append(out, pc.getPaddingByte())
			pc.padCountdown = pc.rng.Intn(pc.padInterval) + 1
		}
		group := byte(pc.bitBuf << (6 - pc.bitCount))
		pc.bitBuf = 0
		pc.bitCount = 0
		out = append(out, pc.encodeGroup(group&0x3F))
		out = append(out, pc.padMarker)
	}

	// 发送数据
	if len(out) > 0 {
		_, err := pc.Conn.Write(out)
		// 保存 buffer 引用以便复用容量（注意：out 是 slice，底层 array 在 pc.writeBuf）
		pc.writeBuf = out[:0]
		return len(p), err
	}
	pc.writeBuf = out[:0]
	return len(p), nil
}

// Flush 保持逻辑不变，处理最后不足 6 bit 的情况
func (pc *PackedConn) Flush() error {
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	out := pc.writeBuf[:0]
	if pc.bitCount > 0 {
		// 左移补零
		group := byte(pc.bitBuf << (6 - pc.bitCount))
		pc.bitBuf = 0
		pc.bitCount = 0

		out = append(out, pc.encodeGroup(group&0x3F))
		out = append(out, pc.padMarker)
	}

	// 随机决定是否在末尾额外添加一个 Padding
	if pc.padCountdown <= 5 {
		out = append(out, pc.getPaddingByte())
		pc.padCountdown = pc.rng.Intn(pc.padInterval) + 1
	}

	if len(out) > 0 {
		_, err := pc.Conn.Write(out)
		pc.writeBuf = out[:0]
		return err
	}
	return nil
}

// Read 优化版：减少切片操作，优化解码循环
func (pc *PackedConn) Read(p []byte) (int, error) {
	// 1. 优先返回待处理区的数据
	if len(pc.pendingData) > 0 {
		n := copy(p, pc.pendingData)
		// 调整 pendingData
		if n == len(pc.pendingData) {
			// 如果全读完了，重置切片长度为0，保留容量
			pc.pendingData = pc.pendingData[:0]
		} else {
			pc.pendingData = pc.pendingData[n:]
		}
		return n, nil
	}

	// 2. 循环读取直到解出数据或出错
	for {
		nr, rErr := pc.reader.Read(pc.rawBuf)
		if nr > 0 {
			// 优化解码循环：尽量减少函数调用和内存分配
			// 这里我们直接向 pendingData 追加解码后的字节

			// 缓存频繁访问的变量到寄存器/栈
			rBuf := pc.readBitBuf
			rBits := pc.readBits
			isASCII := pc.table.IsASCII // 缓存配置项，避免每次都访问 pc.table

			for _, b := range pc.rawBuf[:nr] {
				// 内联 isPadding 逻辑
				var isPad bool
				if isASCII {
					isPad = (b & 0x40) == 0
				} else {
					isPad = (b & 0x90) != 0
				}

				if isPad {
					if b == pc.padMarker {
						rBuf = 0
						rBits = 0
					}
					continue
				}

				// 内联 decodeGroup 逻辑
				var group byte
				if isASCII {
					group = b & 0x3F
				} else {
					// 0xx0xxxx -> bits[5:4] -> 6:5, low nibble stays
					group = ((b >> 1) & 0x30) | (b & 0x0F)
				}

				rBuf = (rBuf << 6) | uint64(group)
				rBits += 6

				if rBits >= 8 {
					rBits -= 8
					val := byte(rBuf >> rBits)
					// rBuf 清理高位非必需，因为下次 << 6 会把新数据推上去，
					// 但为了防止 uint64 溢出（极难发生），可以保留 rBuf &= ...
					// 在 Go 中 uint64 足够容纳积累的位，只要及时提取。
					pc.pendingData = append(pc.pendingData, val)
				}
			}

			// 写回状态
			pc.readBitBuf = rBuf
			pc.readBits = rBits
		}

		// 处理错误或 EOF
		if rErr != nil {
			if rErr == io.EOF {
				pc.readBitBuf = 0
				pc.readBits = 0
			}
			if len(pc.pendingData) > 0 {
				break // 先返回已解码的数据，下次再返回 Error
			}
			return 0, rErr
		}

		if len(pc.pendingData) > 0 {
			break
		}
	}

	// 3. 将解码后的数据复制给用户
	n := copy(p, pc.pendingData)
	if n == len(pc.pendingData) {
		pc.pendingData = pc.pendingData[:0]
	} else {
		pc.pendingData = pc.pendingData[n:]
	}
	return n, nil
}

// 辅助函数：从 Pool 中随机取 Padding 字节
// 这里的 rng.Intn 比较快，且不在最热的循环里（每隔几十个字节才调用一次）
func (pc *PackedConn) getPaddingByte() byte {
	pads := pc.padPool
	return pads[pc.rng.Intn(len(pads))]
}

// 辅助函数：编码 Group (内联候补)
func (pc *PackedConn) encodeGroup(group byte) byte {
	// group 必须是 0-63
	if pc.table.IsASCII {
		return 0x40 | group // 01xxxxxx
	}
	// Binary Mode: 0xx0xxxx
	// bits[5:4] -> move to bit 6:5? No.
	// logic: ((group & 0x30) << 1) | (group & 0x0F)
	// group 00111111 (0x3F)
	// 0x30 = 00110000 -> << 1 -> 01100000 (0x60)
	// 0x0F = 00001111 ->         00001111 (0x0F)
	// Result: 01101111
	return ((group & 0x30) << 1) | (group & 0x0F)
}
