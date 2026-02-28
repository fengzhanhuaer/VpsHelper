package logger

import (
	"bytes"
	"io"
	"log"
	"os"
	"strconv"
	"sync"
)

var (
	GlobalBuffer *RingBuffer
)

func Init(maxLines int) {
	if s := os.Getenv("VPS_LOG_LINES"); s != "" {
		if val, err := strconv.Atoi(s); err == nil && val > 0 {
			maxLines = val
		}
	}
	if maxLines <= 0 {
		maxLines = 500
	}
	GlobalBuffer = &RingBuffer{
		maxLines: maxLines,
		lines:    make([][]byte, maxLines),
	}
	// We want to write to both the system stream and our memory buffer.
	// We use io.MultiWriter to do both so systemd still outputs logs to terminal,
	// but the web UI / remote UI fetches directly from GlobalBuffer.
	log.SetOutput(io.MultiWriter(os.Stdout, GlobalBuffer))
}

func SetMaxLines(maxLines int) {
	if GlobalBuffer != nil {
		GlobalBuffer.SetMaxLines(maxLines)
	}
}

func GetLogs() string {
	if GlobalBuffer != nil {
		return GlobalBuffer.GetLogs()
	}
	return "No logs"
}

type RingBuffer struct {
	mu       sync.Mutex
	maxLines int
	lines    [][]byte
	head     int
	count    int
}

func (b *RingBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// In the log package, Write is typically called with a payload ending with '\n'
	parts := bytes.Split(p, []byte{'\n'})
	for i, part := range parts {
		if i == len(parts)-1 && len(part) == 0 {
			continue // skip trailing newline
		}
		
		line := make([]byte, len(part))
		copy(line, part)

		b.lines[b.head] = line
		b.head = (b.head + 1) % b.maxLines
		if b.count < b.maxLines {
			b.count++
		}
	}
	return len(p), nil
}

func (b *RingBuffer) GetLogs() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.count == 0 {
		return "暂无日志 / No in-memory logs found"
	}

	var buf bytes.Buffer
	start := b.head - b.count
	if start < 0 {
		start += b.maxLines
	}

	for i := 0; i < b.count; i++ {
		idx := (start + i) % b.maxLines
		buf.Write(b.lines[idx])
		buf.WriteByte('\n')
	}
	return buf.String()
}

func (b *RingBuffer) SetMaxLines(maxLines int) {
	if maxLines <= 0 {
		maxLines = 500
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if maxLines == b.maxLines {
		return
	}

	newLines := make([][]byte, maxLines)
	var copyCount int
	if b.count > maxLines {
		copyCount = maxLines
	} else {
		copyCount = b.count
	}

	start := b.head - copyCount
	if start < 0 {
		start += b.maxLines
	}

	for i := 0; i < copyCount; i++ {
		idx := (start + i) % b.maxLines
		newLines[i] = b.lines[idx]
	}

	b.lines = newLines
	b.maxLines = maxLines
	b.head = copyCount % maxLines
	b.count = copyCount
}
