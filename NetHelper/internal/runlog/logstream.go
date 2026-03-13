package runlog

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

const maxLines = 2000

var (
	once    sync.Once
	mu      sync.RWMutex
	lines   []string
	emitter func(string)
)

type writer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func Init() {
	once.Do(func() {
		log.SetOutput(io.MultiWriter(os.Stdout, &writer{}))
	})
}

func SetEmitter(fn func(string)) {
	mu.Lock()
	emitter = fn
	mu.Unlock()
}

func Snapshot(limit int) []string {
	mu.RLock()
	defer mu.RUnlock()

	n := len(lines)
	if limit <= 0 || limit >= n {
		out := make([]string, n)
		copy(out, lines)
		return out
	}
	out := make([]string, limit)
	copy(out, lines[n-limit:])
	return out
}

func appendLine(line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}

	mu.Lock()
	lines = append(lines, line)
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	fn := emitter
	mu.Unlock()

	if fn != nil {
		fn(line)
	}
}

func (w *writer) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n, _ = w.buf.Write(p)
	for {
		b := w.buf.Bytes()
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break
		}
		line := string(b[:i])
		appendLine(line)
		w.buf.Next(i + 1)
	}

	return n, nil
}
