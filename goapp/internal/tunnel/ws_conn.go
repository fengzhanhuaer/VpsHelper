package tunnel

import (
	"io"
	"time"

	"github.com/gorilla/websocket"
)

// WsConn is a wrapper that implements io.ReadWriteCloser around a websocket.Conn
type WsConn struct {
	*websocket.Conn
	r io.Reader
}

func (c *WsConn) Read(p []byte) (int, error) {
	for {
		if c.r == nil {
			// Get next message payload
			msgType, reader, err := c.Conn.NextReader()
			if err != nil {
				return 0, err
			}
			if msgType != websocket.BinaryMessage && msgType != websocket.TextMessage {
				continue // skip non-data messages (pings/pongs are handled automatically)
			}
			c.r = reader
		}

		n, err := c.r.Read(p)
		if err == io.EOF {
			// Finished reading this particular websocket message payload,
			// reset reader to grab the next message on next Read call
			c.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *WsConn) Write(p []byte) (int, error) {
	err := c.Conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *WsConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}
