//go:build windows

package conntrack

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                  = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable   = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable   = iphlpapi.NewProc("GetExtendedUdpTable")
)

// TCP 状态映射
var tcpStateMap = map[uint32]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RCVD",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT1",
	7:  "FIN_WAIT2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE_TCB",
}

// MIB_TCPROW_OWNER_PID (IPv4 with PID)
type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_UDPROW_OWNER_PID
type mibUdpRowOwnerPid struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

func snapshot() ([]Connection, error) {
	conns := make([]Connection, 0, 128)

	tcpConns, err := getTcpConnections()
	if err == nil {
		conns = append(conns, tcpConns...)
	}

	udpConns, err := getUdpConnections()
	if err == nil {
		conns = append(conns, udpConns...)
	}

	// 填充进程名
	pidNames := make(map[uint32]string)
	for i := range conns {
		pid := conns[i].PID
		if pid == 0 {
			conns[i].ProcName = "System"
			continue
		}
		if name, ok := pidNames[pid]; ok {
			conns[i].ProcName = name
		} else {
			name := getProcName(pid)
			pidNames[pid] = name
			conns[i].ProcName = name
		}
	}

	return conns, nil
}

func getTcpConnections() ([]Connection, error) {
	// TCP_TABLE_OWNER_PID_ALL = 5
	const tableType = 5
	var buf []byte
	var size uint32
	for {
		var p unsafe.Pointer
		if len(buf) > 0 {
			p = unsafe.Pointer(&buf[0])
		}
		r, _, _ := procGetExtendedTcpTable.Call(
			uintptr(p),
			uintptr(unsafe.Pointer(&size)),
			1, // bOrder = true
			windows.AF_INET,
			tableType,
			0,
		)
		if r == 0 {
			break
		}
		if r == 122 { // ERROR_INSUFFICIENT_BUFFER
			buf = make([]byte, size)
			continue
		}
		return nil, fmt.Errorf("GetExtendedTcpTable error: %d", r)
	}

	if len(buf) < 4 {
		return nil, nil
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	rowSize := uint32(unsafe.Sizeof(mibTcpRowOwnerPid{}))
	conns := make([]Connection, 0, numEntries)
	offset := uint32(4)

	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > uint32(len(buf)) {
			break
		}
		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		localIP := intToIP(row.LocalAddr)
		remoteIP := intToIP(row.RemoteAddr)
		localPort := portFromNetwork(row.LocalPort)
		remotePort := portFromNetwork(row.RemotePort)
		state := tcpStateMap[row.State]
		if state == "" {
			state = fmt.Sprintf("STATE_%d", row.State)
		}

		conns = append(conns, Connection{
			PID:        row.OwningPid,
			Protocol:   "TCP",
			LocalAddr:  fmt.Sprintf("%s:%d", localIP, localPort),
			RemoteAddr: fmt.Sprintf("%s:%d", remoteIP, remotePort),
			State:      state,
		})
	}
	return conns, nil
}

func getUdpConnections() ([]Connection, error) {
	// UDP_TABLE_OWNER_PID = 1
	const tableType = 1
	var buf []byte
	var size uint32
	for {
		var p unsafe.Pointer
		if len(buf) > 0 {
			p = unsafe.Pointer(&buf[0])
		}
		r, _, _ := procGetExtendedUdpTable.Call(
			uintptr(p),
			uintptr(unsafe.Pointer(&size)),
			1,
			windows.AF_INET,
			tableType,
			0,
		)
		if r == 0 {
			break
		}
		if r == 122 {
			buf = make([]byte, size)
			continue
		}
		return nil, fmt.Errorf("GetExtendedUdpTable error: %d", r)
	}

	if len(buf) < 4 {
		return nil, nil
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	rowSize := uint32(unsafe.Sizeof(mibUdpRowOwnerPid{}))
	conns := make([]Connection, 0, numEntries)
	offset := uint32(4)

	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > uint32(len(buf)) {
			break
		}
		row := (*mibUdpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		localIP := intToIP(row.LocalAddr)
		localPort := portFromNetwork(row.LocalPort)

		conns = append(conns, Connection{
			PID:        row.OwningPid,
			Protocol:   "UDP",
			LocalAddr:  fmt.Sprintf("%s:%d", localIP, localPort),
			RemoteAddr: "*:*",
			State:      "—",
		})
	}
	return conns, nil
}

// getProcName 通过 PID 获取进程名（失败时返回 PID 字符串）
func getProcName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Sprintf("[%d]", pid)
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
	if err != nil {
		return fmt.Sprintf("[%d]", pid)
	}
	fullPath := windows.UTF16ToString(buf[:size])
	// 只取文件名部分
	for i := len(fullPath) - 1; i >= 0; i-- {
		if fullPath[i] == '\\' || fullPath[i] == '/' {
			return fullPath[i+1:]
		}
	}
	return fullPath
}

// intToIP 将小端 uint32 转换成 IPv4 字符串
func intToIP(n uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip.String()
}

// portFromNetwork 将网络字节序端口转换为主机字节序
func portFromNetwork(port uint32) uint16 {
	b := [4]byte{}
	binary.LittleEndian.PutUint32(b[:], port)
	return uint16(b[1]) | uint16(b[0])<<8
}
