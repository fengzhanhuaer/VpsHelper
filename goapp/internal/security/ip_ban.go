package security

import (
	"database/sql"
	"log"
	"strings"
	"sync"
	"time"
)

var (
	banMu         sync.Mutex
	failedIPs     = make(map[string]int)
	bannedIPs     = make(map[string]time.Time)
	lastCleanup   = time.Now()
	maxFailures   = 5
	banDuration   = 24 * time.Hour
	resetInterval = 1 * time.Hour
)

// IsBanned checks if an IP is currently banned in memory.
func IsBanned(ip string) bool {
	banMu.Lock()
	defer banMu.Unlock()

	// Periodic cleanup
	if time.Since(lastCleanup) > resetInterval {
		for k, t := range bannedIPs {
			if time.Since(t) > banDuration {
				delete(bannedIPs, k)
			}
		}
		// Reset failed counters
		failedIPs = make(map[string]int)
		lastCleanup = time.Now()
	}

	expireTime, exists := bannedIPs[ip]
	if exists {
		if time.Since(expireTime) > banDuration {
			delete(bannedIPs, ip)
			return false
		}
		return true
	}
	return false
}

// RecordFailure records a failure for an IP. If it exceeds threshold, it bans the IP
// in memory.
func RecordFailure(dbConn *sql.DB, ip string) {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
		// Ignore local or empty IPs
		return
	}

	banMu.Lock()
	failedIPs[ip]++
	count := failedIPs[ip]
	alreadyBanned := false
	if count >= maxFailures {
		if _, ok := bannedIPs[ip]; !ok {
			bannedIPs[ip] = time.Now()
		} else {
			alreadyBanned = true
		}
	}
	banMu.Unlock()

	if count >= maxFailures && !alreadyBanned {
		log.Printf("[Security] IP %s exceeded failure threshold (%d). Banned temporarily in memory.", ip, maxFailures)
	}
}
