package tg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/peers"
	"github.com/gotd/td/tg"

	"vpshelper-go/internal/store"
)

type autoReplyKey struct {
	owner     string
	accountID int64
}

type autoReplyRunner struct {
	id     int64
	cancel context.CancelFunc
	done   chan struct{}
}

func StartAutoReply(ctx context.Context, dbConn *sql.DB) {
	ticker := time.NewTicker(15 * time.Second)

	var mu sync.Mutex
	var nextRunnerID int64
	runners := map[autoReplyKey]autoReplyRunner{}

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				mu.Lock()
				for _, r := range runners {
					r.cancel()
				}
				runners = map[autoReplyKey]autoReplyRunner{}
				mu.Unlock()
				return
			case <-ticker.C:
				// Clean up exited runners so they can be restarted.
				mu.Lock()
				for k, r := range runners {
					select {
					case <-r.done:
						delete(runners, k)
					default:
					}
				}
				mu.Unlock()

				// Global TG kill-switch: stop all runners when disabled.
				if !isTGEnabled(dbConn) {
					mu.Lock()
					for k, r := range runners {
						r.cancel()
						delete(runners, k)
					}
					mu.Unlock()
					continue
				}

				// All TG accounts: always use tg_accounts as the unified source of truth.
				accounts, _ := store.ListAllTGAccountsAsOwnerAccounts(dbConn)


				want := map[autoReplyKey]bool{}
				for _, a := range accounts {
					want[autoReplyKey{owner: a.Owner, accountID: a.AccountID}] = true
				}

				mu.Lock()
				// Stop removed.
				for k, r := range runners {
					if !want[k] {
						r.cancel()
						delete(runners, k)
					}
				}
				// Start new.
				for _, a := range accounts {
					k := autoReplyKey{owner: a.Owner, accountID: a.AccountID}
					if _, ok := runners[k]; ok {
						continue
					}
					nextRunnerID++
					cctx, cancel := context.WithCancel(ctx)
					runner := autoReplyRunner{id: nextRunnerID, cancel: cancel, done: make(chan struct{})}
					runners[k] = runner
					go func(acct store.OwnerAccount, r autoReplyRunner) {
						defer close(r.done)
						runAutoReplyListener(cctx, dbConn, acct)
					}(a, runner)
				}
				mu.Unlock()
			}
		}
	}()
}

func runAutoReplyListener(ctx context.Context, dbConn *sql.DB, acct store.OwnerAccount) {
	// Always load API credentials from global app_settings (unified source of truth).
	settings, err := store.GetSettings(dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	if err != nil {
		return
	}
	apiIDText := strings.TrimSpace(settings["telegram_api_id"])
	apiHash := strings.TrimSpace(settings["telegram_api_hash"])
	allProxy := strings.TrimSpace(settings["tg_all_proxy"])
	if apiIDText == "" || apiHash == "" {
		return
	}
	apiID, err := parseInt(apiIDText)
	if err != nil {
		return
	}

	// Always load session from tg_accounts table (unified source of truth).
	storage := NewAccountSessionStorage(dbConn, acct.Owner, acct.AccountID)

	h := newAutoReplyHandler(dbConn, acct.Owner, acct.AccountID)
	late := &lateUpdateHandler{}
	opts, err := newTelegramOptions(storage, false, allProxy)
	if err != nil {
		return
	}
	opts.UpdateHandler = late

	client := telegram.NewClient(apiID, apiHash, opts)
	h.setAPI(client.API())

	_ = client.Run(ctx, func(ctx context.Context) error {
		pm := peers.Options{
			Storage: new(peers.InmemoryStorage),
			Cache:   new(peers.InmemoryCache),
		}.Build(client.API())
		if err := pm.Init(ctx); err == nil {
			h.setPeers(pm)
			late.Set(pm.UpdateHook(h))
		} else {
			late.Set(h)
		}

		if res, err := client.API().ContactsGetContacts(ctx, 0); err == nil {
			h.applyContacts(res)
		}

		// On first connect, catch up messages missed while offline (best-effort).
		go catchUpAccountDialogs(ctx, client.API(), acct.AccountID)

		<-ctx.Done()
		return nil
	})
}

// catchUpAccountDialogs fetches messages newer than the last stored msg_id
// for every dialog that already has a local history file for accountID.
func catchUpAccountDialogs(ctx context.Context, api *tg.Client, accountID int64) {
	dialogs := store.ListDialogsWithHistory(accountID)
	for _, dialogID := range dialogs {
		minID := store.GetLastStoredMsgID(accountID, dialogID)
		if minID <= 0 {
			continue
		}
		resolved, err := resolveTarget(ctx, api, dialogID)
		if err != nil {
			continue
		}
		res, err := messagesGetHistoryWithRetry(ctx, api, &tg.MessagesGetHistoryRequest{
			Peer:  resolved.peer,
			MinID: minID,
			Limit: 100,
		})
		if err != nil {
			continue
		}
		nameMap := buildSenderNameMap(historyUsersFromResponse(res))

		// Determine a dialog title from the name map (only for user: dialogs).
		dialogTitle := ""
		if strings.HasPrefix(dialogID, "user:") {
			idStr := strings.TrimPrefix(dialogID, "user:")
			if uid, err2 := strconv.ParseInt(idStr, 10, 64); err2 == nil {
				dialogTitle = nameMap[uid]
			}
		}

		raw := historyMessagesFromResponse(res)
		var latestMsgAt int64
		// Telegram returns newest-first; store oldest-first.
		for i := len(raw) - 1; i >= 0; i-- {
			m, ok := raw[i].(*tg.Message)
			if !ok || strings.TrimSpace(m.Message) == "" {
				continue
			}
			from := "me"
			if !m.Out {
				if fid, ok := m.FromID.(*tg.PeerUser); ok {
					if n := nameMap[fid.UserID]; n != "" {
						from = n
					} else {
						from = strconv.FormatInt(fid.UserID, 10)
					}
				}
			}
			_ = store.AppendChatMessage(accountID, dialogID, store.ChatMessage{
				MsgID: m.ID,
				From:  from,
				Text:  m.Message,
				Date:  int64(m.Date),
				Out:   m.Out,
			})
			if int64(m.Date) > latestMsgAt {
				latestMsgAt = int64(m.Date)
			}
		}
		if latestMsgAt > 0 {
			_ = store.UpdateDialogLastMsgAt(accountID, dialogID, dialogTitle, latestMsgAt)
		}
	}
}

// lateUpdateHandler allows setting the real handler after telegram.Client is constructed.
// It avoids needing UpdateHandler ready before we can build peers.Manager.
type lateUpdateHandler struct {
	mu sync.RWMutex
	h  telegram.UpdateHandler
}

func (l *lateUpdateHandler) Handle(ctx context.Context, u tg.UpdatesClass) error {
	l.mu.RLock()
	h := l.h
	l.mu.RUnlock()
	if h == nil {
		return nil
	}
	return h.Handle(ctx, u)
}

func (l *lateUpdateHandler) Set(h telegram.UpdateHandler) {
	l.mu.Lock()
	l.h = h
	l.mu.Unlock()
}

type incomingMessage struct {
	MsgID      int
	Peer       tg.PeerClass
	SenderID   int64  // 0 = self / outgoing
	SenderName string // display name if resolved, else empty
	Text       string
	Date       int64 // unix timestamp
	Out        bool
}

func extractIncomingMessages(u tg.UpdatesClass) []incomingMessage {
	switch v := u.(type) {
	case *tg.UpdateShortMessage:
		sid := v.UserID
		if v.Out {
			sid = 0
		}
		return []incomingMessage{{MsgID: v.ID, Peer: &tg.PeerUser{UserID: v.UserID}, SenderID: sid, Text: v.Message, Date: int64(v.Date), Out: v.Out}}
	case *tg.UpdateShortChatMessage:
		sid := v.FromID
		if v.Out {
			sid = 0
		}
		return []incomingMessage{{MsgID: v.ID, Peer: &tg.PeerChat{ChatID: v.ChatID}, SenderID: sid, Text: v.Message, Date: int64(v.Date), Out: v.Out}}
	case *tg.UpdateShort:
		return extractFromUpdate(v.Update, nil)
	case *tg.Updates:
		nameMap := buildSenderNameMap(v.Users)
		return extractFromUpdates(v.Updates, nameMap)
	case *tg.UpdatesCombined:
		nameMap := buildSenderNameMap(v.Users)
		return extractFromUpdates(v.Updates, nameMap)
	default:
		return nil
	}
}

func extractFromUpdates(updates []tg.UpdateClass, nameMap map[int64]string) []incomingMessage {
	var out []incomingMessage
	for _, u := range updates {
		out = append(out, extractFromUpdate(u, nameMap)...)
	}
	return out
}

func extractFromUpdate(u tg.UpdateClass, nameMap map[int64]string) []incomingMessage {
	switch v := u.(type) {
	case *tg.UpdateNewMessage:
		return extractFromMessage(v.Message, nameMap)
	case *tg.UpdateNewChannelMessage:
		return extractFromMessage(v.Message, nameMap)
	default:
		return nil
	}
}

func extractFromMessage(m tg.MessageClass, nameMap map[int64]string) []incomingMessage {
	msg, ok := m.(*tg.Message)
	if !ok {
		return nil
	}
	var senderID int64
	var senderName string
	if !msg.Out {
		if fid, ok := msg.FromID.(*tg.PeerUser); ok {
			senderID = fid.UserID
			if nameMap != nil {
				senderName = nameMap[senderID]
			}
		}
	}
	return []incomingMessage{{MsgID: msg.ID, Peer: msg.PeerID, SenderID: senderID, SenderName: senderName, Text: msg.Message, Date: int64(msg.Date), Out: msg.Out}}
}

func randomID() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UnixNano()
	}
	return int64(binary.LittleEndian.Uint64(b[:]) & ^uint64(1<<63))
}

type autoReplyHandler struct {
	dbConn    *sql.DB
	owner     string
	accountID int64

	mu          sync.RWMutex
	api         *tg.Client
	userHash    map[int64]int64
	channelHash map[int64]int64
	peers       *peers.Manager

	rulesMu      sync.Mutex
	rulesCacheAt time.Time
	rulesCache   []compiledRule

	cfgMu          sync.Mutex
	cfgCacheAt     time.Time
	cfgCooldownSec int

	coolMu         sync.Mutex
	lastReplyByKey map[string]time.Time

	resolveMu   sync.Mutex
	resolveFail map[string]resolveBackoff

	statsMu    sync.Mutex
	stats      autoReplyStats
	statsDirty bool
}

type resolveBackoff struct {
	failCount int
	nextTryAt time.Time
}

type autoReplyStats struct {
	windowStart time.Time
	lastUpdate  time.Time
	lastPersist time.Time

	updatesSeen  int
	messagesSeen int
	matches      int
	repliesSent  int
	sendFailures int

	resolveAttempt int
	resolveOK      int
	resolveFail    int
}

type compiledRule struct {
	ID          int64
	NeedleLower string
	Reply       string
}

func newAutoReplyHandler(dbConn *sql.DB, owner string, accountID int64) *autoReplyHandler {
	return &autoReplyHandler{
		dbConn:         dbConn,
		owner:          owner,
		accountID:      accountID,
		userHash:       map[int64]int64{},
		channelHash:    map[int64]int64{},
		lastReplyByKey: map[string]time.Time{},
		cfgCooldownSec: 15,
		resolveFail:    map[string]resolveBackoff{},
		stats:          autoReplyStats{windowStart: time.Now()},
	}
}

func (h *autoReplyHandler) setAPI(api *tg.Client) {
	h.mu.Lock()
	h.api = api
	h.mu.Unlock()
}

func (h *autoReplyHandler) setPeers(pm *peers.Manager) {
	h.mu.Lock()
	h.peers = pm
	h.mu.Unlock()
}

func (h *autoReplyHandler) Handle(ctx context.Context, u tg.UpdatesClass) error {
	h.markUpdate()
	h.applyEntities(u)

	msgs := extractIncomingMessages(u)
	if len(msgs) == 0 {
		return nil
	}
	h.markMessages(len(msgs))

	// ── Persist every message (in + out) to local chat history ──
	_ = h.storeMsgsToHistory(ctx, msgs)

	rules := h.getEnabledRulesCached()
	api := h.getAPI()

	if len(rules) > 0 && api != nil {
		for _, m := range msgs {
			if m.Out {
				continue
			}
			text := strings.TrimSpace(m.Text)
			if text == "" {
				continue
			}
			lowerText := strings.ToLower(text)

			toKey := peerKey(m.Peer)
			if toKey == "" {
				continue
			}

			peer := h.resolveInputPeer(ctx, toKey, m.Peer)
			if peer == nil {
				continue
			}

			for _, r := range rules {
				if r.NeedleLower == "" {
					continue
				}
				if !strings.Contains(lowerText, r.NeedleLower) {
					continue
				}
				if r.Reply == "" {
					continue
				}

				cooldown := h.getCooldownDuration()
				if cooldown > 0 {
					key := toKey + "|rule:" + strconv.FormatInt(r.ID, 10)
					if !h.allowReplyNow(key, cooldown) {
						continue
					}
					h.markReplied(key)
				}
				h.markMatch()

				_, err := api.MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
					Peer:     peer,
					Message:  r.Reply,
					RandomID: randomID(),
				})
				if err != nil {
					h.markSendFailure()
				} else {
					h.markReplySent()
				}
				break
			}
		}
	}

	h.maybePersistStats()
	return nil
}

// storeMsgsToHistory persists each message and updates the dialog's last-message timestamp.
func (h *autoReplyHandler) storeMsgsToHistory(_ context.Context, msgs []incomingMessage) error {
	for _, m := range msgs {
		if m.Peer == nil || m.Text == "" {
			continue
		}
		// Use the same numeric dialogID format as RefreshDialogs so that
		// real-time messages and the dialog list share a single key.
		dialogID, err := dialogIDFromPeer(m.Peer)
		if err != nil || dialogID == "" {
			continue
		}
		t := m.Date
		if t == 0 {
			t = time.Now().Unix()
		}
		// Use resolved name when available, else numeric ID, else "me" for outgoing.
		senderDisplay := "me"
		if !m.Out {
			if m.SenderName != "" {
				senderDisplay = m.SenderName
			} else if m.SenderID != 0 {
				senderDisplay = strconv.FormatInt(m.SenderID, 10)
			}
		}
		cm := store.ChatMessage{
			MsgID: m.MsgID,
			From:  senderDisplay,
			Text:  m.Text,
			Date:  t,
			Out:   m.Out,
		}
		_ = store.AppendChatMessage(h.accountID, dialogID, cm)

		// Determine dialog title:
		// - For user chats: use SenderName (the other party)
		// - For group/channel: no easy name here, pass "" to keep existing title
		dialogTitle := ""
		if _, ok := m.Peer.(*tg.PeerUser); ok && m.SenderName != "" {
			dialogTitle = m.SenderName
		}
		_ = store.UpdateDialogLastMsgAt(h.accountID, dialogID, dialogTitle, t)
	}
	return nil
}

func (h *autoReplyHandler) markUpdate() {
	h.statsMu.Lock()
	h.stats.updatesSeen++
	h.stats.lastUpdate = time.Now()
	h.statsDirty = true
	h.statsMu.Unlock()
}

func (h *autoReplyHandler) markMessages(n int) {
	if n <= 0 {
		return
	}
	h.statsMu.Lock()
	h.stats.messagesSeen += n
	h.stats.lastUpdate = time.Now()
	h.statsDirty = true
	h.statsMu.Unlock()
}

func (h *autoReplyHandler) markMatch() {
	h.statsMu.Lock()
	h.stats.matches++
	h.stats.lastUpdate = time.Now()
	h.statsDirty = true
	h.statsMu.Unlock()
}

func (h *autoReplyHandler) markReplySent() {
	h.statsMu.Lock()
	h.stats.repliesSent++
	h.stats.lastUpdate = time.Now()
	h.statsDirty = true
	h.statsMu.Unlock()
}

func (h *autoReplyHandler) markSendFailure() {
	h.statsMu.Lock()
	h.stats.sendFailures++
	h.stats.lastUpdate = time.Now()
	h.statsDirty = true
	h.statsMu.Unlock()
}

func (h *autoReplyHandler) markResolveAttempt() {
	h.statsMu.Lock()
	h.stats.resolveAttempt++
	h.stats.lastUpdate = time.Now()
	h.statsDirty = true
	h.statsMu.Unlock()
}

func (h *autoReplyHandler) markResolveOK() {
	h.statsMu.Lock()
	h.stats.resolveOK++
	h.stats.lastUpdate = time.Now()
	h.statsDirty = true
	h.statsMu.Unlock()
}

func (h *autoReplyHandler) markResolveFail() {
	h.statsMu.Lock()
	h.stats.resolveFail++
	h.stats.lastUpdate = time.Now()
	h.statsDirty = true
	h.statsMu.Unlock()
}

func (h *autoReplyHandler) maybePersistStats() {
	// Persist to app_settings at low frequency for troubleshooting.
	const persistEvery = 30 * time.Second
	const windowMax = 1 * time.Hour

	now := time.Now()
	h.statsMu.Lock()
	if !h.statsDirty {
		h.statsMu.Unlock()
		return
	}
	if !h.stats.lastPersist.IsZero() && now.Sub(h.stats.lastPersist) < persistEvery {
		h.statsMu.Unlock()
		return
	}
	// Rotate window to keep counters meaningful.
	if now.Sub(h.stats.windowStart) > windowMax {
		h.stats = autoReplyStats{windowStart: now}
	}
	st := h.stats
	h.stats.lastPersist = now
	h.statsDirty = false
	h.statsMu.Unlock()

	key := "tg_auto_reply_stats_" + sanitizeKeyPart(h.owner) + "_" + strconv.FormatInt(h.accountID, 10)
	value := strings.TrimSpace(
		"window_start=" + st.windowStart.Format(time.RFC3339) +
			" last_update=" + st.lastUpdate.Format(time.RFC3339) +
			" updates=" + strconv.Itoa(st.updatesSeen) +
			" msgs=" + strconv.Itoa(st.messagesSeen) +
			" matches=" + strconv.Itoa(st.matches) +
			" replies=" + strconv.Itoa(st.repliesSent) +
			" send_fail=" + strconv.Itoa(st.sendFailures) +
			" resolve_try=" + strconv.Itoa(st.resolveAttempt) +
			" resolve_ok=" + strconv.Itoa(st.resolveOK) +
			" resolve_fail=" + strconv.Itoa(st.resolveFail),
	)
	_ = store.SetSetting(h.dbConn, key, value)
}

func sanitizeKeyPart(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "_"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func (h *autoReplyHandler) getEnabledRulesCached() []compiledRule {
	// TTL cache to avoid querying DB on every update.
	// 3s is short enough for UI edits to take effect quickly.
	const ttl = 3 * time.Second

	now := time.Now()
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	if len(h.rulesCache) > 0 && now.Sub(h.rulesCacheAt) < ttl {
		return h.rulesCache
	}

	rules, err := store.ListEnabledAutoReplyRules(h.dbConn, h.owner, h.accountID)
	if err != nil {
		// Keep old cache (if any) for a short while.
		if len(h.rulesCache) > 0 && now.Sub(h.rulesCacheAt) < 30*time.Second {
			return h.rulesCache
		}
		h.rulesCache = nil
		h.rulesCacheAt = now
		return nil
	}

	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		needle := strings.ToLower(strings.TrimSpace(r.MatchText))
		reply := strings.TrimSpace(r.ReplyText)
		if needle == "" || reply == "" {
			continue
		}
		compiled = append(compiled, compiledRule{ID: r.ID, NeedleLower: needle, Reply: reply})
	}

	h.rulesCache = compiled
	h.rulesCacheAt = now
	return compiled
}

func (h *autoReplyHandler) getCooldownDuration() time.Duration {
	// Cache cooldown seconds from app_settings.
	// Default 15s. <=0 means disabled.
	const ttl = 30 * time.Second
	const maxSec = 24 * 60 * 60

	now := time.Now()
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	if !h.cfgCacheAt.IsZero() && now.Sub(h.cfgCacheAt) < ttl {
		if h.cfgCooldownSec <= 0 {
			return 0
		}
		return time.Duration(h.cfgCooldownSec) * time.Second
	}

	sec := 15
	if m, err := store.GetSettings(h.dbConn, []string{"tg_auto_reply_cooldown_seconds"}); err == nil {
		if v := strings.TrimSpace(m["tg_auto_reply_cooldown_seconds"]); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				sec = n
			}
		}
	}
	if sec > maxSec {
		sec = maxSec
	}
	h.cfgCooldownSec = sec
	h.cfgCacheAt = now
	if sec <= 0 {
		return 0
	}
	return time.Duration(sec) * time.Second
}

func peerKey(p tg.PeerClass) string {
	switch pp := p.(type) {
	case *tg.PeerUser:
		if pp.UserID <= 0 {
			return ""
		}
		return "user:" + strconv.FormatInt(pp.UserID, 10)
	case *tg.PeerChat:
		if pp.ChatID <= 0 {
			return ""
		}
		return "chat:" + strconv.FormatInt(pp.ChatID, 10)
	case *tg.PeerChannel:
		if pp.ChannelID <= 0 {
			return ""
		}
		return "channel:" + strconv.FormatInt(pp.ChannelID, 10)
	default:
		return ""
	}
}

func (h *autoReplyHandler) allowReplyNow(key string, cooldown time.Duration) bool {
	const sweepAfter = 10 * time.Minute
	const maxKeys = 2048

	now := time.Now()
	h.coolMu.Lock()
	defer h.coolMu.Unlock()

	if last, ok := h.lastReplyByKey[key]; ok {
		if now.Sub(last) < cooldown {
			return false
		}
	}

	// Best-effort sweep to avoid unbounded growth.
	if len(h.lastReplyByKey) > maxKeys {
		for k, t := range h.lastReplyByKey {
			if now.Sub(t) > sweepAfter {
				delete(h.lastReplyByKey, k)
			}
		}
	}

	return true
}

func (h *autoReplyHandler) markReplied(key string) {
	h.coolMu.Lock()
	h.lastReplyByKey[key] = time.Now()
	h.coolMu.Unlock()
}

func (h *autoReplyHandler) getAPI() *tg.Client {
	h.mu.RLock()
	api := h.api
	h.mu.RUnlock()
	return api
}

func (h *autoReplyHandler) applyContacts(res tg.ContactsContactsClass) {
	cc, ok := res.(*tg.ContactsContacts)
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, u := range cc.Users {
		uu, ok := u.(*tg.User)
		if !ok {
			continue
		}
		if uu.AccessHash != 0 {
			h.userHash[uu.ID] = uu.AccessHash
		}
	}
}

func (h *autoReplyHandler) applyEntities(u tg.UpdatesClass) {
	var users []tg.UserClass
	var chats []tg.ChatClass

	switch v := u.(type) {
	case *tg.Updates:
		users = v.Users
		chats = v.Chats
	case *tg.UpdatesCombined:
		users = v.Users
		chats = v.Chats
	default:
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, u := range users {
		uu, ok := u.(*tg.User)
		if !ok {
			continue
		}
		if uu.AccessHash != 0 {
			h.userHash[uu.ID] = uu.AccessHash
		}
	}
	for _, c := range chats {
		switch cc := c.(type) {
		case *tg.Channel:
			if cc.AccessHash != 0 {
				h.channelHash[cc.ID] = cc.AccessHash
			}
		}
	}
}

func (h *autoReplyHandler) resolveInputPeer(ctx context.Context, toKey string, p tg.PeerClass) tg.InputPeerClass {
	if p == nil {
		return nil
	}

	switch pp := p.(type) {
	case *tg.PeerChat:
		return &tg.InputPeerChat{ChatID: pp.ChatID}
	case *tg.PeerUser:
		h.mu.RLock()
		hash := h.userHash[pp.UserID]
		pm := h.peers
		h.mu.RUnlock()
		if hash == 0 {
			return h.resolveViaPeersWithBackoff(ctx, toKey, pm, p, pp.UserID, 0)
		}
		return &tg.InputPeerUser{UserID: pp.UserID, AccessHash: hash}
	case *tg.PeerChannel:
		h.mu.RLock()
		hash := h.channelHash[pp.ChannelID]
		pm := h.peers
		h.mu.RUnlock()
		if hash == 0 {
			return h.resolveViaPeersWithBackoff(ctx, toKey, pm, p, 0, pp.ChannelID)
		}
		return &tg.InputPeerChannel{ChannelID: pp.ChannelID, AccessHash: hash}
	default:
		return nil
	}
}

func (h *autoReplyHandler) resolveViaPeersWithBackoff(ctx context.Context, toKey string, pm *peers.Manager, p tg.PeerClass, userID int64, channelID int64) tg.InputPeerClass {
	if pm == nil {
		return nil
	}
	if toKey == "" {
		toKey = peerKey(p)
	}
	if toKey == "" {
		return nil
	}
	if !h.allowResolveNow(toKey) {
		return nil
	}

	h.markResolveAttempt()

	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Try generic resolve first.
	if rp, err := pm.ResolvePeer(rctx, p); err == nil && rp != nil {
		if in := rp.InputPeer(); in != nil {
			h.onResolveSuccess(toKey, in)
			h.markResolveOK()
			return in
		}
	}

	// Try ID-based resolve.
	if userID > 0 {
		if u, err := pm.ResolveUserID(rctx, userID); err == nil {
			if in := u.InputPeer(); in != nil {
				h.onResolveSuccess(toKey, in)
				h.markResolveOK()
				return in
			}
		}
	}
	if channelID > 0 {
		if ch, err := pm.ResolveChannelID(rctx, channelID); err == nil {
			if in := ch.InputPeer(); in != nil {
				h.onResolveSuccess(toKey, in)
				h.markResolveOK()
				return in
			}
		}
	}

	h.onResolveFail(toKey)
	h.markResolveFail()
	return nil
}

func (h *autoReplyHandler) allowResolveNow(toKey string) bool {
	h.resolveMu.Lock()
	defer h.resolveMu.Unlock()
	if b, ok := h.resolveFail[toKey]; ok {
		if !b.nextTryAt.IsZero() && time.Now().Before(b.nextTryAt) {
			return false
		}
	}
	return true
}

func (h *autoReplyHandler) onResolveSuccess(toKey string, in tg.InputPeerClass) {
	// Reset backoff.
	h.resolveMu.Lock()
	delete(h.resolveFail, toKey)
	h.resolveMu.Unlock()

	// Save access hash to local caches to reduce future resolves.
	switch v := in.(type) {
	case *tg.InputPeerUser:
		if v.UserID > 0 && v.AccessHash != 0 {
			h.mu.Lock()
			h.userHash[v.UserID] = v.AccessHash
			h.mu.Unlock()
		}
	case *tg.InputPeerChannel:
		if v.ChannelID > 0 && v.AccessHash != 0 {
			h.mu.Lock()
			h.channelHash[v.ChannelID] = v.AccessHash
			h.mu.Unlock()
		}
	}
}

func (h *autoReplyHandler) onResolveFail(toKey string) {
	// Exponential backoff to avoid hammering API on repeated failures.
	const base = 10 * time.Second
	const max = 5 * time.Minute

	now := time.Now()
	h.resolveMu.Lock()
	b := h.resolveFail[toKey]
	b.failCount++
	// delay = base * 2^(failCount-1)
	delay := base
	if b.failCount > 1 {
		shift := b.failCount - 1
		if shift > 10 {
			shift = 10
		}
		delay = base * time.Duration(1<<shift)
	}
	if delay > max {
		delay = max
	}
	b.nextTryAt = now.Add(delay)
	h.resolveFail[toKey] = b
	// Best-effort cleanup.
	if len(h.resolveFail) > 2048 {
		for k, v := range h.resolveFail {
			if !v.nextTryAt.IsZero() && now.Sub(v.nextTryAt) > 10*time.Minute {
				delete(h.resolveFail, k)
			}
		}
	}
	h.resolveMu.Unlock()
}
