package tg

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"

	"vpshelper-go/internal/store"
)

func RefreshDialogs(ctx context.Context, dbConn *sql.DB, owner string, accountID int64, apiID int, apiHash, allProxy string) (int, string) {
	storage := NewAccountSessionStorage(dbConn, owner, accountID)
	opts, err := newTelegramOptions(storage, true, allProxy)
	if err != nil {
		return 0, "初始化 Telegram 客户端失败：" + err.Error()
	}
	client := telegram.NewClient(apiID, apiHash, opts)

	dialogs := make([]store.TGDialog, 0)
	err = client.Run(ctx, func(ctx context.Context) error {
		api := client.API()

		var offsetPeer tg.InputPeerClass = &tg.InputPeerEmpty{}
		offsetID := 0
		offsetDate := 0
		seen := map[string]bool{}

		for {
			res, err := api.MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{
				OffsetPeer: offsetPeer,
				OffsetID:   offsetID,
				OffsetDate: offsetDate,
				Limit:      100,
				Hash:       0,
			})
			if err != nil {
				return fmt.Errorf("get dialogs: %w", err)
			}

			batch, nextPeer, nextID, nextDate, err := extractDialogs(res)
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				break
			}

			for _, d := range batch {
				// Only keep items we can address by username.
				if d.DialogID == "" {
					continue
				}
				key := strings.ToLower(d.DialogID)
				if seen[key] {
					continue
				}
				seen[key] = true
				d.UpdatedAt = time.Now().Format(time.RFC3339)
				d.AccountID = accountID
				dialogs = append(dialogs, d)
			}

			offsetPeer = nextPeer
			offsetID = nextID
			offsetDate = nextDate
			if offsetID == 0 && offsetDate == 0 {
				break
			}
			if len(batch) < 100 {
				break
			}
		}

		return nil
	})
	if err != nil {
		return 0, err.Error()
	}

	// Sort for stable view.
	sort.Slice(dialogs, func(i, j int) bool {
		return strings.ToLower(dialogs[i].Title) < strings.ToLower(dialogs[j].Title)
	})

	if err := store.ReplaceTGDialogs(dbConn, accountID, dialogs); err != nil {
		return 0, "保存 dialogs 失败：" + err.Error()
	}

	return len(dialogs), "ok"
}

type extracted struct {
	dialogs  []store.TGDialog
	nextPeer tg.InputPeerClass
	nextID   int
	nextDate int
}

func extractDialogs(res tg.MessagesDialogsClass) ([]store.TGDialog, tg.InputPeerClass, int, int, error) {
	switch v := res.(type) {
	case *tg.MessagesDialogs:
		return convertDialogs(v.Dialogs, v.Users, v.Chats)
	case *tg.MessagesDialogsSlice:
		return convertDialogs(v.Dialogs, v.Users, v.Chats)
	case *tg.MessagesDialogsNotModified:
		return nil, &tg.InputPeerEmpty{}, 0, 0, nil
	default:
		return nil, &tg.InputPeerEmpty{}, 0, 0, fmt.Errorf("unsupported dialogs type: %T", res)
	}
}

func convertDialogs(dialogs []tg.DialogClass, users []tg.UserClass, chats []tg.ChatClass) ([]store.TGDialog, tg.InputPeerClass, int, int, error) {
	userByID := map[int64]*tg.User{}
	for _, u := range users {
		if uu, ok := u.(*tg.User); ok {
			userByID[uu.ID] = uu
		}
	}

	channelByID := map[int64]*tg.Channel{}
	chatByID := map[int64]*tg.Chat{}
	for _, c := range chats {
		switch cc := c.(type) {
		case *tg.Channel:
			channelByID[cc.ID] = cc
		case *tg.Chat:
			chatByID[cc.ID] = cc
		}
	}

	out := make([]store.TGDialog, 0, len(dialogs))
	var lastPeer tg.InputPeerClass = &tg.InputPeerEmpty{}
	lastID := 0
	lastDate := 0

	for _, dc := range dialogs {
		d, ok := dc.(*tg.Dialog)
		if !ok {
			continue
		}

		username, title, peer := resolvePeer(d.Peer, userByID, chatByID, channelByID)
		if username == "" {
			continue
		}
		if title == "" {
			title = "@" + username
		}

		out = append(out, store.TGDialog{DialogID: "@" + username, Title: title, Username: username})

		// Update offsets best-effort.
		lastPeer = peer
		lastID = d.TopMessage
		lastDate = d.ReadInboxMaxID
		_ = lastDate
	}

	return out, lastPeer, lastID, 0, nil
}

func resolvePeer(peer tg.PeerClass, users map[int64]*tg.User, chats map[int64]*tg.Chat, channels map[int64]*tg.Channel) (username, title string, outPeer tg.InputPeerClass) {
	switch p := peer.(type) {
	case *tg.PeerUser:
		u := users[p.UserID]
		if u == nil {
			return "", "", &tg.InputPeerEmpty{}
		}
		username = strings.TrimSpace(u.Username)
		if username == "" {
			return "", "", &tg.InputPeerEmpty{}
		}
		name := strings.TrimSpace(strings.TrimSpace(u.FirstName + " " + u.LastName))
		if name == "" {
			name = "@" + username
		}
		return username, name, &tg.InputPeerUser{UserID: u.ID, AccessHash: u.AccessHash}
	case *tg.PeerChat:
		c := chats[p.ChatID]
		if c == nil {
			return "", "", &tg.InputPeerEmpty{}
		}
		// Basic groups often have no username.
		return "", c.Title, &tg.InputPeerChat{ChatID: c.ID}
	case *tg.PeerChannel:
		ch := channels[p.ChannelID]
		if ch == nil {
			return "", "", &tg.InputPeerEmpty{}
		}
		username = strings.TrimSpace(ch.Username)
		if username == "" {
			return "", ch.Title, &tg.InputPeerEmpty{}
		}
		title = strings.TrimSpace(ch.Title)
		if title == "" {
			title = "@" + username
		}
		return username, title, &tg.InputPeerChannel{ChannelID: ch.ID, AccessHash: ch.AccessHash}
	default:
		return "", "", &tg.InputPeerEmpty{}
	}
}
