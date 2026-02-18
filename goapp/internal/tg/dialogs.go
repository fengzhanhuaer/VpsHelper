package tg

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
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
			res, err := messagesGetDialogsWithRetry(ctx, api, &tg.MessagesGetDialogsRequest{
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
		if waitSeconds, ok := parseFloodWaitSeconds(err); ok {
			return 0, fmt.Sprintf("Telegram 限流，请 %d 秒后重试", waitSeconds)
		}
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

		dialogID, username, title, peer := resolveDialogPeer(d.Peer, userByID, chatByID, channelByID)
		if dialogID == "" {
			continue
		}
		if title == "" {
			title = dialogID
		}

		out = append(out, store.TGDialog{DialogID: dialogID, Title: title, Username: username})

		// Update offsets best-effort.
		lastPeer = peer
		lastID = d.TopMessage
		lastDate = d.ReadInboxMaxID
		_ = lastDate
	}

	return out, lastPeer, lastID, 0, nil
}

func resolveDialogPeer(peer tg.PeerClass, users map[int64]*tg.User, chats map[int64]*tg.Chat, channels map[int64]*tg.Channel) (dialogID, username, title string, outPeer tg.InputPeerClass) {
	switch p := peer.(type) {
	case *tg.PeerUser:
		u := users[p.UserID]
		if u == nil {
			return "", "", "", &tg.InputPeerEmpty{}
		}
		dialogID = dialogIDForUser(u.ID)
		username = strings.TrimSpace(u.Username)
		name := strings.TrimSpace(strings.TrimSpace(u.FirstName + " " + u.LastName))
		switch {
		case name != "":
			title = name
		case username != "":
			title = "@" + username
		default:
			title = "user-" + strconv.FormatInt(u.ID, 10)
		}
		return dialogID, username, title, &tg.InputPeerUser{UserID: u.ID, AccessHash: u.AccessHash}
	case *tg.PeerChat:
		c := chats[p.ChatID]
		if c == nil {
			return "", "", "", &tg.InputPeerEmpty{}
		}
		dialogID = dialogIDForChat(int64(c.ID))
		title = strings.TrimSpace(c.Title)
		if title == "" {
			title = "group-" + strconv.FormatInt(int64(c.ID), 10)
		}
		return dialogID, "", title, &tg.InputPeerChat{ChatID: c.ID}
	case *tg.PeerChannel:
		ch := channels[p.ChannelID]
		if ch == nil {
			return "", "", "", &tg.InputPeerEmpty{}
		}
		dialogID = dialogIDForChannel(ch.ID)
		username = strings.TrimSpace(ch.Username)
		title = strings.TrimSpace(ch.Title)
		if title == "" {
			if username != "" {
				title = "@" + username
			} else {
				title = "channel-" + strconv.FormatInt(ch.ID, 10)
			}
		}
		return dialogID, username, title, &tg.InputPeerChannel{ChannelID: ch.ID, AccessHash: ch.AccessHash}
	default:
		return "", "", "", &tg.InputPeerEmpty{}
	}
}
