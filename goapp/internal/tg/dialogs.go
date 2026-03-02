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
	"github.com/gotd/td/telegram/query"
	"github.com/gotd/td/tg"

	"vpshelper-go/internal/store"
)

func RefreshDialogs(ctx context.Context, dbConn *sql.DB, owner string, accountID int64, apiID int, apiHash, allProxy string, onProgress func(int, string)) (int, string) {
	var dialogs []store.TGDialog
	var err error

	if api := GetLiveAPI(owner, accountID); api != nil {
		dialogs, err = execRefreshDialogs(ctx, api, accountID, onProgress)
	} else {
		storage := NewAccountSessionStorage(dbConn, owner, accountID)
		opts, err2 := newTelegramOptions(storage, true, allProxy)
		if err2 != nil {
			return 0, "初始化 Telegram 客户端失败：" + err2.Error()
		}
		client := telegram.NewClient(apiID, apiHash, opts)
		
		err = client.Run(ctx, func(ctx context.Context) error {
			var err3 error
			dialogs, err3 = execRefreshDialogs(ctx, client.API(), accountID, onProgress)
			return err3
		})
	}

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

func execRefreshDialogs(ctx context.Context, api *tg.Client, accountID int64, onProgress func(int, string)) ([]store.TGDialog, error) {
	dialogs := make([]store.TGDialog, 0)
	seen := map[string]bool{}
	iter := query.NewQuery(api).GetDialogs().BatchSize(100).Iter()

	for iter.Next(ctx) {
		elem := iter.Value()
		d, ok := elem.Dialog.(*tg.Dialog)
		if !ok {
			continue
		}

		userByID := elem.Entities.Users()
		chatByID := elem.Entities.Chats()
		channelByID := elem.Entities.Channels()

		dialogID, username, title, _ := resolveDialogPeer(d.Peer, userByID, chatByID, channelByID)
		if dialogID == "" {
			continue
		}
		key := strings.ToLower(dialogID)
		if seen[key] {
			continue
		}
		seen[key] = true

		updatedAt := time.Now().Format(time.RFC3339)
		dialogs = append(dialogs, store.TGDialog{
			DialogID:  dialogID,
			Title:     title,
			Username:  username,
			UpdatedAt: updatedAt,
			AccountID: accountID,
		})

		// Avoid spamming progress, report every 100 dialogs
		if len(dialogs)%100 == 0 && onProgress != nil {
			onProgress(len(dialogs), "拉取中...")
		}
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	if onProgress != nil {
		onProgress(len(dialogs), "拉取中...")
	}

	return dialogs, nil
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
