package tg

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

func NormalizeUsername(input string) string {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "https://t.me/")
	s = strings.TrimPrefix(s, "http://t.me/")
	s = strings.TrimPrefix(s, "t.me/")
	s = strings.TrimPrefix(s, "@")
	s = strings.TrimSpace(s)
	return s
}

func NormalizeDialogID(input string) (string, bool) {
	n, ok := parseNumericTarget(input)
	if !ok || n == 0 {
		return "", false
	}
	return strconv.FormatInt(n, 10), true
}

func IsDialogID(input string) bool {
	_, ok := NormalizeDialogID(input)
	return ok
}

func SendMessageToUsername(ctx context.Context, client *telegram.Client, target, message string) error {
	_, err := SendMessageToTarget(ctx, client, target, message)
	return err
}

func SendMessageToTarget(ctx context.Context, client *telegram.Client, target, message string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", errors.New("empty target")
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return "", errors.New("empty message")
	}

	resolved, err := resolveTarget(ctx, client.API(), target)
	if err != nil {
		return "", err
	}

	if err := sendMessageToPeer(ctx, client.API(), resolved.peer, message); err != nil {
		return "", err
	}
	return resolved.dialogID, nil
}

func ResolveDialogID(ctx context.Context, client *telegram.Client, target string) (string, error) {
	resolved, err := resolveTarget(ctx, client.API(), target)
	if err != nil {
		return "", err
	}
	return resolved.dialogID, nil
}

func sendMessageToPeer(ctx context.Context, api *tg.Client, peer tg.InputPeerClass, message string) error {
	_, err := api.MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
		Peer:     peer,
		Message:  message,
		RandomID: rand.Int63(),
	})
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	return nil
}

type resolvedTarget struct {
	peer     tg.InputPeerClass
	dialogID string
}

func resolveTarget(ctx context.Context, api *tg.Client, target string) (resolvedTarget, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return resolvedTarget{}, errors.New("empty target")
	}

	if _, ok := NormalizeDialogID(target); ok {
		peer, dialogID, err := findInputPeerByTarget(ctx, api, target)
		if err != nil {
			return resolvedTarget{}, err
		}
		return resolvedTarget{peer: peer, dialogID: dialogID}, nil
	}

	username := NormalizeUsername(target)
	if isProbableUsername(username) {
		resolved, err := api.ContactsResolveUsername(ctx, &tg.ContactsResolveUsernameRequest{Username: username})
		if err == nil {
			peer, err := inputPeerFromResolved(resolved)
			if err != nil {
				return resolvedTarget{}, err
			}
			dialogID, err := dialogIDFromPeer(resolved.Peer)
			if err != nil {
				return resolvedTarget{}, err
			}
			return resolvedTarget{peer: peer, dialogID: dialogID}, nil
		}

		peer, dialogID, fallbackErr := findInputPeerByTarget(ctx, api, target)
		if fallbackErr == nil {
			return resolvedTarget{peer: peer, dialogID: dialogID}, nil
		}
		return resolvedTarget{}, fmt.Errorf("resolve username: %w", err)
	}

	peer, dialogID, err := findInputPeerByTarget(ctx, api, target)
	if err != nil {
		return resolvedTarget{}, err
	}
	return resolvedTarget{peer: peer, dialogID: dialogID}, nil
}

func findInputPeerByTarget(ctx context.Context, api *tg.Client, target string) (tg.InputPeerClass, string, error) {
	target = strings.TrimSpace(target)
	num, hasNum := parseNumericTarget(target)
	username := strings.ToLower(NormalizeUsername(target))
	if !hasNum && !isProbableUsername(username) {
		return nil, "", fmt.Errorf("unsupported target: %q", target)
	}

	var offsetPeer tg.InputPeerClass = &tg.InputPeerEmpty{}
	offsetID := 0
	offsetDate := 0

	for page := 0; page < 30; page++ {
		res, err := messagesGetDialogsWithRetry(ctx, api, &tg.MessagesGetDialogsRequest{
			OffsetPeer: offsetPeer,
			OffsetID:   offsetID,
			OffsetDate: offsetDate,
			Limit:      100,
			Hash:       0,
		})
		if err != nil {
			return nil, "", fmt.Errorf("get dialogs: %w", err)
		}

		dialogs, users, chats, err := dialogsFromResponse(res)
		if err != nil {
			return nil, "", err
		}
		if len(dialogs) == 0 {
			break
		}

		userByID, chatByID, channelByID := buildDialogMaps(users, chats)
		for _, dc := range dialogs {
			d, ok := dc.(*tg.Dialog)
			if !ok {
				continue
			}
			peer, dialogID, ok := matchDialogPeerTarget(d.Peer, userByID, chatByID, channelByID, username, hasNum, num)
			if ok {
				return peer, dialogID, nil
			}
		}

		nextPeer, nextID := nextDialogOffset(dialogs, userByID, chatByID, channelByID)
		if nextPeer == nil || nextID == 0 || len(dialogs) < 100 {
			break
		}
		offsetPeer = nextPeer
		offsetID = nextID
		offsetDate = 0
	}

	return nil, "", fmt.Errorf("target not found in dialogs: %q", target)
}

func dialogsFromResponse(res tg.MessagesDialogsClass) ([]tg.DialogClass, []tg.UserClass, []tg.ChatClass, error) {
	switch v := res.(type) {
	case *tg.MessagesDialogs:
		return v.Dialogs, v.Users, v.Chats, nil
	case *tg.MessagesDialogsSlice:
		return v.Dialogs, v.Users, v.Chats, nil
	case *tg.MessagesDialogsNotModified:
		return nil, nil, nil, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported dialogs type: %T", res)
	}
}

func buildDialogMaps(users []tg.UserClass, chats []tg.ChatClass) (map[int64]*tg.User, map[int64]*tg.Chat, map[int64]*tg.Channel) {
	userByID := map[int64]*tg.User{}
	for _, u := range users {
		if uu, ok := u.(*tg.User); ok {
			userByID[uu.ID] = uu
		}
	}

	chatByID := map[int64]*tg.Chat{}
	channelByID := map[int64]*tg.Channel{}
	for _, c := range chats {
		switch cc := c.(type) {
		case *tg.Chat:
			chatByID[cc.ID] = cc
		case *tg.Channel:
			channelByID[cc.ID] = cc
		}
	}
	return userByID, chatByID, channelByID
}

func matchDialogPeerTarget(
	peer tg.PeerClass,
	users map[int64]*tg.User,
	chats map[int64]*tg.Chat,
	channels map[int64]*tg.Channel,
	username string,
	hasNum bool,
	num int64,
) (tg.InputPeerClass, string, bool) {
	switch p := peer.(type) {
	case *tg.PeerUser:
		u := users[p.UserID]
		if u == nil {
			return nil, "", false
		}
		input := &tg.InputPeerUser{UserID: u.ID, AccessHash: u.AccessHash}
		dialogID := dialogIDForUser(u.ID)
		if username != "" && strings.EqualFold(strings.TrimSpace(u.Username), username) {
			return input, dialogID, true
		}
		if hasNum && num == u.ID {
			return input, dialogID, true
		}
		return nil, "", false
	case *tg.PeerChat:
		ch := chats[p.ChatID]
		if ch == nil {
			return nil, "", false
		}
		input := &tg.InputPeerChat{ChatID: ch.ID}
		dialogID := dialogIDForChat(int64(ch.ID))
		if hasNum && (num == int64(ch.ID) || num == -int64(ch.ID)) {
			return input, dialogID, true
		}
		return nil, "", false
	case *tg.PeerChannel:
		ch := channels[p.ChannelID]
		if ch == nil {
			return nil, "", false
		}
		input := &tg.InputPeerChannel{ChannelID: ch.ID, AccessHash: ch.AccessHash}
		dialogID := dialogIDForChannel(ch.ID)
		if username != "" && strings.EqualFold(strings.TrimSpace(ch.Username), username) {
			return input, dialogID, true
		}
		if hasNum {
			channelID := int64(ch.ID)
			if num == channelID || num == -channelID || num == channelDialogID(channelID) {
				return input, dialogID, true
			}
		}
		return nil, "", false
	default:
		return nil, "", false
	}
}

func nextDialogOffset(
	dialogs []tg.DialogClass,
	users map[int64]*tg.User,
	chats map[int64]*tg.Chat,
	channels map[int64]*tg.Channel,
) (tg.InputPeerClass, int) {
	for i := len(dialogs) - 1; i >= 0; i-- {
		d, ok := dialogs[i].(*tg.Dialog)
		if !ok {
			continue
		}
		peer := inputPeerFromDialogPeer(d.Peer, users, chats, channels)
		if peer != nil {
			return peer, d.TopMessage
		}
	}
	return nil, 0
}

func inputPeerFromDialogPeer(
	peer tg.PeerClass,
	users map[int64]*tg.User,
	chats map[int64]*tg.Chat,
	channels map[int64]*tg.Channel,
) tg.InputPeerClass {
	switch p := peer.(type) {
	case *tg.PeerUser:
		u := users[p.UserID]
		if u == nil {
			return nil
		}
		return &tg.InputPeerUser{UserID: u.ID, AccessHash: u.AccessHash}
	case *tg.PeerChat:
		ch := chats[p.ChatID]
		if ch == nil {
			return nil
		}
		return &tg.InputPeerChat{ChatID: ch.ID}
	case *tg.PeerChannel:
		ch := channels[p.ChannelID]
		if ch == nil {
			return nil
		}
		return &tg.InputPeerChannel{ChannelID: ch.ID, AccessHash: ch.AccessHash}
	default:
		return nil
	}
}

func parseNumericTarget(target string) (int64, bool) {
	target = strings.TrimSpace(target)
	if target == "" || strings.HasPrefix(target, "@") {
		return 0, false
	}
	n, err := strconv.ParseInt(target, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func isProbableUsername(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isLetter {
			return false
		}
		if !isLetter && !isDigit && c != '_' {
			return false
		}
	}
	return true
}

func dialogIDFromPeer(peer tg.PeerClass) (string, error) {
	switch p := peer.(type) {
	case *tg.PeerUser:
		return dialogIDForUser(p.UserID), nil
	case *tg.PeerChat:
		return dialogIDForChat(int64(p.ChatID)), nil
	case *tg.PeerChannel:
		return dialogIDForChannel(p.ChannelID), nil
	default:
		return "", fmt.Errorf("unsupported peer type: %T", peer)
	}
}

func dialogIDForUser(id int64) string {
	return strconv.FormatInt(id, 10)
}

func dialogIDForChat(id int64) string {
	return strconv.FormatInt(-id, 10)
}

func dialogIDForChannel(id int64) string {
	return strconv.FormatInt(channelDialogID(id), 10)
}

func channelDialogID(id int64) int64 {
	return -(1000000000000 + id)
}

func inputPeerFromResolved(resolved *tg.ContactsResolvedPeer) (tg.InputPeerClass, error) {
	if resolved == nil || resolved.Peer == nil {
		return nil, errors.New("resolve result empty")
	}

	switch p := resolved.Peer.(type) {
	case *tg.PeerUser:
		for _, u := range resolved.Users {
			user, ok := u.(*tg.User)
			if ok && user.ID == p.UserID {
				return &tg.InputPeerUser{UserID: user.ID, AccessHash: user.AccessHash}, nil
			}
		}
		return nil, errors.New("user not found in resolve response")
	case *tg.PeerChat:
		return &tg.InputPeerChat{ChatID: p.ChatID}, nil
	case *tg.PeerChannel:
		for _, c := range resolved.Chats {
			ch, ok := c.(*tg.Channel)
			if ok && ch.ID == p.ChannelID {
				return &tg.InputPeerChannel{ChannelID: ch.ID, AccessHash: ch.AccessHash}, nil
			}
		}
		return nil, errors.New("channel not found in resolve response")
	default:
		return nil, fmt.Errorf("unsupported peer type: %T", resolved.Peer)
	}
}

// peerKeyToTarget converts a peerKey string (as stored in dialog files) back to
// a numeric target string understood by resolveTarget / findInputPeerByTarget.
//
//	"user:123"    → "123"
//	"chat:123"    → "-123"
//	"channel:123" → channelDialogID(123) as string
func peerKeyToTarget(key string) string {
	if after, ok := strings.CutPrefix(key, "user:"); ok {
		return after
	}
	if after, ok := strings.CutPrefix(key, "chat:"); ok {
		if n, err := strconv.ParseInt(after, 10, 64); err == nil {
			return strconv.FormatInt(-n, 10)
		}
	}
	if after, ok := strings.CutPrefix(key, "channel:"); ok {
		if n, err := strconv.ParseInt(after, 10, 64); err == nil {
			return strconv.FormatInt(channelDialogID(n), 10)
		}
	}
	return key // fallback: pass through unchanged
}
