package tg

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
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

func SendMessageToUsername(ctx context.Context, client *telegram.Client, username, message string) error {
	username = NormalizeUsername(username)
	if username == "" {
		return errors.New("empty username")
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return errors.New("empty message")
	}

	api := client.API()
	resolved, err := api.ContactsResolveUsername(ctx, &tg.ContactsResolveUsernameRequest{Username: username})
	if err != nil {
		return fmt.Errorf("resolve username: %w", err)
	}

	peer, err := inputPeerFromResolved(resolved)
	if err != nil {
		return err
	}

	_, err = api.MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
		Peer:     peer,
		Message:  message,
		RandomID: rand.Int63(),
	})
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	return nil
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
