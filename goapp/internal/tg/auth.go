package tg

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
)

func SendLoginCode(ctx context.Context, appID int, appHash, phone string, storage telegram.SessionStorage, allProxy string) (string, error) {
	opts, err := newTelegramOptions(storage, true, allProxy)
	if err != nil {
		return "", err
	}
	client := telegram.NewClient(appID, appHash, opts)

	var codeHash string
	err = client.Run(ctx, func(ctx context.Context) error {
		sent, err := client.Auth().SendCode(ctx, phone, auth.SendCodeOptions{})
		if err != nil {
			return err
		}
		hash, err := extractCodeHash(sent)
		if err != nil {
			return err
		}
		codeHash = hash
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("send code: %w", err)
	}
	if codeHash == "" {
		return "", fmt.Errorf("empty code hash")
	}
	return codeHash, nil
}

func SignIn(ctx context.Context, appID int, appHash, phone, code, codeHash, password string, storage telegram.SessionStorage, allProxy string) (*tg.User, error) {
	opts, err := newTelegramOptions(storage, true, allProxy)
	if err != nil {
		return nil, err
	}
	client := telegram.NewClient(appID, appHash, opts)

	var self *tg.User
	err = client.Run(ctx, func(ctx context.Context) error {
		authClient := client.Auth()
		if _, err := authClient.SignIn(ctx, phone, code, codeHash); err != nil {
			if errors.Is(err, auth.ErrPasswordAuthNeeded) {
				if password == "" {
					return auth.ErrPasswordNotProvided
				}
				if _, err := authClient.Password(ctx, password); err != nil {
					return err
				}
			} else {
				return err
			}
		}

		user, err := client.Self(ctx)
		if err != nil {
			return err
		}
		self = user
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sign in: %w", err)
	}
	if self == nil {
		return nil, fmt.Errorf("missing user")
	}
	return self, nil
}

func extractCodeHash(sent tg.AuthSentCodeClass) (string, error) {
	switch v := sent.(type) {
	case *tg.AuthSentCode:
		return v.PhoneCodeHash, nil
	case *tg.AuthSentCodeSuccess:
		return "", fmt.Errorf("already authorized")
	default:
		return "", fmt.Errorf("unsupported sent code response")
	}
}

func newTelegramOptions(storage telegram.SessionStorage, noUpdates bool, allProxy string) (telegram.Options, error) {
	old := os.Getenv("ALL_PROXY")
	if allProxy != "" {
		_ = os.Setenv("ALL_PROXY", allProxy)
	}
	defer func() {
		if allProxy != "" {
			_ = os.Setenv("ALL_PROXY", old)
		}
	}()

	opts := telegram.Options{SessionStorage: storage, NoUpdates: noUpdates}
	return telegram.OptionsFromEnvironment(opts)
}
