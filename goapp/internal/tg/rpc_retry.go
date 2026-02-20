package tg

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gotd/td/tg"
)

var (
	floodWaitParenPattern  = regexp.MustCompile(`FLOOD_WAIT\s*\((\d+)\)`)
	floodWaitSuffixPattern = regexp.MustCompile(`FLOOD_WAIT_(\d+)`)
)

func messagesGetDialogsWithRetry(ctx context.Context, api *tg.Client, req *tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		res, err := api.MessagesGetDialogs(ctx, req)
		if err == nil {
			return res, nil
		}
		lastErr = err

		waitSeconds, ok := parseFloodWaitSeconds(err)
		if !ok {
			return nil, err
		}
		if waitSeconds <= 0 {
			waitSeconds = 1
		}
		if waitSeconds > 120 {
			return nil, fmt.Errorf("flood wait too long: %w", err)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(waitSeconds+1) * time.Second):
		}
	}
	if lastErr == nil {
		lastErr = context.DeadlineExceeded
	}
	return nil, lastErr
}

func messagesGetHistoryWithRetry(ctx context.Context, api *tg.Client, req *tg.MessagesGetHistoryRequest) (tg.MessagesMessagesClass, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		res, err := api.MessagesGetHistory(ctx, req)
		if err == nil {
			return res, nil
		}
		lastErr = err

		waitSeconds, ok := parseFloodWaitSeconds(err)
		if !ok {
			return nil, err
		}
		if waitSeconds <= 0 {
			waitSeconds = 1
		}
		if waitSeconds > 120 {
			return nil, fmt.Errorf("flood wait too long: %w", err)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(waitSeconds+1) * time.Second):
		}
	}
	if lastErr == nil {
		lastErr = context.DeadlineExceeded
	}
	return nil, lastErr
}

func parseFloodWaitSeconds(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	text := strings.ToUpper(err.Error())
	if m := floodWaitParenPattern.FindStringSubmatch(text); len(m) == 2 {
		if n, convErr := strconv.Atoi(m[1]); convErr == nil {
			return n, true
		}
	}
	if m := floodWaitSuffixPattern.FindStringSubmatch(text); len(m) == 2 {
		if n, convErr := strconv.Atoi(m[1]); convErr == nil {
			return n, true
		}
	}
	return 0, false
}
