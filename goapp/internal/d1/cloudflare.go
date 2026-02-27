package d1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	Token string
	HTTP  *http.Client
}

type cfError struct {
	Message string `json:"message"`
}

type accountsResponse struct {
	Success bool      `json:"success"`
	Errors  []cfError `json:"errors"`
	Result  []struct {
		ID string `json:"id"`
	} `json:"result"`
}

type listD1Response struct {
	Success bool      `json:"success"`
	Errors  []cfError `json:"errors"`
	Result  []struct {
		ID   string `json:"id"`
		UUID string `json:"uuid"`
		Name string `json:"name"`
	} `json:"result"`
}

type createD1Response struct {
	Success bool      `json:"success"`
	Errors  []cfError `json:"errors"`
	Result  struct {
		ID   string `json:"id"`
		UUID string `json:"uuid"`
	} `json:"result"`
}

type d1QueryResponse struct {
	Success bool      `json:"success"`
	Errors  []cfError `json:"errors"`
	Result  []struct {
		Success bool             `json:"success"`
		Results []map[string]any `json:"results"`
		Error   any              `json:"error"`
		Errors  any              `json:"errors"`
		Meta    map[string]any   `json:"meta"`
	} `json:"result"`
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c Client) doJSON(ctx context.Context, method, url string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func firstError(errors []cfError, fallback string) string {
	if len(errors) > 0 && errors[0].Message != "" {
		return errors[0].Message
	}
	return fallback
}

func (c Client) GetFirstAccountID(ctx context.Context) (ok bool, msg string, accountID string) {
	var resp accountsResponse
	if err := c.doJSON(ctx, http.MethodGet, "https://api.cloudflare.com/client/v4/accounts?page=1&per_page=1", nil, &resp); err != nil {
		return false, err.Error(), ""
	}
	if resp.Success && len(resp.Result) > 0 && resp.Result[0].ID != "" {
		return true, "已获取账号。", resp.Result[0].ID
	}
	return false, "获取账号失败：" + firstError(resp.Errors, "无法获取账号"), ""
}

func (c Client) TestToken(ctx context.Context) (ok bool, msg string, accountID string) {
	okAcc, msgAcc, acc := c.GetFirstAccountID(ctx)
	if !okAcc || acc == "" {
		return false, msgAcc, ""
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/d1/database", acc)
	var resp listD1Response
	if err := c.doJSON(ctx, http.MethodGet, url, nil, &resp); err != nil {
		return false, err.Error(), acc
	}
	if resp.Success {
		return true, "Cloudflare API 可用。", acc
	}
	return false, "测试失败：" + firstError(resp.Errors, "测试失败"), acc
}

func (c Client) FindD1ByName(ctx context.Context, accountID, dbName string) (ok bool, msg string, dbID string) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/d1/database", accountID)
	var resp listD1Response
	if err := c.doJSON(ctx, http.MethodGet, url, nil, &resp); err != nil {
		return false, err.Error(), ""
	}
	if resp.Success {
		for _, item := range resp.Result {
			if item.Name == dbName {
				id := item.UUID
				if id == "" {
					id = item.ID
				}
				if id != "" {
					return true, "已找到数据库。", id
				}
			}
		}
		return false, "未找到数据库。", ""
	}
	return false, "查询失败：" + firstError(resp.Errors, "查询失败"), ""
}

func (c Client) CreateD1(ctx context.Context, accountID, dbName string) (ok bool, msg string, dbID string) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/d1/database", accountID)
	var resp createD1Response
	if err := c.doJSON(ctx, http.MethodPost, url, map[string]string{"name": dbName}, &resp); err != nil {
		return false, err.Error(), ""
	}
	if resp.Success {
		id := resp.Result.UUID
		if id == "" {
			id = resp.Result.ID
		}
		return true, "D1 数据库创建成功。", id
	}
	return false, "创建失败：" + firstError(resp.Errors, "创建失败"), ""
}

func (c Client) D1Query(ctx context.Context, accountID, dbID, sql string, params []any) (ok bool, rows []map[string]any, msg string) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/d1/database/%s/query", accountID, dbID)
	payload := map[string]any{"sql": sql}
	if params != nil {
		payload["params"] = params
	}

	var resp d1QueryResponse
	if err := c.doJSON(ctx, http.MethodPost, url, payload, &resp); err != nil {
		return false, nil, err.Error()
	}

	if resp.Success {
		out := make([]map[string]any, 0)
		for _, st := range resp.Result {
			if st.Success {
				out = append(out, st.Results...)
				continue
			}
			if st.Error != nil {
				return false, nil, fmt.Sprint(st.Error)
			}
			if st.Errors != nil {
				return false, nil, fmt.Sprint(st.Errors)
			}
			return false, nil, "query failed"
		}
		return true, out, "ok"
	}

	return false, nil, firstError(resp.Errors, "query failed")
}
