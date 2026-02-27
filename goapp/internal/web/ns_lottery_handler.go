package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"vpshelper-go/internal/ns"
	"vpshelper-go/internal/store"
)

func (h *Handler) nsLottery(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	message := ""
	msgOK := false

	// Load watch_username default from settings.
	settings, _ := store.GetSettings(h.dbConn, []string{"ns_lottery_username"})
	watchUsername := strings.TrimSpace(settings["ns_lottery_username"])

	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "save_username":
			watchUsername = strings.TrimSpace(c.PostForm("watch_username"))
			_ = store.SetSetting(h.dbConn, "ns_lottery_username", watchUsername)
			message = "用户名已保存。"
			msgOK = true

		case "add":
			rawURL := strings.TrimSpace(c.PostForm("lottery_url"))
			if rawURL == "" {
				message = "请填写抽奖链接。"
				break
			}
			params, err := ns.ParseLotteryURL(rawURL)
			if err != nil {
				message = "链接解析失败：" + err.Error()
				break
			}
			uname := strings.TrimSpace(c.PostForm("watch_username"))
			if uname == "" {
				uname = watchUsername
			}
			if uname == "" {
				message = "请先设置监视用户名。"
				break
			}
			_, err = store.CreateLotteryWatch(
				username, rawURL, params.PostID, params.DrawTimeMs,
				params.Count, params.StartFloor, params.Duplicate, uname,
			)
			if err != nil {
				message = "添加失败：" + err.Error()
				break
			}
			message = "已添加抽奖监视。"
			msgOK = true

		case "delete":
			idText := strings.TrimSpace(c.PostForm("id"))
			id, _ := strconv.ParseInt(idText, 10, 64)
			if id > 0 {
				_ = store.DeleteLotteryWatch(username, id)
				message = "已删除。"
				msgOK = true
			}

		case "check_now":
			idText := strings.TrimSpace(c.PostForm("id"))
			id, _ := strconv.ParseInt(idText, 10, 64)
			if id > 0 {
				watches, _ := store.ListLotteryWatches(username)
				for _, w := range watches {
					if w.ID == id && w.Status == "pending" {
						now := time.Now().UnixMilli()
						if w.DrawTime > now {
							message = "尚未到开奖时间，无法立即检查。"
							break
						}
						result, err := ns.CheckResult(c.Request.Context(), w.URL, w.WatchUsername)
						if err != nil {
							message = "检查失败：" + err.Error()
							break
						}
						status := "drawn"
						if result.IsWon {
							status = "won"
						}
						winnersStr := "[]"
						if len(result.Winners) > 0 {
							var parts []string
							for _, n := range result.Winners {
								parts = append(parts, `"`+n+`"`)
							}
							winnersStr = "[" + strings.Join(parts, ",") + "]"
						}
						_ = store.UpdateLotteryWatchResult(w.ID, status, winnersStr, result.Note)
						message = result.Note
						msgOK = true
						break
					}
				}
			}
		}
	}

	watches, _ := store.ListLotteryWatches(username)

	// Split into categories.
	var pending, drawn, won []store.LotteryWatch
	for _, w := range watches {
		switch w.Status {
		case "won":
			won = append(won, w)
		case "drawn":
			drawn = append(drawn, w)
		default:
			pending = append(pending, w)
		}
	}

	c.HTML(http.StatusOK, "ns_lottery.html", gin.H{
		"Title":         "抽奖监视",
		"Message":       message,
		"MsgOK":         msgOK,
		"WatchUsername": watchUsername,
		"Pending":       pending,
		"Drawn":         drawn,
		"Won":           won,
	})
}
