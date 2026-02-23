package web

import (
	"net/http"
	"strconv"
	"strings"

	"vpshelper-go/internal/store"
	"vpshelper-go/internal/tunnel"

	"github.com/gin-gonic/gin"
)

func (h *Handler) probeTasks(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	var message string
	var msgOK bool

	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "add":
			name := strings.TrimSpace(c.PostForm("name"))
			target := strings.TrimSpace(c.PostForm("target"))
			nodes := c.PostFormArray("nodes")

			if name == "" || target == "" {
				message = "备注名和IP参数不能为空。"
				break
			}
			
			nodeIDsStr := ""
			if len(nodes) > 0 {
				nodeIDsStr = "," + strings.Join(nodes, ",") + ","
			}

			if err := store.CreateProbeTask(h.dbConn, name, target, nodeIDsStr); err != nil {
				message = "添加失败：" + err.Error()
				break
			}
			go h.syncPingTasksToNodes()
			message = "Ping任务已添加。"
			msgOK = true

		case "edit":
			idStr := strings.TrimSpace(c.PostForm("id"))
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || id <= 0 {
				message = "无效的 ID。"
				break
			}
			name := strings.TrimSpace(c.PostForm("name"))
			target := strings.TrimSpace(c.PostForm("target"))
			nodes := c.PostFormArray("nodes")

			if name == "" || target == "" {
				message = "备注名和IP参数不能为空。"
				break
			}

			nodeIDsStr := ""
			if len(nodes) > 0 {
				nodeIDsStr = "," + strings.Join(nodes, ",") + ","
			}

			if err := store.UpdateProbeTask(h.dbConn, id, name, target, nodeIDsStr); err != nil {
				message = "更新任务失败：" + err.Error()
				break
			}
			go h.syncPingTasksToNodes()
			message = "Ping任务已更新。"
			msgOK = true

		case "delete":
			idStr := strings.TrimSpace(c.PostForm("id"))
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || id <= 0 {
				message = "无效的 ID。"
				break
			}
			if err := store.DeleteProbeTask(h.dbConn, id); err != nil {
				message = "删除失败：" + err.Error()
				break
			}
			go h.syncPingTasksToNodes()
			message = "Ping任务已删除。"
			msgOK = true
		}
	}

	tasks, err := store.ListProbeTasks(h.dbConn)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to load tasks")
		return
	}
	
	nodes, err := store.ListProbeNodes(h.dbConn)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to load nodes")
		return
	}

	c.HTML(http.StatusOK, "probe_tasks.html", gin.H{
		"Title":   "任务管理",
		"Message": message,
		"MsgOK":   msgOK,
		"Tasks":   tasks,
		"Nodes":   nodes,
	})
}

// syncPingTasksToNodes pushes updated ping tasks to all connected probes.
func (h *Handler) syncPingTasksToNodes() {
	tunnel.ActiveSessions.Range(func(key, value interface{}) bool {
		nodeID := key.(int64)
		tasksRaw, _ := store.GetProbeTasksForNode(h.dbConn, nodeID)
		tasksRes := make([]map[string]interface{}, 0, len(tasksRaw))
		for _, t := range tasksRaw {
			tasksRes = append(tasksRes, map[string]interface{}{
				"id":     t.ID,
				"target": t.Target,
			})
		}
		_ = tunnel.PushConfigToNode(nodeID, "ping_tasks", tasksRes)
		return true
	})
}
