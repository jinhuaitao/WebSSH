package controllers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"webssh/middleware"
	"webssh/models"
)

// SSHConnectionRequest 表示SSH连接请求
type SSHConnectionRequest struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	AuthType string `json:"authType"`
}

// SSHConnectionResponse 表示SSH连接响应
type SSHConnectionResponse struct {
	ID       int64  `json:"id"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	AuthType string `json:"authType"`
}

// SaveSSHConnectionHandler 保存SSH连接记录
func SaveSSHConnectionHandler(w http.ResponseWriter, r *http.Request) {
	// 检查用户是否已登录
	if !middleware.RequireAuth(w, r) {
		return
	}

	// 获取当前用户
	username := middleware.GetCurrentUser(r)
	user, err := models.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "获取用户信息失败", http.StatusInternalServerError)
		return
	}

	// 解析请求体
	var req SSHConnectionRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	// 保存SSH连接记录
	err = models.SaveSSHConnection(user.ID, req.Host, req.Port, req.Username, req.AuthType)
	if err != nil {
		log.Printf("保存SSH连接记录失败: %v", err)
		http.Error(w, "保存连接记录失败", http.StatusInternalServerError)
		return
	}

	// 返回成功响应
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// GetSSHConnectionsHandler 获取用户的SSH连接记录
func GetSSHConnectionsHandler(w http.ResponseWriter, r *http.Request) {
	// 检查用户是否已登录
	if !middleware.RequireAuth(w, r) {
		return
	}

	// 获取当前用户
	username := middleware.GetCurrentUser(r)
	user, err := models.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "获取用户信息失败", http.StatusInternalServerError)
		return
	}

	// 获取SSH连接记录
	connections, err := models.GetSSHConnectionsByUserID(user.ID)
	if err != nil {
		log.Printf("获取SSH连接记录失败: %v", err)
		http.Error(w, "获取连接记录失败", http.StatusInternalServerError)
		return
	}

	// 转换为响应格式
	var response []SSHConnectionResponse
	for _, conn := range connections {
		response = append(response, SSHConnectionResponse{
			ID:       conn.ID,
			Host:     conn.Host,
			Port:     conn.Port,
			Username: conn.Username,
			AuthType: conn.AuthType,
		})
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")
	
	// 返回连接记录
	json.NewEncoder(w).Encode(response)
}

// DeleteSSHConnectionHandler 删除SSH连接记录
func DeleteSSHConnectionHandler(w http.ResponseWriter, r *http.Request) {
	// 检查用户是否已登录
	if !middleware.RequireAuth(w, r) {
		return
	}

	// 获取当前用户
	username := middleware.GetCurrentUser(r)
	user, err := models.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "获取用户信息失败", http.StatusInternalServerError)
		return
	}

	// 获取连接ID
	connectionID := r.URL.Query().Get("id")
	if connectionID == "" {
		http.Error(w, "缺少连接ID", http.StatusBadRequest)
		return
	}

	// 转换ID为整数
	id, err := strconv.ParseInt(connectionID, 10, 64)
	if err != nil {
		http.Error(w, "无效的连接ID", http.StatusBadRequest)
		return
	}

	// 删除连接记录
	err = models.DeleteSSHConnection(id, user.ID)
	if err != nil {
		log.Printf("删除SSH连接记录失败: %v", err)
		http.Error(w, "删除连接记录失败", http.StatusInternalServerError)
		return
	}

	// 返回成功响应
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}