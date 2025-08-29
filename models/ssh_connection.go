package models

import (
	"log"
	"time"
)

// SSHConnection 表示用户的SSH连接记录
type SSHConnection struct {
	ID        int64
	UserID    int64
	Host      string
	Port      string
	Username  string
	AuthType  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// 初始化SSH连接记录表
func initSSHConnectionTable() error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS ssh_connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		port TEXT NOT NULL,
		username TEXT NOT NULL,
		auth_type TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	)`)

	if err != nil {
		return err
	}

	log.Println("SSH连接记录表初始化成功")
	return nil
}

// SaveSSHConnection 保存SSH连接记录
func SaveSSHConnection(userID int64, host, port, username, authType string) error {
	// 检查是否已存在相同的连接记录
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM ssh_connections 
		WHERE user_id = ? AND host = ? AND port = ? AND username = ? AND auth_type = ?`,
		userID, host, port, username, authType).Scan(&count)
	
	if err != nil {
		return err
	}

	now := time.Now()

	// 如果已存在，则更新时间戳
	if count > 0 {
		_, err = db.Exec(`
			UPDATE ssh_connections 
			SET updated_at = ? 
			WHERE user_id = ? AND host = ? AND port = ? AND username = ? AND auth_type = ?`,
			now, userID, host, port, username, authType)
		return err
	}

	// 不存在则创建新记录
	_, err = db.Exec(`
		INSERT INTO ssh_connections (user_id, host, port, username, auth_type, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, host, port, username, authType, now, now)
	
	return err
}

// GetSSHConnectionsByUserID 获取用户的SSH连接记录
func GetSSHConnectionsByUserID(userID int64) ([]SSHConnection, error) {
	rows, err := db.Query(`
		SELECT id, user_id, host, port, username, auth_type, created_at, updated_at
		FROM ssh_connections
		WHERE user_id = ?
		ORDER BY updated_at DESC
		LIMIT 10`, // 限制返回最近的10条记录
		userID)
	
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []SSHConnection
	for rows.Next() {
		var conn SSHConnection
		err := rows.Scan(
			&conn.ID,
			&conn.UserID,
			&conn.Host,
			&conn.Port,
			&conn.Username,
			&conn.AuthType,
			&conn.CreatedAt,
			&conn.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		connections = append(connections, conn)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return connections, nil
}

// DeleteSSHConnection 删除SSH连接记录
func DeleteSSHConnection(id, userID int64) error {
	_, err := db.Exec("DELETE FROM ssh_connections WHERE id = ? AND user_id = ?", id, userID)
	return err
}