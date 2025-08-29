package models

import (
	"database/sql"
	"errors"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// User 表示系统用户
type User struct {
	ID        int64
	Username  string
	Password  string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

var db *sql.DB

// InitDB 初始化数据库连接
func InitDB() error {
	var err error
	// 使用/app/data目录存储数据库文件，确保在Docker环境中也能正常工作
	db, err = sql.Open("sqlite3", "./data/webssh.db")
	if err != nil {
		return err
	}

	// 创建用户表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		email TEXT UNIQUE,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	)`)

	if err != nil {
		return err
	}

	// 初始化SSH连接记录表
	err = initSSHConnectionTable()
	if err != nil {
		return err
	}

	log.Println("数据库初始化成功")
	return nil
}

// CreateUser 创建新用户
func CreateUser(username, password, email string) error {
	// 检查用户名是否已存在
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("用户名已存在")
	}

	// 检查邮箱是否已存在
	if email != "" {
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&count)
		if err != nil {
			return err
		}
		if count > 0 {
			return errors.New("邮箱已被注册")
		}
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	now := time.Now()
	_, err = db.Exec(
		"INSERT INTO users (username, password, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		username, string(hashedPassword), email, now, now,
	)
	return err
}

// GetUserByUsername 通过用户名获取用户
func GetUserByUsername(username string) (*User, error) {
	user := &User{}
	err := db.QueryRow(
		"SELECT id, username, password, email, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("用户不存在")
		}
		return nil, err
	}
	return user, nil
}

// ValidatePassword 验证用户密码
func ValidatePassword(username, password string) (bool, error) {
	user, err := GetUserByUsername(username)
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}

	return true, nil
}