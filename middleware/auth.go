package middleware

import (
	"log"
	"net/http"

	"github.com/gorilla/sessions"
)

// 会话存储
var (
	// 使用安全的随机密钥，实际应用中应从环境变量或配置文件中读取
	SessionStore = sessions.NewCookieStore([]byte("webssh-secret-key"))
	SessionName  = "webssh-session"
)

func init() {
	// 配置会话
	SessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7天
		HttpOnly: true,
	}
}

// AuthMiddleware 认证中间件
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 获取会话
		session, err := SessionStore.Get(r, SessionName)
		if err != nil {
			log.Printf("获取会话失败: %v", err)
			http.Error(w, "内部服务器错误", http.StatusInternalServerError)
			return
		}

		// 检查用户是否已登录
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			// 用户未登录，重定向到登录页面
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// 用户已登录，继续处理请求
		next.ServeHTTP(w, r)
	})
}

// RequireAuth 检查用户是否已登录，如果未登录则重定向到登录页面
func RequireAuth(w http.ResponseWriter, r *http.Request) bool {
	session, err := SessionStore.Get(r, SessionName)
	if err != nil {
		log.Printf("获取会话失败: %v", err)
		http.Error(w, "内部服务器错误", http.StatusInternalServerError)
		return false
	}

	// 检查用户是否已登录
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		// 用户未登录，重定向到登录页面
		http.Redirect(w, r, "/login", http.StatusFound)
		return false
	}

	return true
}

// GetCurrentUser 获取当前登录的用户名
func GetCurrentUser(r *http.Request) string {
	session, err := SessionStore.Get(r, SessionName)
	if err != nil {
		return ""
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		return ""
	}

	return username
}