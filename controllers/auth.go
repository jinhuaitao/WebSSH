package controllers

import (
	"html/template"
	"log"
	"net/http"
	"strings"

	"webssh/middleware"
	"webssh/models"
)

var templates = template.Must(template.ParseGlob("templates/*.html"))

// RegisterHandler 处理用户注册
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// 如果用户已登录，重定向到首页
	session, _ := middleware.SessionStore.Get(r, middleware.SessionName)
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.Method == "POST" {
		// 解析表单
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "无法解析表单", http.StatusBadRequest)
			return
		}

		// 获取表单数据
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")
		email := strings.TrimSpace(r.FormValue("email"))

		// 验证表单数据
		if username == "" || password == "" {
			templates.ExecuteTemplate(w, "register.html", map[string]interface{}{
				"Error": "用户名和密码不能为空",
			})
			return
		}

		if password != confirmPassword {
			templates.ExecuteTemplate(w, "register.html", map[string]interface{}{
				"Error": "两次输入的密码不一致",
				"Username": username,
				"Email": email,
			})
			return
		}

		// 创建用户
		err = models.CreateUser(username, password, email)
		if err != nil {
			templates.ExecuteTemplate(w, "register.html", map[string]interface{}{
				"Error": err.Error(),
				"Username": username,
				"Email": email,
			})
			return
		}

		// 注册成功，重定向到登录页面
		http.Redirect(w, r, "/login?registered=true", http.StatusFound)
		return
	}

	// GET请求，显示注册表单
	templates.ExecuteTemplate(w, "register.html", nil)
}

// LoginHandler 处理用户登录
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// 如果用户已登录，重定向到首页
	session, _ := middleware.SessionStore.Get(r, middleware.SessionName)
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// 检查是否是注册成功后的重定向
	registered := r.URL.Query().Get("registered") == "true"

	if r.Method == "POST" {
		// 解析表单
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "无法解析表单", http.StatusBadRequest)
			return
		}

		// 获取表单数据
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		// 验证表单数据
		if username == "" || password == "" {
			templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
				"Error": "用户名和密码不能为空",
			})
			return
		}

		// 验证用户凭据
		valid, err := models.ValidatePassword(username, password)
		if err != nil {
			templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
				"Error": err.Error(),
				"Username": username,
			})
			return
		}

		if !valid {
			templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
				"Error": "用户名或密码错误",
				"Username": username,
			})
			return
		}

		// 登录成功，设置会话
		session.Values["authenticated"] = true
		session.Values["username"] = username
		err = session.Save(r, w)
		if err != nil {
			log.Printf("保存会话失败: %v", err)
			http.Error(w, "内部服务器错误", http.StatusInternalServerError)
			return
		}

		// 重定向到首页
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// GET请求，显示登录表单
	templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
		"Registered": registered,
	})
}

// LogoutHandler 处理用户登出
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// 获取会话
	session, err := middleware.SessionStore.Get(r, middleware.SessionName)
	if err != nil {
		http.Error(w, "内部服务器错误", http.StatusInternalServerError)
		return
	}

	// 清除会话数据
	session.Values["authenticated"] = false
	session.Values["username"] = ""
	err = session.Save(r, w)
	if err != nil {
		log.Printf("保存会话失败: %v", err)
		http.Error(w, "内部服务器错误", http.StatusInternalServerError)
		return
	}

	// 重定向到登录页面
	http.Redirect(w, r, "/login", http.StatusFound)
}