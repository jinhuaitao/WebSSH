package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ssh"
)

// --- 数据模型 ---

type AppConfig struct {
	IsSetup    bool   `json:"is_setup"`
	AdminUser  string `json:"admin_user"`
	AdminPass  string `json:"admin_pass"`
	TGBotToken string `json:"tg_bot_token"`
	TGChatID   string `json:"tg_chat_id"`
	TOTPSecret string `json:"totp_secret"` // 2FA 密钥
}

type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Credential struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"` // SSH 私钥
}

type Server struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	GroupID      string `json:"group_id"`
	CredentialID string `json:"credential_id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

type Snippet struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Command string `json:"command"`
}

type Database struct {
	Config      AppConfig            `json:"config"`
	Groups      []Group              `json:"groups"`
	Credentials []Credential         `json:"credentials"`
	Servers     []Server             `json:"servers"`
	Snippets    []Snippet            `json:"snippets"`
	Sessions    map[string]time.Time `json:"-"`
}

type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
	IsDir   bool   `json:"is_dir"`
}

var (
	db       *Database
	dbLock   sync.RWMutex
	dbFile   = "data.json"
	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

// --- 数据持久化 ---

func loadData() {
	dbLock.Lock()
	defer dbLock.Unlock()
	db = &Database{Sessions: make(map[string]time.Time)}
	file, err := os.ReadFile(dbFile)
	if err == nil {
		json.Unmarshal(file, db)
	}
	if db.Sessions == nil {
		db.Sessions = make(map[string]time.Time)
	}
}

func saveData() {
	dbLock.Lock()
	defer dbLock.Unlock()
	data, _ := json.MarshalIndent(db, "", "  ")
	os.WriteFile(dbFile, data, 0644)
}

// --- TG 通知 ---

func sendTelegramNotification(text string) {
	dbLock.RLock()
	token := db.Config.TGBotToken
	chatID := db.Config.TGChatID
	dbLock.RUnlock()
	if token == "" || chatID == "" {
		return
	}
	go func() {
		apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
		resp, err := http.PostForm(apiURL, url.Values{"chat_id": {chatID}, "text": {text}})
		if err != nil {
			log.Printf("TG Error: %v", err)
			return
		}
		defer resp.Body.Close()
	}()
}

// --- SSH 逻辑 ---

func getSSHClient(serverID string) (*ssh.Client, error) {
	var srv Server
	var sshUser, sshPass, sshKey string
	dbLock.RLock()
	for _, s := range db.Servers {
		if s.ID == serverID {
			srv = s
			break
		}
	}
	if srv.CredentialID != "" {
		for _, c := range db.Credentials {
			if c.ID == srv.CredentialID {
				sshUser = c.Username
				sshPass = c.Password
				sshKey = c.PrivateKey
				break
			}
		}
	} else {
		sshUser = srv.Username
		sshPass = srv.Password
	}
	dbLock.RUnlock()
	if srv.ID == "" {
		return nil, fmt.Errorf("server not found")
	}

	authMethods := []ssh.AuthMethod{}
	if sshKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(sshKey))
		if err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		} else {
			log.Printf("Key parse error for %s: %v", srv.Name, err)
		}
	}
	if sshPass != "" {
		authMethods = append(authMethods, ssh.Password(sshPass))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no valid auth method")
	}

	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", srv.IP, srv.Port), config)
}

// --- 主程序 ---

func main() {
	loadData()
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/setup", handleSetup)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/save", handleSaveData)
	http.HandleFunc("/api/backup", handleBackup)
	http.HandleFunc("/api/restore", handleRestore)

	// --- PWA Routes ---
	http.HandleFunc("/manifest.json", handleManifest)
	http.HandleFunc("/sw.js", handleServiceWorker)

	http.HandleFunc("/api/2fa/gen", handle2FAGenerate)
	http.HandleFunc("/api/2fa/enable", handle2FAEnable)
	http.HandleFunc("/api/2fa/disable", handle2FADisable)

	http.HandleFunc("/ws/ssh", handleWebsocketSSH)
	http.HandleFunc("/api/sftp/list", handleSFTPList)
	http.HandleFunc("/api/sftp/download", handleSFTPDownload)
	http.HandleFunc("/api/sftp/upload", handleSFTPUpload)
	http.HandleFunc("/api/sftp/cat", handleSFTPCat)
	http.HandleFunc("/api/sftp/save", handleSFTPSave)

	fmt.Println("Web SSH 启动在 http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// --- Handlers ---

func checkAuth(r *http.Request) bool {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}
	dbLock.RLock()
	defer dbLock.RUnlock()
	expiry, ok := db.Sessions[cookie.Value]
	return ok && time.Now().Before(expiry)
}

func handleManifest(w http.ResponseWriter, r *http.Request) {
	manifest := `{
		"name": "WebSSH Manager",
		"short_name": "WebSSH",
		"start_url": "/",
		"display": "standalone",
		"background_color": "#0f172a",
		"theme_color": "#0f172a",
		"icons": [
			{
				"src": "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/icons/terminal-fill.svg",
				"sizes": "192x192",
				"type": "image/svg+xml"
			},
			{
				"src": "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/icons/hdd-rack-fill.svg",
				"sizes": "512x512",
				"type": "image/svg+xml"
			}
		]
	}`
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(manifest))
}

func handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	sw := `
	self.addEventListener('install', (e) => {
		e.waitUntil(
			caches.open('webssh-store').then((cache) => cache.addAll([
				'/',
				'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
				'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css',
				'https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css'
			]))
		);
	});
	self.addEventListener('fetch', (e) => {
		e.respondWith(
			fetch(e.request).catch(() => caches.match(e.request))
		);
	});`
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(sw))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	dbLock.RLock()
	isSetup := db.Config.IsSetup
	require2FA := db.Config.TOTPSecret != ""
	dbLock.RUnlock()

	if !isSetup {
		renderTemplate(w, "setup", nil)
		return
	}
	if !checkAuth(r) {
		renderTemplate(w, "login", map[string]bool{"Require2FA": require2FA})
		return
	}

	dbLock.RLock()
	data := *db
	dbLock.RUnlock()
	renderTemplate(w, "dashboard", data)
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "405", 405)
		return
	}
	dbLock.Lock()
	db.Config.AdminUser = r.FormValue("username")
	db.Config.AdminPass = r.FormValue("password")
	db.Config.IsSetup = true
	dbLock.Unlock()
	saveData()
	http.Redirect(w, r, "/", 302)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "405", 405)
		return
	}
	user, pass := r.FormValue("username"), r.FormValue("password")
	code := r.FormValue("code")

	dbLock.RLock()
	adminUser := db.Config.AdminUser
	adminPass := db.Config.AdminPass
	totpSecret := db.Config.TOTPSecret
	dbLock.RUnlock()

	if user != adminUser || pass != adminPass {
		http.Redirect(w, r, "/?error=invalid", 302)
		return
	}

	loginType := "密码登录"
	if totpSecret != "" {
		if code == "" {
			http.Redirect(w, r, "/?error=code_required", 302)
			return
		}
		if !totp.Validate(code, totpSecret) {
			http.Redirect(w, r, "/?error=invalid_code", 302)
			return
		}
		loginType = "2FA登录"
	}

	token := fmt.Sprintf("%d", time.Now().UnixNano())
	dbLock.Lock()
	db.Sessions[token] = time.Now().Add(24 * time.Hour)
	dbLock.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: token, Path: "/"})

	sendTelegramNotification(fmt.Sprintf("🔔 WebSSH 登录通知\n用户: %s\n方式: %s\nIP: %s\n时间: %s", user, loginType, r.RemoteAddr, time.Now().Format("2006-01-02 15:04:05")))
	http.Redirect(w, r, "/", 302)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		dbLock.Lock()
		delete(db.Sessions, cookie.Value)
		dbLock.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", 302)
}

func handle2FAGenerate(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "WebSSH", AccountName: "Admin"})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"secret": key.Secret(), "url": key.URL()})
}

func handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "405", 405)
		return
	}
	secret := r.FormValue("secret")
	code := r.FormValue("code")
	if !totp.Validate(code, secret) {
		http.Error(w, "验证失败", 400)
		return
	}
	dbLock.Lock()
	db.Config.TOTPSecret = secret
	dbLock.Unlock()
	saveData()
	w.Write([]byte("ok"))
}

func handle2FADisable(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "405", 405)
		return
	}
	dbLock.Lock()
	db.Config.TOTPSecret = ""
	dbLock.Unlock()
	saveData()
	w.Write([]byte("ok"))
}

func handleBackup(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	dbLock.RLock()
	data, _ := json.MarshalIndent(db, "", "  ")
	dbLock.RUnlock()
	w.Header().Set("Content-Disposition", "attachment; filename=webssh_backup.json")
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleRestore(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "405", 405)
		return
	}
	file, _, err := r.FormFile("backup_file")
	if err != nil {
		http.Error(w, "Invalid file", 400)
		return
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Read error", 500)
		return
	}
	var tempDB Database
	if err := json.Unmarshal(content, &tempDB); err != nil {
		http.Error(w, "Invalid backup file format", 400)
		return
	}
	dbLock.Lock()
	os.WriteFile(dbFile, content, 0644)
	dbLock.Unlock()
	loadData()
	w.Write([]byte("ok"))
}

func handleSaveData(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "405", 405)
		return
	}
	type ActionReq struct {
		Type        string     `json:"type"`
		Action      string     `json:"action"`
		Group       Group      `json:"group"`
		Server      Server     `json:"server"`
		Credential  Credential `json:"credential"`
		Snippet     Snippet    `json:"snippet"`
		NewPassword string     `json:"new_password"`
		TGBotToken  string     `json:"tg_bot_token"`
		TGChatID    string     `json:"tg_chat_id"`
		DeleteID    string     `json:"delete_id"`
		EditID      string     `json:"edit_id"`
	}
	var req ActionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	dbLock.Lock()
	defer func() { dbLock.Unlock(); saveData() }()
	switch req.Type {
	case "group":
		if req.Action == "add" {
			db.Groups = append(db.Groups, req.Group)
		}
		if req.Action == "delete" {
			n := []Group{}
			for _, v := range db.Groups {
				if v.ID != req.DeleteID {
					n = append(n, v)
				}
			}
			db.Groups = n
			// 删除分组时，将该组下的服务器重置为无分组
			for i := range db.Servers {
				if db.Servers[i].GroupID == req.DeleteID {
					db.Servers[i].GroupID = ""
				}
			}
		}
		if req.Action == "edit" {
			for i, v := range db.Groups {
				if v.ID == req.Group.ID {
					db.Groups[i] = req.Group
					break
				}
			}
		}
	case "credential":
		if req.Action == "add" {
			db.Credentials = append(db.Credentials, req.Credential)
		}
		if req.Action == "delete" {
			n := []Credential{}
			for _, v := range db.Credentials {
				if v.ID != req.DeleteID {
					n = append(n, v)
				}
			}
			db.Credentials = n
		}
		if req.Action == "edit" {
			for i, v := range db.Credentials {
				if v.ID == req.Credential.ID {
					db.Credentials[i] = req.Credential
					break
				}
			}
		}
	case "server":
		if req.Action == "add" {
			db.Servers = append(db.Servers, req.Server)
		}
		if req.Action == "delete" {
			n := []Server{}
			for _, v := range db.Servers {
				if v.ID != req.DeleteID {
					n = append(n, v)
				}
			}
			db.Servers = n
		}
		if req.Action == "edit" {
			for i, v := range db.Servers {
				if v.ID == req.Server.ID {
					db.Servers[i] = req.Server
					break
				}
			}
		}
	case "snippet":
		if req.Action == "add" {
			db.Snippets = append(db.Snippets, req.Snippet)
		}
		if req.Action == "delete" {
			n := []Snippet{}
			for _, v := range db.Snippets {
				if v.ID != req.DeleteID {
					n = append(n, v)
				}
			}
			db.Snippets = n
		}
		if req.Action == "edit" {
			for i, v := range db.Snippets {
				if v.ID == req.Snippet.ID {
					db.Snippets[i] = req.Snippet
					break
				}
			}
		}
	case "settings":
		if req.NewPassword != "" {
			db.Config.AdminPass = req.NewPassword
		}
		db.Config.TGBotToken = req.TGBotToken
		db.Config.TGChatID = req.TGChatID
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func handleWebsocketSSH(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	serverID := r.URL.Query().Get("id")
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	var srvName, srvIP string
	dbLock.RLock()
	for _, s := range db.Servers {
		if s.ID == serverID {
			srvName = s.Name
			srvIP = s.IP
			break
		}
	}
	dbLock.RUnlock()
	sendTelegramNotification(fmt.Sprintf("🔌 SSH 连接通知\n服务器: %s (%s)\n操作者IP: %s\n时间: %s", srvName, srvIP, r.RemoteAddr, time.Now().Format("15:04:05")))
	client, err := getSSHClient(serverID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return
	}
	defer session.Close()
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm", rows, cols, modes); err != nil {
		return
	}
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()
	go io.Copy(wsWriter{ws}, stdout)
	go io.Copy(wsWriter{ws}, stderr)
	if err := session.Shell(); err != nil {
		return
	}
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}
		stdin.Write(msg)
	}
}

type wsWriter struct{ *websocket.Conn }

func (w wsWriter) Write(p []byte) (n int, err error) {
	err = w.Conn.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

func handleSFTPList(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	serverID := r.URL.Query().Get("id")
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "."
	}
	client, err := getSSHClient(serverID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer sftpClient.Close()
	files, err := sftpClient.ReadDir(path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	realPath, err := sftpClient.RealPath(path)
	if err != nil {
		realPath = path
	}
	var fileList []FileInfo
	if realPath != "/" && realPath != "." {
		fileList = append(fileList, FileInfo{Name: "..", IsDir: true})
	}
	for _, f := range files {
		fileList = append(fileList, FileInfo{Name: f.Name(), Size: f.Size(), ModTime: f.ModTime().Format("2006-01-02 15:04"), IsDir: f.IsDir()})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"path": realPath, "files": fileList})
}

func handleSFTPDownload(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	serverID := r.URL.Query().Get("id")
	path := r.URL.Query().Get("path")
	client, err := getSSHClient(serverID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer sftpClient.Close()
	file, err := sftpClient.Open(path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(path))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, file)
}

func handleSFTPUpload(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "405", 405)
		return
	}
	r.ParseMultipartForm(32 << 20)
	serverID := r.FormValue("id")
	remotePath := r.FormValue("path")
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer file.Close()
	client, err := getSSHClient(serverID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer sftpClient.Close()
	destPath := filepath.Join(remotePath, header.Filename)
	destFile, err := sftpClient.Create(destPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer destFile.Close()
	io.Copy(destFile, file)
	w.Write([]byte("ok"))
}

func handleSFTPCat(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	serverID := r.URL.Query().Get("id")
	path := r.URL.Query().Get("path")
	client, err := getSSHClient(serverID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer sftpClient.Close()
	file, err := sftpClient.Open(path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	const maxReadSize = 2 * 1024 * 1024
	content, err := io.ReadAll(io.LimitReader(file, maxReadSize))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(content)
}

func handleSFTPSave(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "405", 405)
		return
	}
	serverID := r.FormValue("id")
	path := r.FormValue("path")
	content := r.FormValue("content")
	client, err := getSSHClient(serverID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer sftpClient.Close()
	f, err := sftpClient.Create(path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer f.Close()
	if _, err := f.Write([]byte(content)); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write([]byte("ok"))
}

func renderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	funcMap := template.FuncMap{"json": func(v interface{}) template.JS { a, _ := json.Marshal(v); return template.JS(a) }}
	
	fullTpl := tplSetup + tplLogin + 
		`{{ define "dashboard" }}<!DOCTYPE html><html><head><title>WebSSH</title>` +
		`<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">` + 
		`<link rel="manifest" href="/manifest.json">` +
		`<meta name="theme-color" content="#0f172a">` +
		`<meta name="apple-mobile-web-app-capable" content="yes">` +
		`<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">` +
		`<link rel="apple-touch-icon" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/icons/terminal-fill.svg">` +
		dashCSS + `</head><body class="d-flex" data-theme="light">` +
		dashBody + dashModals + dashScript + `</body></html>{{ end }}`
	
	t, _ := template.New("html").Funcs(funcMap).Parse(fullTpl)
	t.ExecuteTemplate(w, tmplName, data)
}

const tplSetup = `{{ define "setup" }}<!DOCTYPE html><html><head><title>Setup</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root { --bg-body: #0f172a; --bg-card: rgba(30, 41, 59, 0.8); --text-main: #f8fafc; --text-muted: #94a3b8; --input-bg: #020617; --input-border: #334155; --accent: #3b82f6; --bg-grad-1: #1e293b; --bg-grad-2: #3b82f6; }
[data-theme="light"] { --bg-body: #f1f5f9; --bg-card: rgba(255, 255, 255, 0.85); --text-main: #0f172a; --text-muted: #64748b; --input-bg: #ffffff; --input-border: #cbd5e1; --accent: #2563eb; --bg-grad-1: #e2e8f0; --bg-grad-2: #cbd5e1; }
body { margin: 0; padding: 0; height: 100vh; font-family: 'Inter', system-ui, -apple-system, sans-serif; background-color: var(--bg-body); background-image: radial-gradient(at 50% 0%, var(--bg-grad-1) 0px, transparent 50%), radial-gradient(at 100% 0%, var(--bg-grad-2) 0px, transparent 50%); display: flex; align-items: center; justify-content: center; color: var(--text-main); transition: background-color 0.3s, color 0.3s; position: relative; }
.login-card { background: var(--bg-card); backdrop-filter: blur(12px); border: 1px solid rgba(128, 128, 128, 0.1); width: 100%; max-width: 400px; padding: 2.5rem; border-radius: 1rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.15); animation: fadeUp 0.5s ease-out; }
.brand { display: flex; align-items: center; justify-content: center; margin-bottom: 2rem; font-size: 1.5rem; font-weight: 700; color: var(--text-main); gap: 0.75rem; }
.brand i { color: var(--accent); font-size: 1.75rem; }
.input-group { position: relative; margin-bottom: 1.25rem; }
.input-icon { position: absolute; left: 1rem; top: 50%; transform: translateY(-50%); color: var(--text-muted); pointer-events: none; transition: color 0.2s; z-index: 5; }
.form-control { width: 100%; background: var(--input-bg); border: 1px solid var(--input-border); color: var(--text-main); padding: 0.875rem 1rem 0.875rem 3rem; border-radius: 0.5rem; font-size: 0.95rem; transition: all 0.2s; box-sizing: border-box; }
.form-control:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15); background: var(--input-bg); color: var(--text-main); }
.form-control:focus + .input-icon { color: var(--accent); }
.btn-login { width: 100%; background: linear-gradient(135deg, var(--accent) 0%, #2563eb 100%); color: white; border: none; padding: 0.875rem; border-radius: 0.5rem; font-weight: 600; font-size: 1rem; cursor: pointer; transition: transform 0.1s, opacity 0.2s; margin-top: 0.5rem; }
.btn-login:hover { opacity: 0.95; transform: translateY(-1px); }
.btn-login:active { transform: translateY(0); }
.footer { text-align: center; margin-top: 2rem; color: var(--text-muted); font-size: 0.8rem; }
.theme-toggle { position: absolute; top: 1.5rem; right: 1.5rem; cursor: pointer; color: var(--text-muted); font-size: 1.25rem; transition: color 0.2s; }
.theme-toggle:hover { color: var(--accent); }
@keyframes fadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
</style></head><body data-theme="light">
<div class="theme-toggle" onclick="toggleLoginTheme()"><i class="bi bi-sun-fill" id="theme-icon"></i></div>
<div class="login-card"><div class="brand"><i class="bi bi-hdd-rack-fill"></i> WebSSH Setup</div>
<form action="/api/setup" method="post"><div class="input-group"><input type="text" name="username" class="form-control" placeholder="设置管理员账号" required autocomplete="off"><i class="bi bi-person input-icon"></i></div>
<div class="input-group"><input type="password" name="password" class="form-control" placeholder="设置管理员密码" required><i class="bi bi-shield-lock input-icon"></i></div>
<button class="btn-login">完成初始化</button></form><div class="footer">Initial Configuration</div></div>
<script>
    function initLoginTheme() { const stored = localStorage.getItem('theme'); if (stored) { document.body.setAttribute('data-theme', stored); } else { document.body.setAttribute('data-theme', 'light'); } updateIcon(); }
    function toggleLoginTheme() { const current = document.body.getAttribute('data-theme') || 'light'; const next = current === 'dark' ? 'light' : 'dark'; document.body.setAttribute('data-theme', next); localStorage.setItem('theme', next); updateIcon(); }
    function updateIcon() { const isDark = document.body.getAttribute('data-theme') === 'dark'; const icon = document.getElementById('theme-icon'); icon.className = isDark ? 'bi bi-moon-fill' : 'bi bi-sun-fill'; }
    initLoginTheme();
</script></body></html>{{ end }}`

const tplLogin = `{{ define "login" }}<!DOCTYPE html><html><head><title>Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root { --bg-body: #0f172a; --bg-card: rgba(30, 41, 59, 0.8); --text-main: #f8fafc; --text-muted: #94a3b8; --input-bg: #020617; --input-border: #334155; --accent: #3b82f6; --bg-grad-1: #1e293b; --bg-grad-2: #3b82f6; }
[data-theme="light"] { --bg-body: #f1f5f9; --bg-card: rgba(255, 255, 255, 0.85); --text-main: #0f172a; --text-muted: #64748b; --input-bg: #ffffff; --input-border: #cbd5e1; --accent: #2563eb; --bg-grad-1: #e2e8f0; --bg-grad-2: #cbd5e1; }
body { margin: 0; padding: 0; height: 100vh; font-family: 'Inter', system-ui, -apple-system, sans-serif; background-color: var(--bg-body); background-image: radial-gradient(at 50% 0%, var(--bg-grad-1) 0px, transparent 50%), radial-gradient(at 100% 0%, var(--bg-grad-2) 0px, transparent 50%); display: flex; align-items: center; justify-content: center; color: var(--text-main); transition: background-color 0.3s, color 0.3s; position: relative; }
.login-card { background: var(--bg-card); backdrop-filter: blur(12px); border: 1px solid rgba(128, 128, 128, 0.1); width: 100%; max-width: 400px; padding: 2.5rem; border-radius: 1rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.15); animation: fadeUp 0.5s ease-out; }
.brand { display: flex; align-items: center; justify-content: center; margin-bottom: 2rem; font-size: 1.5rem; font-weight: 700; color: var(--text-main); gap: 0.75rem; }
.brand i { color: var(--accent); font-size: 1.75rem; }
.input-group { position: relative; margin-bottom: 1.25rem; }
.input-icon { position: absolute; left: 1rem; top: 50%; transform: translateY(-50%); color: var(--text-muted); pointer-events: none; transition: color 0.2s; z-index: 5; }
.form-control { width: 100%; background: var(--input-bg); border: 1px solid var(--input-border); color: var(--text-main); padding: 0.875rem 1rem 0.875rem 3rem; border-radius: 0.5rem; font-size: 0.95rem; transition: all 0.2s; box-sizing: border-box; }
.form-control:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15); background: var(--input-bg); color: var(--text-main); }
.form-control:focus + .input-icon { color: var(--accent); }
.btn-login { width: 100%; background: linear-gradient(135deg, var(--accent) 0%, #2563eb 100%); color: white; border: none; padding: 0.875rem; border-radius: 0.5rem; font-weight: 600; font-size: 1rem; cursor: pointer; transition: transform 0.1s, opacity 0.2s; margin-top: 0.5rem; }
.btn-login:hover { opacity: 0.95; transform: translateY(-1px); }
.btn-login:active { transform: translateY(0); }
.footer { text-align: center; margin-top: 2rem; color: var(--text-muted); font-size: 0.8rem; }
.alert-box { color: var(--danger, #ef4444); font-size: 0.9rem; text-align: center; margin-bottom: 1rem; display: none; }
.theme-toggle { position: absolute; top: 1.5rem; right: 1.5rem; cursor: pointer; color: var(--text-muted); font-size: 1.25rem; transition: color 0.2s; }
.theme-toggle:hover { color: var(--accent); }
@keyframes fadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
</style></head><body data-theme="light">
<div class="theme-toggle" onclick="toggleLoginTheme()"><i class="bi bi-sun-fill" id="theme-icon"></i></div>
<div class="login-card"><div class="brand"><i class="bi bi-hdd-rack-fill"></i> WebSSH</div>
<div id="error-msg" class="alert-box"></div>
<form action="/api/login" method="post"><div class="input-group"><input type="text" name="username" class="form-control" placeholder="用户名" required autocomplete="off"><i class="bi bi-person input-icon"></i></div>
<div class="input-group"><input type="password" name="password" class="form-control" placeholder="密码" required><i class="bi bi-shield-lock input-icon"></i></div>
{{if .Require2FA}}
<div class="input-group"><input type="text" name="code" class="form-control" placeholder="2FA 验证码" required autocomplete="off" inputmode="numeric"><i class="bi bi-phone input-icon"></i></div>
{{end}}
<button class="btn-login">安全登录</button></form><div class="footer">Secure Terminal Access</div></div>
<script>
    const params = new URLSearchParams(window.location.search);
    const err = params.get("error");
    const box = document.getElementById("error-msg");
    if(err === "invalid") { box.innerText = "用户名或密码错误"; box.style.display = "block"; }
    if(err === "code_required") { box.innerText = "请输入 2FA 验证码"; box.style.display = "block"; }
    if(err === "invalid_code") { box.innerText = "2FA 验证码错误"; box.style.display = "block"; }
    function initLoginTheme() { const stored = localStorage.getItem('theme'); if (stored) { document.body.setAttribute('data-theme', stored); } else { document.body.setAttribute('data-theme', 'light'); } updateIcon(); }
    function toggleLoginTheme() { const current = document.body.getAttribute('data-theme') || 'light'; const next = current === 'dark' ? 'light' : 'dark'; document.body.setAttribute('data-theme', next); localStorage.setItem('theme', next); updateIcon(); }
    function updateIcon() { const isDark = document.body.getAttribute('data-theme') === 'dark'; const icon = document.getElementById('theme-icon'); icon.className = isDark ? 'bi bi-moon-fill' : 'bi bi-sun-fill'; }
    initLoginTheme();
</script></body></html>{{ end }}`

const dashCSS = `<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.12/ace.js"></script>
<style>
:root { --bg-body: #0f172a; --bg-card: #1e293b; --text-main: #f8fafc; --text-muted: #ffffff; --border: #334155; --accent: #3b82f6; --accent-hover: #2563eb; --danger: #ef4444; --input-bg: #0f172a; --hover-bg: #334155; --term-bg: #000000; --nav-height: 0px; }
[data-theme="light"] { --bg-body: #f1f5f9; --bg-card: #ffffff; --text-main: #0f172a; --text-muted: #64748b; --border: #e2e8f0; --accent: #2563eb; --accent-hover: #1d4ed8; --danger: #ef4444; --input-bg: #f8fafc; --hover-bg: #f1f5f9; --term-bg: #ffffff; }
.text-muted { color: var(--text-muted) !important; }
body{background-color:var(--bg-body);color:var(--text-main);font-family:'Inter',sans-serif;height:100vh;height:100dvh;overflow:hidden;transition:background-color 0.3s,color 0.3s}
::-webkit-scrollbar{width:8px;height:8px} ::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px} ::-webkit-scrollbar-thumb:hover{background:var(--text-muted)}

/* 侧边栏基础样式 */
.sidebar{height:100vh;background:var(--bg-card);border-right:1px solid var(--border);min-width:240px;display:flex;flex-direction:column;transition:all 0.3s;z-index: 1000;}
.logo{padding:1.5rem;font-size:1.25rem;font-weight:700;color:var(--text-main);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.nav-link{color:var(--text-muted);padding:0.75rem 1.5rem;display:flex;align-items:center;gap:12px;font-weight:500;transition:all 0.2s; white-space: nowrap;}
.nav-link:hover{background:var(--hover-bg);color:var(--text-main)}
.nav-link.active{background:rgba(59,130,246,0.15);color:var(--accent);border-right:3px solid var(--accent)}
.nav-link i { font-size: 1.1rem; }
.logout-btn{margin-top:auto;border-top:1px solid var(--border);color:var(--danger)}
.logout-btn:hover{background:rgba(239,68,68,0.1);color:#f87171}

.content{flex:1;padding:2rem;overflow-y:auto;height: 100vh; height: 100dvh; padding-bottom: calc(2rem + var(--nav-height));}

/* --- 移动端适配 (核心修改) --- */
@media (max-width: 768px) {
    :root { --nav-height: 65px; }
    body { flex-direction: column; }
    .sidebar {
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        height: var(--nav-height);
        min-width: auto;
        border-right: none;
        border-top: 1px solid var(--border);
        flex-direction: row;
        justify-content: space-around;
        padding: 0;
        box-shadow: 0 -4px 20px rgba(0,0,0,0.1);
    }
    .logo { display: none; }
    .nav-link {
        flex-direction: column;
        gap: 4px;
        padding: 8px 0;
        font-size: 0.75rem;
        flex: 1;
        justify-content: center;
        border-right: none !important;
        border-top: 3px solid transparent;
    }
    .nav-link.active {
        border-right: none;
        border-top: 3px solid var(--accent);
        background: transparent;
    }
    .nav-link i { font-size: 1.4rem; margin-bottom: 2px; }
    .logout-btn { 
        margin-top: 0; 
        border-top: none; 
        border-left: 1px solid var(--border);
        max-width: 60px;
    }
    .content { padding: 1rem; padding-bottom: 120px; } /* 增加到底部 120px，防止内容被遮挡 */
    h3 { font-size: 1.25rem; }
    
    /* 调整卡片和列表在手机上的显示 */
    .section-header { margin-bottom: 1rem; }
    .card-item { padding: 1rem; }
    .server-item { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
    .server-info { width: 100%; }
    .server-actions { width: 100%; justify-content: flex-end; opacity: 1; margin-top: 0.5rem; border-top: 1px solid var(--border); padding-top: 0.5rem; }
    
    /* 模态框全屏化，提升体验 */
    .modal-dialog { margin: 0.5rem; }
    #termModal .modal-dialog { max-width: 100vw; margin: 0; height: 100vh; }
    #termModal .modal-content { height: 100%; border-radius: 0; }
    .term-container { height: calc(100vh - 110px); }
}

/* 通用样式 */
h3{font-size:1.5rem;font-weight:600;margin:0;color:var(--text-main)}
.section-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem}
.btn-primary{background:var(--accent);border:none;padding:0.5rem 1rem;font-weight:500;color:#fff}
.btn-primary:hover{background:var(--accent-hover);color:#fff}
.card-item{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:1.25rem;transition:all 0.2s}
.card-item:hover{transform:translateY(-2px);box-shadow:0 10px 15px -3px rgba(0,0,0,0.1);border-color:var(--text-muted)}
.card-title{font-size:1.1rem;font-weight:600;color:var(--text-main);margin-bottom:0.25rem}
.card-sub{color:var(--text-muted);font-size:0.875rem;margin-bottom:1rem;font-family:monospace}
.btn-action{background:var(--hover-bg);color:var(--text-main);border:1px solid var(--border);width:100%;margin-bottom:0.5rem;border-radius:6px;padding:0.4rem;font-size:0.9rem;transition:background 0.2s}
.btn-action:hover{background:var(--border)}
.btn-danger-soft{background:rgba(239,68,68,0.15);color:var(--danger);border:none}
.btn-danger-soft:hover{background:rgba(239,68,68,0.25);color:var(--danger)}
.table-custom{width:100%;border-collapse:collapse;color:var(--text-main)}
.table-custom th{text-align:left;padding:0.75rem;border-bottom:1px solid var(--border);color:var(--text-muted);font-weight:500}
.table-custom td{padding:0.75rem;border-bottom:1px solid var(--border)}
.table-custom tr:last-child td{border-bottom:none}
.table-custom tr:hover{background:var(--hover-bg)}
.list-group-item{background:var(--bg-card);border:1px solid var(--border);color:var(--text-main);margin-bottom:0.5rem;border-radius:6px!important;padding:1rem}
.hidden{display:none!important}
.modal-content{background:var(--bg-card);border:1px solid var(--border);color:var(--text-main)}
.modal-header,.modal-footer{border-color:var(--border)}
.form-control,.form-select{background:var(--input-bg);border:1px solid var(--border);color:var(--text-main)}
.form-control:focus,.form-select:focus{background:var(--input-bg);border-color:var(--accent);color:var(--text-main);box-shadow:none}
.btn-close{filter:var(--btn-close-filter)}
[data-theme="light"] .btn-close{filter:none} [data-theme="dark"] .btn-close{filter:invert(1)}
#termModal .modal-content{background:var(--term-bg)}
.term-container{background:var(--term-bg);height:calc(90vh - 45px)}
#editor{width:100%;height:65vh;border-radius:4px;border:1px solid var(--border)}
#modalEditor{z-index:1060}
.snippet-code{background:#000;color:#fff} [data-theme="light"] .snippet-code{background:#f1f5f9;color:#0f172a}
.btn-icon{width:32px;height:32px;padding:0;display:inline-flex;align-items:center;justify-content:center;border-radius:6px;transition:all 0.2s}
.icon-box{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.1rem}
.settings-card { padding: 1rem; }
.server-item { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 0.5rem; transition: all 0.2s; display: flex; align-items: center; justify-content: space-between; }
.server-item:hover { background: var(--hover-bg); border-color: var(--accent); transform: translateX(2px); }
.server-info { display: flex; align-items: center; gap: 1rem; }
.server-actions { display: flex; gap: 0.5rem; opacity: 0.7; transition: opacity 0.2s; }
.server-item:hover .server-actions { opacity: 1; }
.group-header { cursor: pointer; padding: 0.5rem 0; user-select: none; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
.group-header:hover { color: var(--accent); }
.group-icon { transition: transform 0.2s; }
.group-header[aria-expanded="false"] .group-icon { transform: rotate(-90deg); }
</style>`

const dashBody = `<div class="sidebar">
<div class="logo"><i class="bi bi-terminal-fill"></i>WebSSH</div>
<a href="#" onclick="showSection('servers',this)" class="nav-link active"><i class="bi bi-hdd-stack"></i> <span>服务器</span></a>
<a href="#" onclick="showSection('groups',this)" class="nav-link"><i class="bi bi-folder2"></i> <span>分组</span></a>
<a href="#" onclick="showSection('credentials',this)" class="nav-link"><i class="bi bi-key"></i> <span>凭证</span></a>
<a href="#" onclick="showSection('snippets',this)" class="nav-link"><i class="bi bi-code-slash"></i> <span>指令</span></a>
<a href="#" onclick="showSection('settings',this)" class="nav-link"><i class="bi bi-gear"></i> <span>设置</span></a>
<a href="/api/logout" class="nav-link logout-btn"><i class="bi bi-box-arrow-left"></i> <span>退出</span></a>
</div><div class="content"><div id="section-servers">
<div class="section-header"><h3>服务器列表</h3><button class="btn btn-primary" onclick="openModal('modalServer')"><i class="bi bi-plus-lg"></i> 新增服务器</button></div>
{{range $g := .Groups}}
<div class="group-section mb-4">
    <div class="group-header" data-bs-toggle="collapse" data-bs-target="#group-{{$g.ID}}" aria-expanded="true">
        <h6 class="mb-0 fw-bold text-uppercase"><i class="bi bi-folder2-open me-2"></i>{{$g.Name}}</h6>
        <i class="bi bi-chevron-down group-icon"></i>
    </div>
    <div id="group-{{$g.ID}}" class="collapse show"><div class="row">
        {{range $s := $.Servers}}{{if eq $s.GroupID $g.ID}}
        <div class="col-12" id="item-server-{{$s.ID}}"><div class="server-item">
            <div class="server-info"><div class="icon-box bg-primary bg-opacity-10 text-primary"><i class="bi bi-hdd-network"></i></div><div><div class="fw-bold">{{$s.Name}}</div><div class="small text-muted font-monospace">{{$s.IP}}:{{$s.Port}}</div></div></div>
            <div class="server-actions"><button class="btn btn-primary btn-sm" onclick="openTerminal('{{$s.ID}}','{{$s.Name}}')"><i class="bi bi-terminal me-1"></i>连接</button><button class="btn btn-action btn-sm btn-icon" onclick="editItem('server','{{$s.ID}}')" title="编辑"><i class="bi bi-pencil"></i></button><button class="btn btn-danger-soft btn-sm btn-icon" onclick="deleteItem('server','{{$s.ID}}')" title="删除"><i class="bi bi-trash"></i></button></div>
        </div></div>
        {{end}}{{end}}
    </div></div>
</div>
{{end}}
</div>
<div id="section-credentials" class="hidden"><div class="section-header"><h3>凭证管理</h3><button class="btn btn-primary" onclick="openModal('modalCred')"><i class="bi bi-plus-lg"></i> 新增凭证</button></div>
<div class="card-item p-0 overflow-hidden"><table class="table-custom"><thead><tr><th>备注名称</th><th>用户名</th><th width="150" class="text-end">操作</th></tr></thead><tbody id="cred-list">{{range .Credentials}}
<tr id="item-credential-{{.ID}}"><td><i class="bi bi-key-fill text-warning me-2"></i>{{.Name}}</td><td>{{.Username}}</td>
<td class="text-end"><div class="d-flex justify-content-end gap-2"><button class="btn btn-sm btn-action btn-icon" onclick="editItem('credential','{{.ID}}')"><i class="bi bi-pencil"></i></button><button class="btn btn-sm btn-danger-soft btn-icon" onclick="deleteItem('credential','{{.ID}}')"><i class="bi bi-trash"></i></button></div></td></tr>{{end}}</tbody></table></div></div>
<div id="section-groups" class="hidden"><div class="section-header"><h3>分组管理</h3><button class="btn btn-primary" onclick="openModal('modalGroup')"><i class="bi bi-plus-lg"></i> 新增分组</button></div>
<div class="row"><div class="col-md-6"><div id="group-list">{{range .Groups}}<div class="list-group-item d-flex justify-content-between align-items-center" id="item-group-{{.ID}}">
<span class="fw-bold"><i class="bi bi-folder-fill me-2 text-info"></i>{{.Name}}</span><div class="d-flex gap-2"><button class="btn btn-sm btn-action btn-icon" onclick="editItem('group','{{.ID}}')"><i class="bi bi-pencil"></i></button><button class="btn btn-sm btn-danger-soft btn-icon" onclick="deleteItem('group','{{.ID}}')"><i class="bi bi-trash"></i></button></div></div>{{end}}</div></div></div></div>
<div id="section-snippets" class="hidden"><div class="section-header"><h3>快捷指令</h3><button class="btn btn-primary" onclick="openModal('modalSnippet')"><i class="bi bi-plus-lg"></i> 新增指令</button></div>
<div class="row" id="snippet-list">{{range .Snippets}}<div class="col-md-6 mb-3" id="item-snippet-{{.ID}}"><div class="list-group-item">
<div class="d-flex justify-content-between mb-2"><span class="fw-bold text-primary">{{.Name}}</span><div class="d-flex gap-2"><button class="btn btn-sm btn-action btn-icon" onclick="editItem('snippet','{{.ID}}')"><i class="bi bi-pencil"></i></button><button class="btn btn-sm btn-danger-soft btn-icon" onclick="deleteItem('snippet','{{.ID}}')"><i class="bi bi-trash"></i></button></div></div>
<div class="snippet-code p-2 rounded small font-monospace cursor-pointer text-muted" onclick="copyText('{{.Command}}')" title="点击复制">{{.Command}}</div></div></div>{{end}}</div></div>
<div id="section-settings" class="hidden"><div class="section-header"><h3>系统设置</h3></div><div class="row g-3">
<div class="col-xl-3 col-lg-4 col-md-6"><div class="card-item h-100 settings-card"><div class="d-flex align-items-center mb-2"><div class="icon-box bg-primary bg-opacity-10 text-primary me-3"><i class="bi bi-palette"></i></div><h6 class="mb-0">界面风格</h6></div><p class="text-muted small mb-3">切换明亮/深色模式</p><button class="btn btn-action btn-sm w-100" onclick="toggleTheme()"><i class="bi bi-sun-fill me-2"></i>日/夜切换</button></div></div>
<div class="col-xl-3 col-lg-4 col-md-6"><div class="card-item h-100 settings-card"><div class="d-flex align-items-center mb-2"><div class="icon-box bg-warning bg-opacity-10 text-warning me-3"><i class="bi bi-shield-lock"></i></div><h6 class="mb-0">修改密码</h6></div><p class="text-muted small mb-2">更新管理员密码</p><div class="input-group input-group-sm"><input type="password" id="new-sys-pass" class="form-control" placeholder="新密码"><button class="btn btn-primary" onclick="updateSettings('pass')">更新</button></div></div></div>
<div class="col-xl-3 col-lg-4 col-md-6"><div class="card-item h-100 settings-card"><div class="d-flex align-items-center mb-2"><div class="icon-box bg-danger bg-opacity-10 text-danger me-3"><i class="bi bi-shield-check"></i></div><h6 class="mb-0">两步验证 (2FA)</h6></div>
{{if .Config.TOTPSecret}}
    <div class="alert alert-success py-1 small mb-2 text-center"><i class="bi bi-check-circle-fill me-1"></i>已启用</div>
    <button class="btn btn-action btn-danger-soft btn-sm w-100" onclick="disable2FA()">关闭 2FA</button>
{{else}}
    <p class="text-muted small mb-2">Google Authenticator</p>
    <button class="btn btn-primary btn-sm w-100" onclick="open2FAModal()">启用 2FA</button>
{{end}}
</div></div>
<div class="col-xl-3 col-lg-4 col-md-6"><div class="card-item h-100 settings-card"><div class="d-flex align-items-center mb-2"><div class="icon-box bg-success bg-opacity-10 text-success me-3"><i class="bi bi-database-gear"></i></div><h6 class="mb-0">数据维护</h6></div><div class="d-grid gap-2"><button class="btn btn-outline-secondary btn-action btn-sm" onclick="window.location.href='/api/backup'"><i class="bi bi-download me-2"></i>备份</button><div class="input-group input-group-sm"><input type="file" class="form-control" id="restore-file"><button class="btn btn-danger-soft" onclick="restoreData()">恢复</button></div></div></div></div>
<div class="col-xl-3 col-lg-4 col-md-6"><div class="card-item h-100 settings-card"><div class="d-flex align-items-center mb-2"><div class="icon-box bg-info bg-opacity-10 text-info me-3"><i class="bi bi-telegram"></i></div><h6 class="mb-0">TG 通知</h6></div><div class="mb-2"><input type="text" id="tg-token" class="form-control form-control-sm mb-1" placeholder="Bot Token" value="{{.Config.TGBotToken}}"><input type="text" id="tg-chat" class="form-control form-control-sm" placeholder="Chat ID" value="{{.Config.TGChatID}}"></div><div class="d-grid"><button class="btn btn-primary btn-sm" onclick="updateSettings('tg')">保存配置</button></div></div></div></div></div></div>`

const dashModals = `<div class="modal fade" id="modalConfirm" tabindex="-1"><div class="modal-dialog modal-sm modal-dialog-centered"><div class="modal-content"><div class="modal-header border-0 pb-0"><h5 class="modal-title text-danger">操作确认</h5></div><div class="modal-body text-center text-muted" id="confirmMessage">Are you sure?</div><div class="modal-footer border-0 justify-content-center pt-0"><button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">取消</button><button type="button" class="btn btn-danger btn-sm" onclick="confirmAction()">确认</button></div></div></div></div>
<div class="modal fade" id="modal2FA"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title">设置两步验证</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body text-center">
    <p class="text-muted small">请使用 Google Authenticator 扫描下方二维码</p>
    <div id="qrcode" class="d-flex justify-content-center my-3 bg-white p-2 rounded"></div>
    <div class="input-group mb-3"><span class="input-group-text">密钥</span><input type="text" id="2fa-secret" class="form-control font-monospace" readonly></div>
    <div class="mb-3"><label class="form-label">输入 6 位验证码以启用</label><input type="text" id="2fa-verify-code" class="form-control text-center" placeholder="000000" maxlength="6"></div>
</div>
<div class="modal-footer"><button class="btn btn-primary w-100" onclick="confirmEnable2FA()">验证并启用</button></div></div></div></div>
<div class="modal fade" id="modalServer"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="titleServer">新增服务器</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="formServer"><div class="mb-3"><label class="form-label">服务器名称</label><input type="text" id="srv-name" class="form-control" required></div><div class="row mb-3"><div class="col-8"><label class="form-label">IP 地址</label><input type="text" id="srv-ip" class="form-control" required></div><div class="col-4"><label class="form-label">端口</label><input type="number" id="srv-port" class="form-control" value="22" required></div></div><div class="mb-3"><div class="btn-group w-100"><input type="radio" class="btn-check" name="authType" id="authCustom" value="custom" checked onchange="toggleAuthFields()"><label class="btn btn-outline-secondary" for="authCustom">自定义账号</label><input type="radio" class="btn-check" name="authType" id="authSaved" value="saved" onchange="toggleAuthFields()"><label class="btn btn-outline-secondary" for="authSaved">选择凭证</label></div></div><div id="field-custom-auth"><div class="mb-2"><label class="form-label">用户名</label><input type="text" id="srv-user" class="form-control" value="root"></div><div class="mb-2"><label class="form-label">密码</label><input type="password" id="srv-pass" class="form-control"></div></div><div id="field-saved-auth" class="hidden"><div class="mb-2"><label class="form-label">选择凭证</label><select id="srv-cred" class="form-select"><option value="">请选择...</option>{{range .Credentials}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select></div></div><div class="mb-2"><label class="form-label">分组</label><select id="srv-group" class="form-select">{{range .Groups}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select></div></form></div><div class="modal-footer"><button class="btn btn-primary" onclick="submitServer()">保存</button></div></div></div></div>
<div class="modal fade" id="modalCred"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="titleCred">新增凭证</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="formCred"><label class="form-label">备注名称</label><input type="text" id="cred-name" class="form-control mb-3"><label class="form-label">用户名</label><input type="text" id="cred-user" class="form-control mb-3" value="root"><label class="form-label">密码 (可选)</label><input type="password" id="cred-pass" class="form-control mb-3"><label class="form-label">SSH 私钥 (可选)</label><textarea id="cred-key" class="form-control font-monospace" rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..."></textarea></form></div><div class="modal-footer"><button class="btn btn-primary" onclick="submitCred()">保存</button></div></div></div></div>
<div class="modal fade" id="modalGroup"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="titleGroup">新增分组</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><label class="form-label">分组名称</label><input type="text" id="group-name" class="form-control"></div><div class="modal-footer"><button class="btn btn-primary" onclick="submitGroup()">保存</button></div></div></div></div>
<div class="modal fade" id="modalSnippet"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="titleSnippet">新增指令</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><label class="form-label">标题</label><input type="text" id="snip-name" class="form-control mb-3"><label class="form-label">命令内容</label><textarea id="snip-cmd" class="form-control" rows="4"></textarea></div><div class="modal-footer"><button class="btn btn-primary" onclick="submitSnippet()">保存</button></div></div></div></div>
<div class="modal fade" id="termModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false"><div class="modal-dialog modal-xl" style="max-width: 95vw;"><div class="modal-content" style="height: 90vh;"><div class="modal-header border-bottom border-secondary py-2"><ul class="nav nav-pills me-auto" id="termTabs"><li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#tab-ssh" onclick="toggleQuickCmd(true)">Terminal</a></li><li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-sftp" onclick="loadSFTP();toggleQuickCmd(false)">SFTP</a></li></ul><div class="dropdown d-inline-block me-3" id="btn-quick-cmd"><button class="btn btn-sm btn-outline-light text-muted" type="button" data-bs-toggle="dropdown"><i class="bi bi-lightning-charge"></i></button><ul class="dropdown-menu dropdown-menu-end dropdown-menu-dark" id="quick-snippets-menu"></ul></div><span class="me-3 small text-muted" id="termTitle"></span><button type="button" class="btn-close" onclick="closeTerm()"></button></div><div class="modal-body p-0 tab-content"><div class="tab-pane fade show active h-100" id="tab-ssh"><div class="term-container h-100"><div id="terminal" style="height:100%"></div></div></div><div class="tab-pane fade h-100" id="tab-sftp"><div class="d-flex flex-column h-100" style="background:var(--bg-body)"><div class="p-2 border-bottom border-secondary d-flex align-items-center"><button class="btn btn-sm btn-outline-secondary me-2" onclick="loadSFTP('..')"><i class="bi bi-arrow-up"></i></button><input type="text" id="sftp-path" class="form-control form-control-sm me-2" readonly><button class="btn btn-sm btn-primary me-2" onclick="document.getElementById('upload-file').click()"><i class="bi bi-upload"></i></button><input type="file" id="upload-file" class="hidden" onchange="uploadFile(this)"><span id="sftp-status" class="text-muted small"></span></div><div class="flex-grow-1 overflow-auto"><table class="table-custom"><thead class="sticky-top"><tr><th>Name</th><th>Size</th><th>Time</th><th>Action</th></tr></thead><tbody id="sftp-list"></tbody></table></div></div></div></div></div></div></div>
<div class="modal fade" id="modalEditor" data-bs-backdrop="static" data-bs-keyboard="false"><div class="modal-dialog modal-xl"><div class="modal-content"><div class="modal-header"><h5 class="modal-title">编辑: <span id="editor-filename" class="text-info font-monospace"></span></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body p-0"><div id="editor"></div></div><div class="modal-footer border-top border-secondary"><span id="editor-status" class="me-auto text-muted small"></span><button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">关闭</button><button type="button" class="btn btn-primary btn-sm" onclick="saveFileContent()">保存 (Ctrl+S)</button></div></div></div></div>`

const dashScript = `<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script><script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script><script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script><script>
// --- Register PWA Service Worker ---
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').then(reg => {
        console.log('SW registered:', reg);
    }).catch(err => console.log('SW registration failed:', err));
}
// -----------------------------------

const uuid=()=>Math.random().toString(36).substr(2,9);let bsModals={},currentServerId="",editingId=null;const dbData={servers:{{.Servers|json}},groups:{{.Groups|json}},credentials:{{.Credentials|json}},snippets:{{.Snippets|json}}};
let pendingAction=null;const bsConfirm=new bootstrap.Modal(document.getElementById('modalConfirm'));
function showConfirm(msg,action){document.getElementById('confirmMessage').innerText=msg;pendingAction=action;bsConfirm.show();}
async function confirmAction(){if(pendingAction)await pendingAction();bsConfirm.hide();}
function showSection(id,btn){document.querySelectorAll('[id^="section-"]').forEach(el=>el.classList.add('hidden'));document.getElementById('section-'+id).classList.remove('hidden');if(btn){document.querySelectorAll('.sidebar a').forEach(a=>a.classList.remove('active'));btn.classList.add('active');}localStorage.setItem('activeSection',id);}
function initTheme(){const t=localStorage.getItem('theme')||'light';document.body.setAttribute('data-theme',t);if(aceEditor)aceEditor.setTheme(t==='dark'?'ace/theme/monokai':'ace/theme/chrome');}
function toggleTheme(){const c=document.body.getAttribute('data-theme');const n=c==='light'?'dark':'light';document.body.setAttribute('data-theme',n);localStorage.setItem('theme',n);if(aceEditor)aceEditor.setTheme(n==='dark'?'ace/theme/monokai':'ace/theme/chrome');}
window.addEventListener('load',()=>{initTheme();let last=localStorage.getItem('activeSection')||'servers';let btn=document.querySelector(".sidebar a[onclick*=\"'"+last+"'\"]");if(btn)btn.click();});
function findItem(type,id){if(type==='server')return dbData.servers.find(i=>i.id===id);if(type==='group')return dbData.groups.find(i=>i.id===id);if(type==='credential')return dbData.credentials.find(i=>i.id===id);if(type==='snippet')return dbData.snippets.find(i=>i.id===id);return null;}
function openModal(id,isEdit=false){if(!isEdit){editingId=null;document.querySelector('#'+id+' form')?.reset();if(id==='modalServer')document.getElementById('titleServer').innerText='新增服务器';if(id==='modalGroup')document.getElementById('titleGroup').innerText='新增分组';if(id==='modalCred')document.getElementById('titleCred').innerText='新增凭证';if(id==='modalSnippet')document.getElementById('titleSnippet').innerText='新增指令';}if(!bsModals[id])bsModals[id]=new bootstrap.Modal(document.getElementById(id));bsModals[id].show();}
function editItem(type,id){const item=findItem(type,id);if(!item)return;editingId=id;if(type==='server'){document.getElementById('titleServer').innerText='编辑服务器';document.getElementById('srv-name').value=item.name;document.getElementById('srv-ip').value=item.ip;document.getElementById('srv-port').value=item.port;document.getElementById('srv-group').value=item.group_id;if(item.credential_id){document.getElementById('authSaved').checked=true;document.getElementById('srv-cred').value=item.credential_id;}else{document.getElementById('authCustom').checked=true;document.getElementById('srv-user').value=item.username;document.getElementById('srv-pass').value=item.password;}toggleAuthFields();openModal('modalServer',true);}else if(type==='group'){document.getElementById('titleGroup').innerText='编辑分组';document.getElementById('group-name').value=item.name;openModal('modalGroup',true);}else if(type==='credential'){document.getElementById('titleCred').innerText='编辑凭证';document.getElementById('cred-name').value=item.name;document.getElementById('cred-user').value=item.username;document.getElementById('cred-pass').value=item.password;document.getElementById('cred-key').value=item.private_key||'';openModal('modalCred',true);}else if(type==='snippet'){document.getElementById('titleSnippet').innerText='编辑指令';document.getElementById('snip-name').value=item.name;document.getElementById('snip-cmd').value=item.command;openModal('modalSnippet',true);}}
async function api(payload){let res=await fetch('/api/save',{method:'POST',body:JSON.stringify(payload)});return res.ok;}
async function deleteItem(type,id){showConfirm("确认要删除吗？操作不可恢复。",async()=>{if(await api({type:type,action:'delete',delete_id:id}))location.reload();});}
function copyText(txt){navigator.clipboard.writeText(txt);alert('已复制到剪贴板');}
function toggleAuthFields(){const isCustom=document.getElementById('authCustom').checked;document.getElementById('field-custom-auth').classList.toggle('hidden',!isCustom);document.getElementById('field-saved-auth').classList.toggle('hidden',isCustom);}
async function submitServer(){let name=document.getElementById('srv-name').value,ip=document.getElementById('srv-ip').value,port=document.getElementById('srv-port').value,group=document.getElementById('srv-group').value;let isCustom=document.getElementById('authCustom').checked,credId="",user="",pass="";if(isCustom){user=document.getElementById('srv-user').value;pass=document.getElementById('srv-pass').value;if(!user)return alert('请填写用户名');}else{credId=document.getElementById('srv-cred').value;if(!credId)return alert('请选择凭证');}let action=editingId?"edit":"add";let id=editingId?editingId:uuid();if(await api({type:"server",action:action,server:{id:id,name:name,ip:ip,port:parseInt(port),group_id:group,credential_id:credId,username:user,password:pass}}))location.reload();}
async function submitCred(){let action=editingId?"edit":"add";let id=editingId?editingId:uuid();if(await api({type:"credential",action:action,credential:{id:id,name:document.getElementById('cred-name').value,username:document.getElementById('cred-user').value,password:document.getElementById('cred-pass').value,private_key:document.getElementById('cred-key').value}}))location.reload();}
async function submitGroup(){let action=editingId?"edit":"add";let id=editingId?editingId:uuid();if(await api({type:"group",action:action,group:{id:id,name:document.getElementById('group-name').value}}))location.reload();}
async function submitSnippet(){let action=editingId?"edit":"add";let id=editingId?editingId:uuid();if(await api({type:"snippet",action:action,snippet:{id:id,name:document.getElementById('snip-name').value,command:document.getElementById('snip-cmd').value}}))location.reload();}
async function updateSettings(type){let payload={type:"settings",action:"update"};if(type==='pass'){let p=document.getElementById('new-sys-pass').value;if(!p)return;payload.new_password=p;}else if(type==='tg'){payload.tg_bot_token=document.getElementById('tg-token').value;payload.tg_chat_id=document.getElementById('tg-chat').value;}if(await api(payload)){alert('设置已保存');location.reload();}}
async function restoreData(){let fileInput=document.getElementById('restore-file');if(fileInput.files.length===0)return alert('请选择备份文件');showConfirm("确定恢复数据？这将覆盖当前所有配置！",async()=>{let fd=new FormData();fd.append("backup_file",fileInput.files[0]);let res=await fetch('/api/restore',{method:'POST',body:fd});if(res.ok){alert('恢复成功，请重新登录');location.reload();}else{alert('恢复失败');}});}
let term,socket,currentPath=".";const termModal=new bootstrap.Modal(document.getElementById('termModal'));
function toggleQuickCmd(show){const btn=document.getElementById('btn-quick-cmd');if(show)btn.classList.remove('d-none');else btn.classList.add('d-none');}
function openTerminal(id,name){currentServerId=id;document.getElementById('termTitle').innerText=name;toggleQuickCmd(true);document.querySelector('#termTabs a[href="#tab-ssh"]').click();termModal.show();const menu=document.getElementById('quick-snippets-menu');menu.innerHTML='';if(dbData.snippets&&dbData.snippets.length===0){menu.innerHTML='<li><span class="dropdown-item text-muted">暂无快捷指令</span></li>';}else if(dbData.snippets){dbData.snippets.forEach(s=>{let li=document.createElement('li');let a=document.createElement('a');a.className='dropdown-item cursor-pointer';a.innerHTML='<strong>'+s.name+'</strong><br><small class="text-muted" style="font-size:0.7em">'+s.command.substring(0,25)+'...</small>';a.onclick=function(){sendCommand(s.command);};li.appendChild(a);menu.appendChild(li);});}setTimeout(()=>{const c=document.getElementById('terminal');c.innerHTML='';const isLight=document.body.getAttribute('data-theme')==='light';const themeObj=isLight?{background:'#ffffff',foreground:'#000000',cursor:'#000000',selection:'rgba(0,0,0,0.3)'}:{background:'#000000',foreground:'#ffffff'};term=new Terminal({cursorBlink:true,fontSize:14,fontFamily:'Menlo, Monaco, "Courier New", monospace',theme:themeObj});const f=new FitAddon.FitAddon();term.loadAddon(f);term.open(c);f.fit();socket=new WebSocket('ws://'+location.host+'/ws/ssh?id='+id+'&cols='+term.cols+'&rows='+term.rows);socket.onmessage=(ev)=>{if(typeof ev.data==='string')term.write(ev.data);else{let r=new FileReader();r.onload=()=>term.write(r.result);r.readAsText(ev.data);}};term.onData(d=>socket.send(d));socket.onclose=()=>term.write('\r\n\x1b[31mConnection Closed.\x1b[0m\r\n');window.onresize=()=>f.fit();},500);}
function closeTerm(){if(socket)socket.close();if(term)term.dispose();termModal.hide();}
function sendCommand(cmd){if(socket&&socket.readyState===WebSocket.OPEN){socket.send(cmd+"\n");term.focus();}}
async function loadSFTP(path){if(!path)path=currentPath;if(path==='..'){let p=currentPath.split('/');p.pop();path=p.join('/')||'/';}document.getElementById('sftp-status').innerText="加载中...";try{let res=await fetch('/api/sftp/list?id='+currentServerId+'&path='+encodeURIComponent(path));let data=await res.json();currentPath=data.path;document.getElementById('sftp-path').value=currentPath;let tbody=document.getElementById('sftp-list');tbody.innerHTML='';data.files.forEach(f=>{let tr=document.createElement('tr');let icon=f.is_dir?'<i class="bi bi-folder-fill text-warning"></i>':'<i class="bi bi-file-earmark-text text-secondary"></i>';let clickFn=f.is_dir?"loadSFTP('"+currentPath+"/"+f.name+"')":"";let nameLink='<span class="cursor-pointer text-primary" onclick="'+clickFn+'">'+f.name+'</span>';let actions='';if(!f.is_dir){actions+='<button class="btn btn-sm py-0 me-2 text-info" title="下载" onclick="window.open(\'/api/sftp/download?id='+currentServerId+'&path='+encodeURIComponent(currentPath+'/'+f.name)+'\')"><i class="bi bi-download"></i></button>';actions+='<button class="btn btn-sm py-0 text-warning" title="编辑" onclick="openEditor(\''+f.name+'\')"><i class="bi bi-pencil-square"></i></button>';}tr.innerHTML='<td>'+icon+' '+nameLink+'</td><td>'+(f.is_dir?'-':(f.size/1024).toFixed(1)+' KB')+'</td><td>'+f.mod_time+'</td><td>'+actions+'</td>';tbody.appendChild(tr);});document.getElementById('sftp-status').innerText="";}catch(e){document.getElementById('sftp-status').innerText="Error: "+e;}}
async function uploadFile(input){if(input.files.length===0)return;let fd=new FormData();fd.append("file",input.files[0]);fd.append("id",currentServerId);fd.append("path",currentPath);document.getElementById('sftp-status').innerText="上传中...";let res=await fetch('/api/sftp/upload',{method:'POST',body:fd});if(res.ok){loadSFTP();alert('上传成功');}else{alert('上传失败');}input.value='';}
let aceEditor,editingFilePath="";const modalEditor=new bootstrap.Modal(document.getElementById('modalEditor'));
function initEditor(){if(!aceEditor){aceEditor=ace.edit("editor");const t=document.body.getAttribute('data-theme')||'dark';aceEditor.setTheme(t==='dark'?'ace/theme/monokai':'ace/theme/chrome');aceEditor.session.setMode("ace/mode/text");aceEditor.setFontSize(14);aceEditor.commands.addCommand({name:'save',bindKey:{win:'Ctrl-S',mac:'Command-S'},exec:function(){saveFileContent();}});}}
async function openEditor(fileName){initEditor();editingFilePath=currentPath+"/"+fileName;document.getElementById('editor-filename').innerText=fileName;document.getElementById('editor-status').innerText="读取中...";modalEditor.show();let ext=fileName.split('.').pop();let mode="ace/mode/text";const modeMap={'js':'javascript','json':'json','html':'html','css':'css','go':'golang','py':'python','sh':'sh','yaml':'yaml','yml':'yaml','md':'markdown','sql':'sql','xml':'xml','dockerfile':'dockerfile'};if(modeMap[ext])mode="ace/mode/"+modeMap[ext];aceEditor.session.setMode(mode);try{let res=await fetch('/api/sftp/cat?id='+currentServerId+'&path='+encodeURIComponent(editingFilePath));if(!res.ok)throw new Error("Read failed");let content=await res.text();aceEditor.setValue(content,-1);document.getElementById('editor-status').innerText="";}catch(e){aceEditor.setValue("");document.getElementById('editor-status').innerText="读取失败: "+e;}}
async function saveFileContent(){if(!editingFilePath)return;let content=aceEditor.getValue();document.getElementById('editor-status').innerText="保存中...";let fd=new FormData();fd.append("id",currentServerId);fd.append("path",editingFilePath);fd.append("content",content);try{let res=await fetch('/api/sftp/save',{method:'POST',body:fd});if(res.ok){document.getElementById('editor-status').innerText="已保存 "+new Date().toLocaleTimeString();document.getElementById('editor-status').classList.add('text-success');setTimeout(()=>document.getElementById('editor-status').classList.remove('text-success'),2000);}else{alert("保存失败");document.getElementById('editor-status').innerText="保存失败";}}catch(e){alert("错误: "+e);}}

// 2FA Functions
const modal2FA = new bootstrap.Modal(document.getElementById('modal2FA'));
let current2FASecret = "";
async function open2FAModal() {
    let res = await fetch('/api/2fa/gen');
    let data = await res.json();
    current2FASecret = data.secret;
    document.getElementById('2fa-secret').value = data.secret;
    document.getElementById('qrcode').innerHTML = "";
    new QRCode(document.getElementById("qrcode"), {text: data.url, width: 128, height: 128});
    document.getElementById('2fa-verify-code').value = "";
    modal2FA.show();
}
async function confirmEnable2FA() {
    let code = document.getElementById('2fa-verify-code').value;
    if(!code || code.length !== 6) return alert("请输入6位验证码");
    let fd = new FormData();
    fd.append("secret", current2FASecret);
    fd.append("code", code);
    let res = await fetch('/api/2fa/enable', {method:'POST', body:fd});
    if(res.ok) { alert("2FA 已成功启用！下次登录需要输入验证码。"); location.reload(); } else { alert("验证失败，请检查验证码是否正确"); }
}
function disable2FA() {
    showConfirm("确定要关闭两步验证吗？账户安全性将降低。", async () => {
        let res = await fetch('/api/2fa/disable', {method:'POST'});
        if(res.ok) location.reload();
    });
}
</script>`
