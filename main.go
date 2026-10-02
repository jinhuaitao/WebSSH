package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
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
	Sessions    map[string]time.Time `json:"sessions"`
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

// --- 版本与在线更新 ---

// version 版本号来源：每次发版前把这里的默认值改成与 Release tag 一致（如 CI 用 ldflags 注入则以 CI 为准）
var version = "0.0.32"

const ghRepo = "jinhuaitao/WebSSH"

// ghProxy 返回 GitHub 加速前缀，可用环境变量 WEBSSH_GH_PROXY 覆盖（设为空串则直连）
func ghProxy() string {
	if p, ok := os.LookupEnv("WEBSSH_GH_PROXY"); ok {
		return p
	}
	return "https://jht126.eu.org/"
}

// isDocker 判断是否运行在容器内；用 bind mount 挂载二进制时可设 WEBSSH_FORCE_SELFUPDATE=1 强制允许在线更新
func isDocker() bool {
	if os.Getenv("WEBSSH_FORCE_SELFUPDATE") == "1" {
		return false
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

type releaseInfo struct {
	TagName string `json:"tag_name"`
}

func fetchLatestVersion() (string, error) {
	direct := "https://api.github.com/repos/" + ghRepo + "/releases/latest"
	candidates := []string{direct}
	if p := ghProxy(); p != "" {
		candidates = append([]string{p + direct}, candidates...)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	for _, u := range candidates {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "webssh-"+version)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("版本接口返回 %d", resp.StatusCode)
			continue
		}
		var info releaseInfo
		if err := json.Unmarshal(body, &info); err != nil {
			lastErr = err
			continue
		}
		if info.TagName == "" {
			lastErr = fmt.Errorf("未获取到版本信息")
			continue
		}
		return strings.TrimPrefix(info.TagName, "v"), nil
	}
	return "", lastErr
}

// downloadAndReplace 下载最新版本的 Linux 二进制并原子替换当前程序
func downloadAndReplace() (int64, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("在线自更新仅支持 Linux")
	}
	if isDocker() {
		return 0, fmt.Errorf("Docker 环境请通过拉取新镜像升级: docker pull jhtone/webssh && docker compose up -d")
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
	default:
		return 0, fmt.Errorf("不支持的 CPU 架构: %s", runtime.GOARCH)
	}
	dlURL := ghProxy() + "https://github.com/" + ghRepo + "/releases/latest/download/webssh-linux-" + runtime.GOARCH
	req, err := http.NewRequest("GET", dlURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "webssh-"+version)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("下载地址返回 %d，请检查网络或 GH_PROXY 配置", resp.StatusCode)
	}
	exPath, err := os.Executable()
	if err != nil {
		return 0, err
	}
	tmp := exPath + ".update.tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return 0, fmt.Errorf("无法写入临时文件: %v", err)
	}
	n, err := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("下载中断: %v", err)
	}
	// 静态 Go 二进制通常 10MB+，过小基本可判定为下载到了错误页面
	if n < 1<<20 {
		os.Remove(tmp)
		return 0, fmt.Errorf("下载内容异常（仅 %d 字节），已取消更新", n)
	}
	if err := os.Rename(tmp, exPath); err != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("替换二进制失败（需要 root 权限？）: %v", err)
	}
	log.Printf("二进制已更新: %s (%d bytes)", exPath, n)
	return n, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// restartAfterUpdate 更新落地后让新版本接管进程（兼容 Debian/systemd 与 Alpine/OpenRC 及手动运行）:
//   - systemd: 直接退出，由 Restart=always 拉起，避免双实例竞争端口
//   - OpenRC/手动: 派生 setsid 后台进程，等旧进程退出、端口释放后 exec 新二进制
func restartAfterUpdate() {
	if os.Getenv("INVOCATION_ID") != "" {
		log.Println("更新完成: 退出旧进程，由 systemd 拉起新版本")
		os.Exit(0)
	}
	exPath, err := os.Executable()
	if err != nil {
		log.Printf("更新完成但无法定位可执行文件: %v，请手动重启服务", err)
		os.Exit(0)
	}
	cmdline := "sleep 2; exec " + shellQuote(exPath)
	for _, a := range os.Args[1:] {
		cmdline += " " + shellQuote(a)
	}
	var cmd *exec.Cmd
	if sp, lookErr := exec.LookPath("setsid"); lookErr == nil {
		cmd = exec.Command(sp, "sh", "-c", cmdline)
	} else {
		cmd = exec.Command("sh", "-c", cmdline)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("更新完成但后台拉起新进程失败: %v，请手动重启服务", err)
		os.Exit(1)
	}
	log.Println("更新完成: 已在后台拉起新版本进程，旧进程退出")
	os.Exit(0)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// versionLessThan 按数字段逐段比较语义化版本 (如 v1.2.10 > v1.2.9)
func versionLessThan(a, b string) bool {
	parse := func(v string) []int {
		v = strings.TrimPrefix(strings.TrimSpace(v), "v")
		parts := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
		nums := make([]int, len(parts))
		for i, p := range parts {
			nums[i], _ = strconv.Atoi(p)
		}
		return nums
	}
	na, nb := parse(a), parse(b)
	for i := 0; i < len(na) || i < len(nb); i++ {
		var x, y int
		if i < len(na) {
			x = na[i]
		}
		if i < len(nb) {
			y = nb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"version": version})
}

func handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	latest, err := fetchLatestVersion()
	if err != nil {
		http.Error(w, "检查更新失败: "+err.Error(), 502)
		return
	}
	writeJSON(w, map[string]interface{}{
		"current":    version,
		"latest":     latest,
		"has_update": versionLessThan(version, latest),
		"docker":     isDocker(),
	})
}

func handleUpdateRun(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "405", 405)
		return
	}
	n, err := downloadAndReplace()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "ok", "size": n})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	// 稍等响应发出，然后自动重启接管新版本
	go func() {
		time.Sleep(500 * time.Millisecond)
		restartAfterUpdate()
	}()
}

// --- 工具函数 ---

// generateRandomToken 生成安全的随机 Session ID
func generateRandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// 如果随机数生成失败，回退到时间戳（极低概率）
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

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

	// 启动时清理过期 Session
	now := time.Now()
	dirty := false
	for token, expiry := range db.Sessions {
		if now.After(expiry) {
			delete(db.Sessions, token)
			dirty = true
		}
	}
	if dirty {
		log.Println("已清理过期会话")
		data, _ := json.MarshalIndent(db, "", "  ")
		if err := os.WriteFile(dbFile, data, 0644); err != nil {
			log.Printf("写入数据文件失败: %v", err)
		}
	}
}

// saveData 原子写入：先写临时文件再 rename，避免进程崩溃/断电导致 data.json 损坏
func saveData() {
	dbLock.Lock()
	defer dbLock.Unlock()
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		log.Printf("序列化数据失败: %v", err)
		return
	}
	tmp := dbFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("写入数据文件失败: %v", err)
		return
	}
	if err := os.Rename(tmp, dbFile); err != nil {
		log.Printf("数据文件重命名失败: %v", err)
		os.Remove(tmp)
	}
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

	targetAddr := net.JoinHostPort(srv.IP, strconv.Itoa(srv.Port))
	return ssh.Dial("tcp", targetAddr, config)
}

// --- 主程序 ---

func main() {
	port := flag.Int("port", 8080, "监听端口")
	showVer := flag.Bool("v", false, "打印版本号并退出")
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}
	if p := os.Getenv("WEBSSH_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			*port = v
		}
	}

	loadData()
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/setup", handleSetup)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/save", handleSaveData)
	http.HandleFunc("/api/backup", handleBackup)
	http.HandleFunc("/api/restore", handleRestore)

	http.HandleFunc("/api/version", handleVersion)
	http.HandleFunc("/api/update/check", handleUpdateCheck)
	http.HandleFunc("/api/update/run", handleUpdateRun)

	http.HandleFunc("/manifest.json", handleManifest)
	http.HandleFunc("/sw.js", handleServiceWorker)

	http.HandleFunc("/api/2fa/gen", handle2FAGenerate)
	http.HandleFunc("/api/2fa/enable", handle2FAEnable)
	http.HandleFunc("/api/2fa/disable", handle2FADisable)

	http.HandleFunc("/ws/ssh", handleWebsocketSSH)
	http.HandleFunc("/api/sftp/list", handleSFTPList)
	http.HandleFunc("/api/sftp/download", handleSFTPDownload)
	http.HandleFunc("/api/sftp/upload", handleSFTPUpload)
	http.HandleFunc("/api/sftp/delete", handleSFTPDelete)
	http.HandleFunc("/api/sftp/cat", handleSFTPCat)
	http.HandleFunc("/api/sftp/save", handleSFTPSave)

	fmt.Printf("WebSSH %s 启动在 http://localhost:%d\n", version, *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
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
	dbLock.RLock()
	isSetup := db.Config.IsSetup
	dbLock.RUnlock()
	if isSetup {
		http.Error(w, "系统已初始化，如需修改密码请在设置页操作", 403)
		return
	}
	user, pass := r.FormValue("username"), r.FormValue("password")
	if user == "" || pass == "" {
		http.Error(w, "账号和密码不能为空", 400)
		return
	}
	dbLock.Lock()
	db.Config.AdminUser = user
	db.Config.AdminPass = pass
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

	token := generateRandomToken()

	const sessionDuration = 30 * 24 * time.Hour
	expiry := time.Now().Add(sessionDuration)

	dbLock.Lock()
	db.Sessions[token] = expiry
	dbLock.Unlock()

	saveData()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
	})

	sendTelegramNotification(fmt.Sprintf("🔔 WebSSH 登录通知\n用户: %s\n方式: %s\nIP: %s\n时间: %s", user, loginType, r.RemoteAddr, time.Now().Format("2006-01-02 15:04:05")))
	http.Redirect(w, r, "/", 302)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		dbLock.Lock()
		delete(db.Sessions, cookie.Value)
		dbLock.Unlock()
		saveData()
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
			if req.Server.GroupID == "" {
				var defaultGroupID string
				for _, g := range db.Groups {
					if g.Name == "默认分组" {
						defaultGroupID = g.ID
						break
					}
				}
				if defaultGroupID == "" {
					defaultGroupID = fmt.Sprintf("%d", time.Now().UnixNano())
					newGroup := Group{
						ID:   defaultGroupID,
						Name: "默认分组",
					}
					db.Groups = append(db.Groups, newGroup)
				}
				req.Server.GroupID = defaultGroupID
			}
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

	// 保留 xterm-256color 支持颜色高亮
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		return
	}
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()
	// gorilla/websocket 不允许并发写，stdout/stderr 两个拷贝协程需共享同一把锁
	wsMu := &sync.Mutex{}
	go io.Copy(wsWriter{ws, wsMu}, stdout)
	go io.Copy(wsWriter{ws, wsMu}, stderr)
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

type wsWriter struct {
	*websocket.Conn
	mu *sync.Mutex
}

func (w wsWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
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

	var dirs []FileInfo
	var regularFiles []FileInfo

	for _, f := range files {
		item := FileInfo{
			Name:    f.Name(),
			Size:    f.Size(),
			ModTime: f.ModTime().Format("2006-01-02 15:04"),
			IsDir:   f.IsDir(),
		}

		if f.IsDir() {
			dirs = append(dirs, item)
		} else {
			regularFiles = append(regularFiles, item)
		}
	}

	sort.Slice(dirs, func(i, j int) bool {
		return strings.ToLower(dirs[i].Name) < strings.ToLower(dirs[j].Name)
	})
	sort.Slice(regularFiles, func(i, j int) bool {
		return strings.ToLower(regularFiles[i].Name) < strings.ToLower(regularFiles[j].Name)
	})

	fileList = append(fileList, dirs...)
	fileList = append(fileList, regularFiles...)

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

func handleSFTPDelete(w http.ResponseWriter, r *http.Request) {
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

	err = sftpClient.Remove(path)
	if err != nil {
		err = sftpClient.RemoveDirectory(path)
	}

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
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
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#05070d;--card:rgba(17,24,39,.72);--text:#e8eef7;--muted:#7c8ba1;--line:rgba(148,163,184,.14);--accent:#10b981;--accent-2:#06b6d4;--input-bg:rgba(5,7,13,.6);--input-line:rgba(148,163,184,.22);--glow:rgba(16,185,129,.35)}
[data-theme="light"]{--bg:#eef2f4;--card:rgba(255,255,255,.85);--text:#0b1b2b;--muted:#5b6b7c;--line:rgba(15,32,48,.08);--accent:#059669;--accent-2:#0891b2;--input-bg:#ffffff;--input-line:rgba(15,32,48,.14);--glow:rgba(5,150,105,.25)}
*{box-sizing:border-box}
body{margin:0;height:100vh;height:100dvh;display:flex;align-items:center;justify-content:center;font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);overflow:hidden;position:relative;transition:background .3s,color .3s}
.bg-grid{position:fixed;inset:0;background-image:linear-gradient(rgba(148,163,184,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(148,163,184,.05) 1px,transparent 1px);background-size:44px 44px;mask-image:radial-gradient(ellipse 80% 70% at 50% 40%,#000 30%,transparent 75%);-webkit-mask-image:radial-gradient(ellipse 80% 70% at 50% 40%,#000 30%,transparent 75%);pointer-events:none}
.orb{position:fixed;border-radius:50%;filter:blur(90px);opacity:.5;pointer-events:none;animation:drift 16s ease-in-out infinite alternate}
.orb-a{width:46vw;height:46vw;max-width:560px;max-height:560px;left:-12vw;top:-16vw;background:radial-gradient(circle,var(--accent),transparent 65%)}
.orb-b{width:40vw;height:40vw;max-width:520px;max-height:520px;right:-10vw;bottom:-14vw;background:radial-gradient(circle,var(--accent-2),transparent 65%);animation-delay:-8s}
@keyframes drift{from{transform:translate(0,0) scale(1)}to{transform:translate(5vw,4vh) scale(1.12)}}
.theme-toggle{position:absolute;top:1.4rem;right:1.6rem;cursor:pointer;color:var(--muted);font-size:1.2rem;z-index:10;transition:color .2s}
.theme-toggle:hover{color:var(--accent)}
.login-card{position:relative;z-index:5;width:100%;max-width:420px;margin:1rem;padding:2.6rem 2.4rem;background:var(--card);border:1px solid var(--line);border-radius:22px;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);box-shadow:0 40px 90px -30px rgba(0,0,0,.55),0 0 0 1px rgba(255,255,255,.03) inset;animation:fadeUp .55s cubic-bezier(.2,.8,.3,1)}
.login-card::before{content:"";position:absolute;inset:0 0 auto;height:3px;border-radius:22px 22px 0 0;background:linear-gradient(90deg,var(--accent),var(--accent-2))}
@keyframes fadeUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
.brand{display:flex;flex-direction:column;align-items:center;gap:.9rem;margin-bottom:2.1rem;text-align:center}
.brand-mark{width:58px;height:58px;border-radius:17px;background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;display:flex;align-items:center;justify-content:center;font-size:1.7rem;box-shadow:0 14px 34px -12px var(--glow)}
.brand h1{margin:0;font-size:1.45rem;font-weight:800;letter-spacing:-.02em}
.brand p{margin:.15rem 0 0;font-size:.82rem;color:var(--muted)}
.input-group{position:relative;margin-bottom:1.15rem}
.input-icon{position:absolute;left:1.05rem;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none;transition:color .2s;z-index:5}
.form-control{width:100%;background:var(--input-bg);border:1px solid var(--input-line);color:var(--text);padding:.95rem 1rem .95rem 3rem;border-radius:12px;font-size:.95rem;transition:border-color .2s,box-shadow .2s}
.form-control:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px var(--glow)}
.form-control:focus ~ .input-icon{color:var(--accent)}
.btn-login{width:100%;border:none;cursor:pointer;color:#fff;font-weight:700;font-size:1rem;padding:.95rem;border-radius:12px;margin-top:.4rem;background:linear-gradient(135deg,var(--accent),var(--accent-2));box-shadow:0 14px 30px -12px var(--glow);transition:transform .15s,filter .2s}
.btn-login:hover{transform:translateY(-1px);filter:brightness(1.06)}
.btn-login:active{transform:translateY(0)}
.footer{text-align:center;margin-top:1.9rem;color:var(--muted);font-size:.75rem;letter-spacing:.14em;text-transform:uppercase}
</style></head><body data-theme="light">
<div class="bg-grid"></div><div class="orb orb-a"></div><div class="orb orb-b"></div>
<div class="theme-toggle" onclick="toggleLoginTheme()"><i class="bi bi-sun-fill" id="theme-icon"></i></div>
<div class="login-card"><div class="brand"><div class="brand-mark"><i class="bi bi-terminal-fill"></i></div><div><h1>初始化 WebSSH</h1><p>设置你的管理员账号</p></div></div>
<form action="/api/setup" method="post"><div class="input-group"><input type="text" name="username" class="form-control" placeholder="管理员账号" required autocomplete="off"><i class="bi bi-person input-icon"></i></div>
<div class="input-group"><input type="password" name="password" class="form-control" placeholder="管理员密码" required><i class="bi bi-shield-lock input-icon"></i></div>
<button class="btn-login">完成初始化</button></form><div class="footer">Initial Setup</div></div>
<script>
    function initLoginTheme() { const stored = localStorage.getItem('theme'); if (stored) { document.body.setAttribute('data-theme', stored); } else { document.body.setAttribute('data-theme', 'light'); } updateIcon(); }
    function toggleLoginTheme() { const current = document.body.getAttribute('data-theme') || 'light'; const next = current === 'dark' ? 'light' : 'dark'; document.body.setAttribute('data-theme', next); localStorage.setItem('theme', next); updateIcon(); }
    function updateIcon() { const isDark = document.body.getAttribute('data-theme') === 'dark'; const icon = document.getElementById('theme-icon'); icon.className = isDark ? 'bi bi-moon-fill' : 'bi bi-sun-fill'; }
    initLoginTheme();
</script></body></html>{{ end }}`
const tplLogin = `{{ define "login" }}<!DOCTYPE html><html><head><title>Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#05070d;--card:rgba(17,24,39,.72);--text:#e8eef7;--muted:#7c8ba1;--line:rgba(148,163,184,.14);--accent:#10b981;--accent-2:#06b6d4;--input-bg:rgba(5,7,13,.6);--input-line:rgba(148,163,184,.22);--glow:rgba(16,185,129,.35);--danger:#f87171}
[data-theme="light"]{--bg:#eef2f4;--card:rgba(255,255,255,.85);--text:#0b1b2b;--muted:#5b6b7c;--line:rgba(15,32,48,.08);--accent:#059669;--accent-2:#0891b2;--input-bg:#ffffff;--input-line:rgba(15,32,48,.14);--glow:rgba(5,150,105,.25);--danger:#dc2626}
*{box-sizing:border-box}
body{margin:0;height:100vh;height:100dvh;display:flex;align-items:center;justify-content:center;font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);overflow:hidden;position:relative;transition:background .3s,color .3s}
.bg-grid{position:fixed;inset:0;background-image:linear-gradient(rgba(148,163,184,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(148,163,184,.05) 1px,transparent 1px);background-size:44px 44px;mask-image:radial-gradient(ellipse 80% 70% at 50% 40%,#000 30%,transparent 75%);-webkit-mask-image:radial-gradient(ellipse 80% 70% at 50% 40%,#000 30%,transparent 75%);pointer-events:none}
.orb{position:fixed;border-radius:50%;filter:blur(90px);opacity:.5;pointer-events:none;animation:drift 16s ease-in-out infinite alternate}
.orb-a{width:46vw;height:46vw;max-width:560px;max-height:560px;left:-12vw;top:-16vw;background:radial-gradient(circle,var(--accent),transparent 65%)}
.orb-b{width:40vw;height:40vw;max-width:520px;max-height:520px;right:-10vw;bottom:-14vw;background:radial-gradient(circle,var(--accent-2),transparent 65%);animation-delay:-8s}
@keyframes drift{from{transform:translate(0,0) scale(1)}to{transform:translate(5vw,4vh) scale(1.12)}}
.theme-toggle{position:absolute;top:1.4rem;right:1.6rem;cursor:pointer;color:var(--muted);font-size:1.2rem;z-index:10;transition:color .2s}
.theme-toggle:hover{color:var(--accent)}
.login-card{position:relative;z-index:5;width:100%;max-width:420px;margin:1rem;padding:2.6rem 2.4rem;background:var(--card);border:1px solid var(--line);border-radius:22px;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);box-shadow:0 40px 90px -30px rgba(0,0,0,.55),0 0 0 1px rgba(255,255,255,.03) inset;animation:fadeUp .55s cubic-bezier(.2,.8,.3,1)}
.login-card::before{content:"";position:absolute;inset:0 0 auto;height:3px;border-radius:22px 22px 0 0;background:linear-gradient(90deg,var(--accent),var(--accent-2))}
@keyframes fadeUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
.brand{display:flex;flex-direction:column;align-items:center;gap:.9rem;margin-bottom:2.1rem;text-align:center}
.brand-mark{width:58px;height:58px;border-radius:17px;background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;display:flex;align-items:center;justify-content:center;font-size:1.7rem;box-shadow:0 14px 34px -12px var(--glow)}
.brand h1{margin:0;font-size:1.45rem;font-weight:800;letter-spacing:-.02em}
.brand p{margin:.15rem 0 0;font-size:.82rem;color:var(--muted)}
.input-group{position:relative;margin-bottom:1.15rem}
.input-icon{position:absolute;left:1.05rem;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none;transition:color .2s;z-index:5}
.form-control{width:100%;background:var(--input-bg);border:1px solid var(--input-line);color:var(--text);padding:.95rem 1rem .95rem 3rem;border-radius:12px;font-size:.95rem;transition:border-color .2s,box-shadow .2s}
.form-control:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px var(--glow)}
.form-control:focus ~ .input-icon{color:var(--accent)}
.btn-login{width:100%;border:none;cursor:pointer;color:#fff;font-weight:700;font-size:1rem;padding:.95rem;border-radius:12px;margin-top:.4rem;background:linear-gradient(135deg,var(--accent),var(--accent-2));box-shadow:0 14px 30px -12px var(--glow);transition:transform .15s,filter .2s}
.btn-login:hover{transform:translateY(-1px);filter:brightness(1.06)}
.btn-login:active{transform:translateY(0)}
.footer{text-align:center;margin-top:1.9rem;color:var(--muted);font-size:.75rem;letter-spacing:.14em;text-transform:uppercase}
.alert-box{display:none;color:var(--danger);background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.25);border-radius:10px;padding:.6rem .9rem;font-size:.85rem;text-align:center;margin-bottom:1.15rem}
</style></head><body data-theme="light">
<div class="bg-grid"></div><div class="orb orb-a"></div><div class="orb orb-b"></div>
<div class="theme-toggle" onclick="toggleLoginTheme()"><i class="bi bi-sun-fill" id="theme-icon"></i></div>
<div class="login-card"><div class="brand"><div class="brand-mark"><i class="bi bi-terminal-fill"></i></div><div><h1>WebSSH</h1><p>登录后开始管理你的服务器</p></div></div>
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
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.12/ace.js"></script>
<style>
:root{--bg-body:#070b12;--bg-card:#0e1521;--bg-elev:#151f2e;--bg-hover:#182335;--text-main:#e8eef7;--text-muted:#7c8ba1;--border:rgba(148,163,184,.13);--border-strong:rgba(148,163,184,.22);--accent:#10b981;--accent-2:#06b6d4;--accent-hover:#0ea371;--accent-soft:rgba(16,185,129,.14);--accent-line:rgba(16,185,129,.35);--danger:#f87171;--danger-soft:rgba(248,113,113,.12);--warn:#fbbf24;--input-bg:#0a101b;--term-bg:#05080f;--radius:16px;--radius-sm:10px;--nav-height:0px;--shadow-card:0 1px 2px rgba(0,0,0,.3),0 14px 34px -18px rgba(0,0,0,.6);--grad-accent:linear-gradient(135deg,var(--accent),var(--accent-2));--glow:rgba(16,185,129,.35)}
[data-theme="light"]{--bg-body:#f2f5f9;--bg-card:#ffffff;--bg-elev:#f6f8fb;--bg-hover:#eef2f7;--text-main:#0b1b2b;--text-muted:#5b6b7c;--border:rgba(11,27,43,.09);--border-strong:rgba(11,27,43,.16);--accent:#059669;--accent-2:#0891b2;--accent-hover:#047857;--accent-soft:rgba(5,150,105,.10);--accent-line:rgba(5,150,105,.28);--danger:#dc2626;--danger-soft:rgba(220,38,38,.08);--warn:#d97706;--input-bg:#f8fafc;--term-bg:#ffffff;--shadow-card:0 1px 2px rgba(11,27,43,.05),0 12px 28px -14px rgba(11,27,43,.16);--glow:rgba(5,150,105,.22)}
::selection{background:var(--accent-soft);color:var(--text-main)}
.text-muted{color:var(--text-muted)!important}
body{background-color:var(--bg-body);color:var(--text-main);font-family:'Inter',system-ui,-apple-system,sans-serif;-webkit-font-smoothing:antialiased;height:100vh;height:100dvh;overflow:hidden;transition:background-color .25s,color .25s}
.font-monospace,code,.mono{font-family:'JetBrains Mono',ui-monospace,Menlo,monospace!important}
::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border-strong);border-radius:9px;border:2px solid transparent;background-clip:content-box}::-webkit-scrollbar-thumb:hover{background:var(--text-muted)}
.cursor-pointer{cursor:pointer}
.app-shell{display:flex;height:100vh;height:100dvh}
.sidebar{height:100vh;height:100dvh;width:252px;min-width:252px;background:var(--bg-card);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:1000}
.logo{padding:1.35rem 1.4rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
.logo-mark{width:40px;height:40px;border-radius:12px;flex-shrink:0;background:var(--grad-accent);color:#fff;display:flex;align-items:center;justify-content:center;font-size:1.2rem;box-shadow:0 10px 22px -10px var(--glow)}
.logo-text{font-size:1.14rem;font-weight:800;letter-spacing:-.02em;line-height:1.15}
.logo-sub{display:block;font-size:.58rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);margin-top:3px;opacity:.9}
.nav-label{padding:1.15rem 1.4rem .45rem;font-size:.66rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--text-muted);opacity:.75}
.nav-link{position:relative;color:var(--text-muted);margin:2px .8rem;padding:.62rem .95rem;display:flex;align-items:center;gap:12px;font-weight:500;font-size:.92rem;border-radius:var(--radius-sm);transition:all .18s;white-space:nowrap;border:none;text-decoration:none}
.nav-link:hover{background:var(--bg-hover);color:var(--text-main)}
.nav-link.active{background:var(--accent-soft);color:var(--accent);font-weight:700}
.nav-link.active::before{content:"";position:absolute;left:-.8rem;top:22%;bottom:22%;width:3px;border-radius:0 3px 3px 0;background:var(--accent)}
.nav-link i{font-size:1.08rem;width:1.25rem;text-align:center}
.sidebar-footer{margin-top:auto;border-top:1px solid var(--border);display:flex;align-items:center;width:100%;padding:.4rem 0 .6rem}
.logout-btn{flex:1;margin-top:0!important;color:var(--danger)!important}
.logout-btn:hover{background:var(--danger-soft);color:var(--danger)}
.github-btn{color:var(--text-muted);padding:.75rem 1.2rem;font-size:1.2rem;display:flex;align-items:center;transition:all .2s;border-left:1px solid var(--border);text-decoration:none}
.github-btn:hover{color:var(--accent);background:var(--bg-hover)}
.content{flex:1;padding:2.1rem 2.4rem;overflow-y:auto;height:100vh;height:100dvh;padding-bottom:calc(2.1rem + var(--nav-height))}
.section-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:1.4rem;gap:1rem}
.section-header h3{font-size:1.42rem;font-weight:800;margin:0;letter-spacing:-.025em;display:flex;align-items:center;gap:.65rem}
.section-header h3::before{content:"";width:5px;height:1.35rem;border-radius:3px;background:var(--grad-accent)}
.section-sub{color:var(--text-muted);font-size:.85rem;margin-top:.35rem}
.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.9rem;margin-bottom:1.6rem}
.stat-chip{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:.95rem 1.1rem;display:flex;align-items:center;gap:.9rem;box-shadow:var(--shadow-card);transition:transform .2s,border-color .2s}
.stat-chip:hover{transform:translateY(-2px);border-color:var(--accent-line)}
.stat-chip .icon-box{width:40px;height:40px;border-radius:11px;background:var(--accent-soft);color:var(--accent);font-size:1.1rem;flex-shrink:0}
.stat-num{font-size:1.3rem;font-weight:800;line-height:1.1;letter-spacing:-.02em}
.stat-label{font-size:.72rem;color:var(--text-muted);font-weight:600;letter-spacing:.06em;text-transform:uppercase}
.btn-primary{background:var(--grad-accent);border:none;padding:.58rem 1.15rem;font-weight:700;font-size:.9rem;color:#fff;border-radius:var(--radius-sm);box-shadow:0 8px 20px -10px var(--glow);transition:all .18s}
.btn-primary:hover{background:var(--grad-accent);filter:brightness(1.08);color:#fff;transform:translateY(-1px);box-shadow:0 10px 24px -10px var(--glow)}
.btn-primary:active{transform:translateY(0)}
.btn-primary:focus{box-shadow:0 0 0 3px var(--accent-soft)}
.btn-secondary{background:var(--bg-hover);border:1px solid var(--border-strong);color:var(--text-main);border-radius:var(--radius-sm)}
.btn-outline-secondary{border-color:var(--border-strong);color:var(--text-muted)}
.btn-outline-secondary:hover{background:var(--bg-hover);border-color:var(--accent);color:var(--accent)}
.btn-danger{background:var(--danger);border:none;border-radius:var(--radius-sm)}
.btn-group .btn-check:checked+.btn{background:var(--accent-soft);border-color:var(--accent);color:var(--accent);font-weight:600}
.card-item{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:1.3rem;box-shadow:var(--shadow-card);transition:all .2s}
.card-item:hover{border-color:var(--accent-line)}
.list-group-item{background:var(--bg-card);border:1px solid var(--border);color:var(--text-main);margin-bottom:.55rem;border-radius:var(--radius-sm)!important;padding:.95rem 1.1rem;box-shadow:var(--shadow-card);transition:all .18s}
.list-group-item:hover{border-color:var(--accent-line)}
.btn-action{background:var(--bg-hover);color:var(--text-main);border:1px solid var(--border);width:100%;margin-bottom:.5rem;border-radius:var(--radius-sm);padding:.48rem;font-size:.88rem;transition:all .18s}
.btn-action:hover{background:var(--bg-elev);border-color:var(--accent-line);color:var(--text-main)}
.btn-danger-soft{background:var(--danger-soft);color:var(--danger);border:1px solid rgba(220,38,38,.22)}
.btn-danger-soft:hover{background:rgba(220,38,38,.2);color:var(--danger);border-color:var(--danger)}
.btn-icon{width:33px;height:33px;padding:0;display:inline-flex;align-items:center;justify-content:center;border-radius:var(--radius-sm);transition:all .18s}
.icon-box{width:38px;height:38px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:1.05rem}
.table-custom{width:100%;border-collapse:collapse;color:var(--text-main)}
.table-custom th{text-align:left;padding:.72rem .95rem;border-bottom:1px solid var(--border);color:var(--text-muted);font-weight:700;font-size:.7rem;text-transform:uppercase;letter-spacing:.09em;background:var(--bg-elev)}
.table-custom th:first-child{border-top-left-radius:0}
.table-custom td{padding:.82rem .95rem;border-bottom:1px solid var(--border);font-size:.9rem}
.table-custom tr:last-child td{border-bottom:none}
.table-custom tbody tr{transition:background .15s}
.table-custom tbody tr:hover{background:var(--bg-hover)}
.badge-soft{display:inline-flex;align-items:center;gap:.35rem;background:var(--accent-soft);color:var(--accent);font-weight:600;font-size:.72rem;padding:.28rem .6rem;border-radius:999px}
.badge-mono{background:var(--bg-elev);border:1px solid var(--border);color:var(--text-muted);font-family:'JetBrains Mono',ui-monospace,monospace;font-size:.74rem;padding:.22rem .55rem;border-radius:6px}
.empty-state{border:1.5px dashed var(--border-strong);border-radius:var(--radius);padding:3rem 1rem;text-align:center;color:var(--text-muted);font-size:.9rem;margin-top:.5rem;background:linear-gradient(180deg,transparent,var(--accent-soft));transition:border-color .2s}
.empty-state:hover{border-color:var(--accent-line)}
.empty-state i{display:block;font-size:2rem;margin-bottom:.7rem;opacity:.4}
.empty-inline{padding:2.4rem!important;text-align:center;color:var(--text-muted)}
.hidden{display:none!important}
.server-item{position:relative;overflow:hidden;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:1.05rem 1.2rem;margin-bottom:.75rem;transition:all .22s;display:flex;align-items:center;justify-content:space-between;box-shadow:var(--shadow-card)}
.server-item::after{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--grad-accent);opacity:0;transition:opacity .22s}
.server-item:hover{border-color:var(--accent-line);transform:translateY(-2px);box-shadow:0 18px 36px -16px rgba(0,0,0,.45)}
.server-item:hover::after{opacity:1}
.server-info{display:flex;align-items:center;gap:1rem;min-width:0}
.server-info .icon-box{background:var(--grad-accent);color:#fff;box-shadow:0 8px 18px -9px var(--glow)}
.server-name{font-weight:700;font-size:.98rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.server-actions{display:flex;gap:.5rem;opacity:.8;transition:opacity .2s;flex-shrink:0}
.server-item:hover .server-actions{opacity:1}
.group-header{cursor:pointer;padding:.5rem .35rem;user-select:none;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);margin-bottom:.95rem;transition:color .18s}
.group-header h6{display:flex;align-items:center;gap:.5rem;font-size:.82rem;letter-spacing:.08em;color:var(--text-muted)}
.group-header:hover,.group-header:hover h6{color:var(--accent)}
.group-icon{transition:transform .2s;color:var(--text-muted)}
.group-header[aria-expanded="false"] .group-icon{transform:rotate(-90deg)}
.snippet-code{background:var(--bg-elev);color:var(--text-main);padding:.65rem .85rem;border-radius:var(--radius-sm);font-size:.8rem;border:1px solid var(--border);transition:border-color .18s;cursor:pointer;font-family:'JetBrains Mono',ui-monospace,monospace}
.snippet-code:hover{border-color:var(--accent);color:var(--accent)}
.settings-card{padding:1.2rem}
.settings-card h6{font-weight:700}
.settings-card .icon-box{background:var(--accent-soft);color:var(--accent)}
.snip-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:1.1rem 1.2rem;height:100%;box-shadow:var(--shadow-card);transition:all .22s;position:relative;overflow:hidden;display:flex;flex-direction:column}
.snip-card::after{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--grad-accent);opacity:0;transition:opacity .22s}
.snip-card:hover{border-color:var(--accent-line);transform:translateY(-2px)}
.snip-card:hover::after{opacity:1}
.grp-row{padding:1.15rem 1.25rem;border-bottom:1px solid var(--border);transition:background .18s}
.grp-row:last-child{border-bottom:none}
.grp-row:hover{background:var(--bg-hover)}
.grp-servers{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.7rem}
.srv-chip{display:inline-flex;align-items:center;gap:.4rem;background:var(--bg-elev);border:1px solid var(--border);border-radius:999px;padding:.24rem .7rem;font-size:.76rem;color:var(--text-muted);transition:all .18s}
.srv-chip:hover{border-color:var(--accent-line);color:var(--accent)}
.srv-chip i{font-size:.72rem}
.grp-nosrv{font-size:.76rem;color:var(--text-muted);opacity:.65;font-style:italic}
.grp-top{display:flex;align-items:center;gap:.9rem}
.grp-icon{width:42px;height:42px;border-radius:12px;background:var(--grad-accent);color:#fff;display:flex;align-items:center;justify-content:center;font-size:1.15rem;flex-shrink:0;box-shadow:0 8px 18px -9px var(--glow)}
.grp-name{font-weight:700;font-size:1rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.grp-meta{margin-top:.35rem}
.set-row-ctl .btn-action{width:auto;margin-bottom:0}
.snip-head{display:flex;align-items:center;gap:.9rem;margin-bottom:.85rem}
.copy-hint{margin-left:auto;opacity:.45;flex-shrink:0}
.set-panel{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow-card);margin-bottom:1rem;overflow:hidden}
.set-panel-head{padding:.75rem 1.2rem;font-size:.72rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text-muted);background:var(--bg-elev);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.5rem}
.set-row{display:flex;align-items:center;gap:1rem;padding:1rem 1.2rem;border-bottom:1px solid var(--border)}
.set-row:last-child{border-bottom:none}
.set-row-icon{width:38px;height:38px;border-radius:11px;background:var(--accent-soft);color:var(--accent);display:flex;align-items:center;justify-content:center;font-size:1.05rem;flex-shrink:0}
.set-row-body{flex:1;min-width:0}
.set-row-title{font-weight:700;font-size:.92rem}
.set-row-desc{font-size:.78rem;color:var(--text-muted);margin-top:.15rem}
.set-row-ctl{flex-shrink:0;display:flex;gap:.5rem;align-items:center}
.update-hero{background:linear-gradient(165deg,var(--accent-soft),transparent 60%),var(--bg-card)}
.upd-label{font-size:.68rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--text-muted)}
.upd-cur{font-size:2.1rem;font-weight:800;letter-spacing:-.02em;margin:.2rem 0 .4rem;background:var(--grad-accent);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.badge-soft i{font-size:.72rem}
.modal-content{background:var(--bg-card);border:1px solid var(--border);color:var(--text-main);border-radius:18px;box-shadow:0 40px 80px -20px rgba(0,0,0,.6)}
.modal-header{border-bottom:1px solid var(--border);padding:1rem 1.35rem;border-radius:18px 18px 0 0;background:var(--bg-elev)}
.modal-header .modal-title{font-weight:700;font-size:1.02rem;display:flex;align-items:center;gap:.6rem}
.modal-footer{border-color:var(--border);padding:.9rem 1.35rem;border-radius:0 0 18px 18px}
.modal-body{padding:1.35rem}
.form-label{font-size:.82rem;font-weight:600;color:var(--text-muted);margin-bottom:.35rem;letter-spacing:.02em}
.form-control,.form-select{background:var(--input-bg);border:1px solid var(--border-strong);color:var(--text-main);border-radius:var(--radius-sm);padding:.58rem .85rem;transition:border-color .18s,box-shadow .18s}
.form-control::placeholder{color:var(--text-muted);opacity:.65}
.form-control:focus,.form-select:focus{background:var(--input-bg);border-color:var(--accent);color:var(--text-main);box-shadow:0 0 0 3px var(--accent-soft)}
.input-group-text{background:var(--bg-elev);border:1px solid var(--border-strong);color:var(--text-muted);border-radius:var(--radius-sm)}
.btn-close{filter:invert(1) grayscale(1) brightness(.8)}
[data-theme="light"] .btn-close{filter:none}
.term-chrome{background:var(--term-bg);border-radius:16px;overflow:hidden;border:1px solid var(--border-strong);box-shadow:var(--shadow-card)}
.term-header{background:var(--bg-card);border-bottom:1px solid var(--border)!important;padding:.55rem .85rem!important;display:flex;align-items:center}
#termModal .nav-link{color:var(--text-muted);padding:.4rem 1rem;margin:0;font-size:.85rem;font-weight:600;border-radius:8px}
#termModal .nav-link:hover{background:var(--bg-hover);color:var(--text-main)}
#termModal .nav-link.active{background:var(--grad-accent);color:#fff;box-shadow:0 2px 10px -2px var(--glow)}
#termModal .nav-link.active::before{display:none}
.term-meta{display:flex;align-items:center;gap:.5rem;min-width:0}
.term-title{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:.8rem;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px}
.term-dot{width:9px;height:9px;border-radius:50%;background:var(--text-muted);flex-shrink:0;transition:background .2s}
.term-dot.connecting{background:var(--warn);animation:termPulse 1s ease-in-out infinite}
.term-dot.on{background:var(--accent);box-shadow:0 0 8px var(--glow)}
.term-dot.off{background:var(--danger)}
@keyframes termPulse{50%{opacity:.35}}
.term-tool{background:var(--bg-hover);border:1px solid var(--border);color:var(--text-muted);border-radius:8px;display:inline-flex;align-items:center;justify-content:center}
.term-tool:hover{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)}
.term-close{margin-left:.25rem}
.term-container{background:var(--term-bg);height:calc(90vh - 45px)}
#terminal{padding:8px 4px}
.term-keys{min-height:62px;background:var(--bg-card);border-top:1px solid var(--border);padding:.5rem .6rem;flex-wrap:wrap}
.term-key{width:44px;height:38px;background:var(--bg-hover);border:1px solid var(--border-strong);color:var(--text-main);border-radius:9px;box-shadow:0 2px 0 var(--border-strong);display:inline-flex;align-items:center;justify-content:center;font-size:.95rem}
.term-key:active{transform:translateY(2px);box-shadow:none}
.term-key-fn{width:auto;padding:0 .75rem;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:.75rem;font-weight:700}
.term-key-danger{width:auto;padding:0 .75rem;background:var(--danger-soft);border-color:rgba(220,38,38,.3);color:var(--danger)}
.sftp-pane{background:var(--bg-body)}
.sftp-bar{display:flex;align-items:center;padding:.6rem .85rem;border-bottom:1px solid var(--border);background:var(--bg-card)}
.sftp-loc{display:flex;align-items:center;gap:.5rem;background:var(--input-bg);border:1px solid var(--border-strong);border-radius:9px;padding:.32rem .7rem;color:var(--text-muted);min-width:0}
.sftp-loc input{background:transparent;border:none;outline:none;color:var(--text-main);font-family:'JetBrains Mono',ui-monospace,monospace;font-size:.8rem;width:100%}
.sftp-status{margin-left:.7rem;font-size:.78rem;color:var(--text-muted);white-space:nowrap}
.sfi-dir{color:var(--warn)!important}
.sfi-file{color:var(--text-muted)!important}
.sftp-name{color:var(--accent);cursor:pointer;font-weight:600}
.sftp-name:hover{text-decoration:underline}
.sftp-size{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:.78rem;color:var(--text-muted)}
.sfa{width:28px;height:28px;padding:0;display:inline-flex;align-items:center;justify-content:center;border-radius:7px;background:var(--bg-hover);border:1px solid var(--border);color:var(--text-muted);font-size:.8rem}
.sfa:hover{color:var(--accent);border-color:var(--accent-line);background:var(--accent-soft)}
.sfa-danger{color:var(--danger)}
.sfa-danger:hover{color:#fff;background:var(--danger);border-color:var(--danger)}
#quick-snippets-menu{background:var(--bg-card);border:1px solid var(--border-strong)}
#quick-snippets-menu .dropdown-item{padding:.55rem .95rem;cursor:pointer;color:var(--text-main)}
#quick-snippets-menu .dropdown-item:hover{background:var(--bg-hover);color:var(--accent)}
#editor{width:100%;height:65vh;border-radius:var(--radius-sm);border:1px solid var(--border-strong)}
#modalEditor{z-index:1060}
#modalConfirm{z-index:10000!important}
#modalConfirm .modal-header{background:transparent;border:none}
#modalConfirm .modal-footer{border:none;background:transparent}
.alert{border-radius:var(--radius-sm);border-color:var(--border-strong)}
.alert-success{background:var(--accent-soft);border-color:var(--accent-line);color:var(--accent)}
.dropdown-menu{background:var(--bg-card);border:1px solid var(--border-strong);border-radius:12px}
.dropdown-item{color:var(--text-main)}
.dropdown-item:hover{background:var(--bg-hover);color:var(--accent)}
@media (max-width:768px){
    :root{--nav-height:66px}
    body{flex-direction:column}
    .sidebar{position:fixed;bottom:0;left:0;width:100%;min-width:auto;height:var(--nav-height);border-right:none;border-top:1px solid var(--border);flex-direction:row;justify-content:space-around;padding:0;background:color-mix(in srgb,var(--bg-card) 88%,transparent);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);box-shadow:0 -8px 30px rgba(0,0,0,.18)}
    .logo,.nav-label{display:none}
    .nav-link{flex-direction:column;gap:3px;padding:9px 0;font-size:.68rem;flex:1;justify-content:center;margin:0;border-radius:0}
    .nav-link.active{background:transparent}
    .nav-link.active::before{left:28%;right:28%;top:0;bottom:auto;width:auto;height:2.5px;border-radius:0 2.5px 2.5px 0}
    .nav-link i{font-size:1.35rem;margin-bottom:1px;width:auto}
    .sidebar-footer{margin-top:0;border-top:none;width:auto;display:contents}
    .logout-btn{margin-top:0;border-left:1px solid var(--border);max-width:62px}
    .github-btn{flex:1;padding:9px 0;justify-content:center;border-left:1px solid var(--border)}
    .content{padding:1.05rem;padding-bottom:125px}
    .section-header h3{font-size:1.18rem}
    .stat-row{grid-template-columns:repeat(2,1fr);gap:.65rem}
    .set-row{flex-wrap:wrap}
    .set-row-ctl{width:100%;flex-wrap:wrap}
    .snip-card{height:auto}
    .server-item{flex-direction:column;align-items:flex-start;gap:.6rem}
    .server-info{width:100%}
    .server-actions{width:100%;justify-content:flex-end;opacity:1;margin-top:.35rem;border-top:1px solid var(--border);padding-top:.6rem}
    .modal-dialog{margin:.5rem}
    #termModal .modal-dialog{max-width:100vw;margin:0;height:100vh}
    #termModal .modal-content{height:100%;border-radius:0}
    #termModal .modal-header{border-radius:0}
    .term-container{height:calc(100vh - 110px)}
}
</style>`
const dashBody = `<div class="sidebar">
<div class="logo"><div class="logo-mark"><i class="bi bi-terminal-fill"></i></div><div class="logo-text">WebSSH<span class="logo-sub">Server Console</span></div></div>
<div class="nav-label">主菜单</div>
<a href="#" onclick="showSection('servers',this)" class="nav-link active"><i class="bi bi-hdd-stack"></i> <span>服务器</span></a>
<a href="#" onclick="showSection('groups',this)" class="nav-link"><i class="bi bi-folder2"></i> <span>分组管理</span></a>
<a href="#" onclick="showSection('credentials',this)" class="nav-link"><i class="bi bi-key"></i> <span>凭证管理</span></a>
<a href="#" onclick="showSection('snippets',this)" class="nav-link"><i class="bi bi-code-slash"></i> <span>脚本管理</span></a>
<a href="#" onclick="showSection('settings',this)" class="nav-link"><i class="bi bi-gear"></i> <span>系统设置</span></a>
<div class="sidebar-footer">
    <a href="/api/logout" class="nav-link logout-btn"><i class="bi bi-box-arrow-left"></i> <span>退出</span></a>
    <a href="https://github.com/jinhuaitao/WebSSH" target="_blank" class="github-btn" title="View on GitHub"><i class="bi bi-github"></i></a>
</div>
</div><div class="content"><div id="section-servers">
<div class="section-header"><div><h3>服务器列表</h3><div class="section-sub">集中管理你的全部 SSH 服务器，点击连接即可打开终端</div></div><button class="btn btn-primary" onclick="openModal('modalServer')"><i class="bi bi-plus-lg"></i> 新增服务器</button></div>
<div class="stat-row">
<div class="stat-chip"><div class="icon-box"><i class="bi bi-hdd-network"></i></div><div><div class="stat-num">{{len .Servers}}</div><div class="stat-label">服务器</div></div></div>
<div class="stat-chip"><div class="icon-box"><i class="bi bi-folder2-open"></i></div><div><div class="stat-num">{{len .Groups}}</div><div class="stat-label">分组</div></div></div>
<div class="stat-chip"><div class="icon-box"><i class="bi bi-key-fill"></i></div><div><div class="stat-num">{{len .Credentials}}</div><div class="stat-label">凭证</div></div></div>
<div class="stat-chip"><div class="icon-box"><i class="bi bi-lightning-charge-fill"></i></div><div><div class="stat-num">{{len .Snippets}}</div><div class="stat-label">快捷指令</div></div></div>
</div>
{{range $g := .Groups}}
<div class="group-section mb-4">
    <div class="group-header" data-bs-toggle="collapse" data-bs-target="#group-{{$g.ID}}" aria-expanded="true">
        <h6 class="mb-0"><i class="bi bi-folder2-open"></i> {{$g.Name}}</h6>
        <i class="bi bi-chevron-down group-icon"></i>
    </div>
    <div id="group-{{$g.ID}}" class="collapse show"><div class="row">
        {{range $s := $.Servers}}{{if eq $s.GroupID $g.ID}}
        <div class="col-xl-6 col-12" id="item-server-{{$s.ID}}"><div class="server-item">
            <div class="server-info"><div class="icon-box"><i class="bi bi-hdd-network-fill"></i></div><div style="min-width:0"><div class="server-name">{{$s.Name}}</div><div class="d-flex gap-2 mt-1 flex-wrap"><span class="badge-mono">{{$s.IP}}:{{$s.Port}}</span>{{if $s.Username}}<span class="badge-soft"><i class="bi bi-person-fill"></i>{{$s.Username}}</span>{{end}}</div></div></div>
            <div class="server-actions"><button class="btn btn-primary btn-sm" onclick="openTerminal('{{$s.ID}}','{{$s.Name}}')"><i class="bi bi-terminal me-1"></i>连接</button><button class="btn btn-action btn-sm btn-icon" onclick="editItem('server','{{$s.ID}}')" title="编辑"><i class="bi bi-pencil"></i></button><button class="btn btn-danger-soft btn-sm btn-icon" onclick="deleteItem('server','{{$s.ID}}')" title="删除"><i class="bi bi-trash"></i></button></div>
        </div></div>
        {{end}}{{end}}
    </div></div>
</div>
{{end}}
{{if not .Groups}}<div class="empty-state"><i class="bi bi-hdd-network"></i>还没有服务器，点击右上方“新增服务器”开始使用（自动归入默认分组）</div>{{end}}
</div>
<div id="section-credentials" class="hidden"><div class="section-header"><div><h3>凭证管理</h3><div class="section-sub">统一管理的密码 / 私钥凭证，可被多台服务器复用</div></div><button class="btn btn-primary" onclick="openModal('modalCred')"><i class="bi bi-plus-lg"></i> 新增凭证</button></div>
<div class="card-item p-0 overflow-hidden"><table class="table-custom"><thead><tr><th>备注名称</th><th>用户名</th><th width="150" class="text-end">操作</th></tr></thead><tbody id="cred-list">{{range .Credentials}}
<tr id="item-credential-{{.ID}}"><td><i class="bi bi-key-fill me-2" style="color:var(--warn)"></i>{{.Name}}</td><td><span class="badge-mono">{{.Username}}</span></td>
<td class="text-end"><div class="d-flex justify-content-end gap-2"><button class="btn btn-sm btn-action btn-icon" onclick="editItem('credential','{{.ID}}')"><i class="bi bi-pencil"></i></button><button class="btn btn-sm btn-danger-soft btn-icon" onclick="deleteItem('credential','{{.ID}}')"><i class="bi bi-trash"></i></button></div></td></tr>{{end}}{{if not .Credentials}}<tr><td colspan="3" class="empty-inline"><i class="bi bi-key" style="display:block;font-size:1.7rem;margin-bottom:.5rem;opacity:.4"></i>暂无凭证，点击右上方“新增凭证”创建</td></tr>{{end}}</tbody></table></div></div>
<div id="section-groups" class="hidden"><div class="section-header"><div><h3>分组管理</h3><div class="section-sub">按项目或环境对服务器归类，分组在服务器列表中可折叠展开</div></div><button class="btn btn-primary" onclick="openModal('modalGroup')"><i class="bi bi-plus-lg"></i> 新增分组</button></div>
<div class="set-panel" id="group-list"><div class="set-panel-head"><i class="bi bi-folder2-open"></i> 全部分组<span class="badge-soft ms-auto" style="letter-spacing:0"><i class="bi bi-collection"></i>{{len .Groups}} 个分组</span></div>
{{range .Groups}}<div class="grp-row" id="item-group-{{.ID}}">
<div class="grp-top"><div class="grp-icon"><i class="bi bi-folder-fill"></i></div><div style="min-width:0;flex:1"><div class="grp-name" title="{{.Name}}">{{.Name}}</div><div class="grp-meta"><span class="badge-soft"><i class="bi bi-hdd-network"></i><span class="grp-count" data-group="{{.ID}}">0</span> 台服务器</span></div></div><div class="d-flex gap-2 flex-shrink-0"><button class="btn btn-sm btn-action btn-icon" onclick="editItem('group','{{.ID}}')" title="编辑"><i class="bi bi-pencil"></i></button><button class="btn btn-sm btn-danger-soft btn-icon" onclick="deleteItem('group','{{.ID}}')" title="删除"><i class="bi bi-trash"></i></button></div></div>
<div class="grp-servers" data-servers-for="{{.ID}}"></div>
</div>{{end}}{{if not .Groups}}<div class="p-3"><div class="empty-state"><i class="bi bi-folder-plus"></i>暂无分组，点击右上方“新增分组”创建第一个分组</div></div>{{end}}</div></div>
<div id="section-snippets" class="hidden"><div class="section-header"><div><h3>快捷指令</h3><div class="section-sub">常用命令片段，可在终端弹窗中一键发送或点击复制</div></div><button class="btn btn-primary" onclick="openModal('modalSnippet')"><i class="bi bi-plus-lg"></i> 新增指令</button></div>
<div class="row g-3" id="snippet-list">{{range .Snippets}}<div class="col-lg-6" id="item-snippet-{{.ID}}"><div class="snip-card">
<div class="snip-head"><div class="grp-icon"><i class="bi bi-lightning-charge-fill"></i></div><div style="min-width:0;flex:1"><div class="grp-name" title="{{.Name}}">{{.Name}}</div><div class="small text-muted">终端弹窗右上角闪电按钮可一键发送</div></div><div class="d-flex gap-2 flex-shrink-0"><button class="btn btn-sm btn-action btn-icon" onclick="editItem('snippet','{{.ID}}')" title="编辑"><i class="bi bi-pencil"></i></button><button class="btn btn-sm btn-danger-soft btn-icon" onclick="deleteItem('snippet','{{.ID}}')" title="删除"><i class="bi bi-trash"></i></button></div></div>
<div class="snippet-code" onclick="copyText('{{.Command}}')" title="点击复制"><i class="bi bi-chevron-right" style="color:var(--accent);flex-shrink:0"></i><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{.Command}}</span><i class="bi bi-clipboard copy-hint"></i></div>
</div></div>{{end}}{{if not .Snippets}}<div class="col-12"><div class="empty-state"><i class="bi bi-lightning-charge"></i>暂无快捷指令，添加后可在终端里快速发送</div></div>{{end}}</div></div>
<div id="section-settings" class="hidden"><div class="section-header"><div><h3>系统设置</h3><div class="section-sub">主题外观、账号安全、通知与版本管理</div></div></div>
<div class="row g-3"><div class="col-lg-7">
<div class="set-panel"><div class="set-panel-head"><i class="bi bi-palette-fill"></i> 外观与账户</div>
<div class="set-row"><div class="set-row-icon"><i class="bi bi-brightness-high"></i></div><div class="set-row-body"><div class="set-row-title">界面风格</div><div class="set-row-desc">切换明亮 / 深色模式，全局即时生效</div></div><div class="set-row-ctl"><button class="btn btn-action btn-sm" onclick="toggleTheme()"><i class="bi bi-sun-fill me-1"></i>日/夜切换</button></div></div>
<div class="set-row"><div class="set-row-icon"><i class="bi bi-shield-lock"></i></div><div class="set-row-body"><div class="set-row-title">修改密码</div><div class="set-row-desc">更新管理员登录密码</div></div><div class="set-row-ctl"><div class="input-group input-group-sm"><input type="password" id="new-sys-pass" class="form-control" placeholder="新密码"><button class="btn btn-primary" onclick="updateSettings('pass')">更新</button></div></div></div>
<div class="set-row"><div class="set-row-icon"><i class="bi bi-shield-check"></i></div><div class="set-row-body"><div class="set-row-title">两步验证 (2FA)</div><div class="set-row-desc">使用 Google Authenticator 等 TOTP 应用保护登录</div></div><div class="set-row-ctl">
{{if .Config.TOTPSecret}}<span class="badge-soft"><i class="bi bi-check-circle-fill"></i>已启用</span><button class="btn btn-danger-soft btn-sm" onclick="disable2FA()">关闭 2FA</button>
{{else}}<button class="btn btn-primary btn-sm" onclick="open2FAModal()"><i class="bi bi-plus-lg me-1"></i>启用 2FA</button>{{end}}
</div></div>
</div>
<div class="set-panel"><div class="set-panel-head"><i class="bi bi-database-gear-fill"></i> 数据维护</div>
<div class="set-row"><div class="set-row-icon"><i class="bi bi-cloud-arrow-down"></i></div><div class="set-row-body"><div class="set-row-title">备份与恢复</div><div class="set-row-desc">导出 JSON 备份，或从备份文件恢复（会覆盖当前全部配置）</div></div><div class="set-row-ctl"><button class="btn btn-action btn-sm" onclick="window.location.href='/api/backup'"><i class="bi bi-download me-1"></i>备份</button><div class="input-group input-group-sm" style="max-width:240px"><input type="file" class="form-control" id="restore-file"><button class="btn btn-danger-soft" onclick="restoreData()">恢复</button></div></div></div>
</div>
<div class="set-panel"><div class="set-panel-head"><i class="bi bi-megaphone-fill"></i> 通知与集成</div>
<div class="set-row"><div class="set-row-icon"><i class="bi bi-telegram"></i></div><div class="set-row-body"><div class="set-row-title">Telegram 通知</div><div class="set-row-desc">登录 / 连接事件实时推送到 TG 机器人</div><div class="d-flex gap-2 mt-2 flex-wrap"><input type="text" id="tg-token" class="form-control form-control-sm" style="flex:2;min-width:180px" placeholder="Bot Token" value="{{.Config.TGBotToken}}"><input type="text" id="tg-chat" class="form-control form-control-sm" style="flex:1;min-width:130px" placeholder="Chat ID" value="{{.Config.TGChatID}}"><button class="btn btn-primary btn-sm" onclick="updateSettings('tg')">保存配置</button></div></div></div>
</div>
</div><div class="col-lg-5">
<div class="set-panel update-hero"><div class="set-panel-head"><i class="bi bi-cloud-arrow-up-fill"></i> 版本更新</div>
<div class="p-4 text-center">
<div class="upd-label">当前版本</div>
<div class="upd-cur font-monospace"><span id="cur-version">-</span></div>
<div id="update-info" class="small text-muted" style="min-height:22px"></div>
<div class="d-grid gap-2 mt-2"><button class="btn btn-action" id="btn-check-update" onclick="checkUpdate()"><i class="bi bi-arrow-repeat me-1"></i>检查更新</button><button class="btn btn-primary hidden" id="btn-do-update" onclick="runUpdate()"><i class="bi bi-cloud-arrow-down-fill me-1"></i>立即更新</button></div>
</div></div>
<div class="set-panel"><div class="set-panel-head"><i class="bi bi-info-circle"></i> 关于</div>
<div class="p-3 small text-muted" style="line-height:1.8">WebSSH Manager · 单文件 SSH 运维面板<br>全部数据保存在运行目录的 data.json，建议定期备份。<br><a href="https://github.com/jinhuaitao/WebSSH" target="_blank" style="color:var(--accent);font-weight:600;text-decoration:none"><i class="bi bi-github me-1"></i>GitHub 项目主页 <i class="bi bi-box-arrow-up-right" style="font-size:.7rem"></i></a></div></div>
</div></div></div></div></div>`
const dashModals = `<div class="modal fade" id="modalConfirm" tabindex="-1"><div class="modal-dialog modal-sm modal-dialog-centered"><div class="modal-content"><div class="modal-header border-0 pb-0"><h5 class="modal-title" style="color:var(--danger)"><i class="bi bi-exclamation-triangle-fill me-2"></i>操作确认</h5></div><div class="modal-body text-center text-muted" id="confirmMessage">Are you sure?</div><div class="modal-footer border-0 justify-content-center pt-0"><button type="button" class="btn btn-secondary btn-sm px-3" data-bs-dismiss="modal">取消</button><button type="button" class="btn btn-danger btn-sm px-3" onclick="confirmAction()">确认</button></div></div></div></div>
<div class="modal fade" id="modal2FA"><div class="modal-dialog modal-dialog-centered"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-shield-check me-2" style="color:var(--accent)"></i>设置两步验证</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body text-center">
    <p class="text-muted small">请使用 Google Authenticator 扫描下方二维码</p>
    <div id="qrcode" class="d-flex justify-content-center my-3 bg-white p-3 mx-auto" style="width:160px;height:160px;border-radius:14px"></div>
    <div class="input-group mb-3"><span class="input-group-text"><i class="bi bi-key"></i></span><input type="text" id="2fa-secret" class="form-control font-monospace" readonly></div>
    <div class="mb-3"><label class="form-label">输入 6 位验证码以启用</label><input type="text" id="2fa-verify-code" class="form-control text-center font-monospace" placeholder="000000" maxlength="6"></div>
</div>
<div class="modal-footer"><button class="btn btn-primary w-100" onclick="confirmEnable2FA()">验证并启用</button></div></div></div></div>
<div class="modal fade" id="modalServer"><div class="modal-dialog modal-dialog-centered"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-hdd-network me-2" style="color:var(--accent)"></i><span id="titleServer">新增服务器</span></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="formServer"><div class="mb-3"><label class="form-label">服务器名称</label><input type="text" id="srv-name" class="form-control" placeholder="例如：生产 Web-01" required></div><div class="row mb-3"><div class="col-8"><label class="form-label">IP 地址</label><input type="text" id="srv-ip" class="form-control font-monospace" placeholder="203.0.113.10" required></div><div class="col-4"><label class="form-label">端口</label><input type="number" id="srv-port" class="form-control font-monospace" value="22" required></div></div><div class="mb-3"><label class="form-label">认证方式</label><div class="btn-group w-100" role="group"><input type="radio" class="btn-check" name="authType" id="authCustom" value="custom" checked onchange="toggleAuthFields()"><label class="btn btn-outline-secondary" for="authCustom"><i class="bi bi-person-gear me-1"></i>自定义账号</label><input type="radio" class="btn-check" name="authType" id="authSaved" value="saved" onchange="toggleAuthFields()"><label class="btn btn-outline-secondary" for="authSaved"><i class="bi bi-key me-1"></i>选择凭证</label></div></div><div id="field-custom-auth"><div class="row mb-2"><div class="col-6"><label class="form-label">用户名</label><input type="text" id="srv-user" class="form-control" value="root"></div><div class="col-6"><label class="form-label">密码</label><input type="password" id="srv-pass" class="form-control"></div></div></div><div id="field-saved-auth" class="hidden"><div class="mb-2"><label class="form-label">选择凭证</label><select id="srv-cred" class="form-select"><option value="">请选择...</option>{{range .Credentials}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select></div></div><div class="mb-2"><label class="form-label">分组</label><select id="srv-group" class="form-select">{{range .Groups}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select></div></form></div><div class="modal-footer"><button class="btn btn-secondary btn-sm" data-bs-dismiss="modal">取消</button><button class="btn btn-primary" onclick="submitServer()"><i class="bi bi-check-lg me-1"></i>保存</button></div></div></div></div>
<div class="modal fade" id="modalCred"><div class="modal-dialog modal-dialog-centered"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-key me-2" style="color:var(--accent)"></i><span id="titleCred">新增凭证</span></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="formCred"><label class="form-label">备注名称</label><input type="text" id="cred-name" class="form-control mb-3" placeholder="例如：机房通用密钥"><label class="form-label">用户名</label><input type="text" id="cred-user" class="form-control mb-3" value="root"><label class="form-label">密码 (可选)</label><input type="password" id="cred-pass" class="form-control mb-3"><label class="form-label">SSH 私钥 (可选)</label><textarea id="cred-key" class="form-control font-monospace" rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..."></textarea></form></div><div class="modal-footer"><button class="btn btn-secondary btn-sm" data-bs-dismiss="modal">取消</button><button class="btn btn-primary" onclick="submitCred()"><i class="bi bi-check-lg me-1"></i>保存</button></div></div></div></div>
<div class="modal fade" id="modalGroup"><div class="modal-dialog modal-dialog-centered modal-sm"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-folder2 me-2" style="color:var(--accent)"></i><span id="titleGroup">新增分组</span></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><label class="form-label">分组名称</label><input type="text" id="group-name" class="form-control" placeholder="例如：生产环境"></div><div class="modal-footer"><button class="btn btn-secondary btn-sm" data-bs-dismiss="modal">取消</button><button class="btn btn-primary" onclick="submitGroup()"><i class="bi bi-check-lg me-1"></i>保存</button></div></div></div></div>
<div class="modal fade" id="modalSnippet"><div class="modal-dialog modal-dialog-centered"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-lightning-charge me-2" style="color:var(--accent)"></i><span id="titleSnippet">新增指令</span></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><label class="form-label">标题</label><input type="text" id="snip-name" class="form-control mb-3" placeholder="例如：查看磁盘占用"><label class="form-label">命令内容</label><textarea id="snip-cmd" class="form-control font-monospace" rows="4" placeholder="df -h"></textarea></div><div class="modal-footer"><button class="btn btn-secondary btn-sm" data-bs-dismiss="modal">取消</button><button class="btn btn-primary" onclick="submitSnippet()"><i class="bi bi-check-lg me-1"></i>保存</button></div></div></div></div>
<div class="modal fade" id="termModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false"><div class="modal-dialog modal-xl" style="max-width: 95vw;"><div class="modal-content term-chrome" style="height: 90vh;"><div class="modal-header border-0 py-0 term-header"><ul class="nav nav-pills me-auto" id="termTabs"><li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#tab-ssh" onclick="toggleQuickCmd(true)"><i class="bi bi-terminal-fill me-1"></i>Terminal</a></li><li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-sftp" onclick="loadSFTP();toggleQuickCmd(false)"><i class="bi bi-folder-symlink me-1"></i>SFTP</a></li></ul><div class="term-meta me-3"><span id="term-dot" class="term-dot"></span><span id="termTitle" class="term-title"></span></div><div class="dropdown d-inline-block me-2" id="btn-quick-cmd"><button class="btn btn-sm term-tool" type="button" data-bs-toggle="dropdown" title="快捷指令"><i class="bi bi-lightning-charge-fill"></i></button><ul class="dropdown-menu dropdown-menu-end" id="quick-snippets-menu"></ul></div><button type="button" class="btn-close term-close" onclick="closeTerm()"></button></div><div class="modal-body p-0 tab-content"><div class="tab-pane fade show active h-100" id="tab-ssh"><div class="term-container h-100 d-flex flex-column"><div id="terminal" class="flex-grow-1"></div><div class="d-flex d-md-none justify-content-center align-items-center gap-2 term-keys" id="mobile-controls"><button class="btn term-key" onclick="sendKey('\x1b[D')"><i class="bi bi-arrow-left"></i></button><button class="btn term-key" onclick="sendKey('\x1b[A')"><i class="bi bi-arrow-up"></i></button><button class="btn term-key" onclick="sendKey('\x1b[B')"><i class="bi bi-arrow-down"></i></button><button class="btn term-key" onclick="sendKey('\x1b[C')"><i class="bi bi-arrow-right"></i></button><button class="btn term-key term-key-fn" onclick="sendKey('\t')">Tab</button><button class="btn term-key term-key-fn" onclick="sendKey('\x1b')">Esc</button><button class="btn term-key term-key-danger" onclick="sendKey('\x03')">Ctrl+C</button></div></div></div><div class="tab-pane fade h-100" id="tab-sftp"><div class="d-flex flex-column h-100 sftp-pane"><div class="sftp-bar"><button class="btn btn-sm term-tool me-2" onclick="loadSFTP('..')" title="返回上级"><i class="bi bi-arrow-up"></i></button><button class="btn btn-sm term-tool me-2" onclick="loadSFTP()" title="刷新"><i class="bi bi-arrow-repeat"></i></button><div class="sftp-loc flex-grow-1"><i class="bi bi-folder2-open"></i><input type="text" id="sftp-path" readonly></div><button class="btn btn-sm btn-primary ms-2" onclick="document.getElementById('upload-file').click()"><i class="bi bi-upload me-1"></i>上传</button><input type="file" id="upload-file" class="hidden" onchange="uploadFile(this)"><span id="sftp-status" class="sftp-status"></span></div><div class="flex-grow-1 overflow-auto"><table class="table-custom"><thead class="sticky-top"><tr><th>名称</th><th>大小</th><th>修改时间</th><th class="text-end">操作</th></tr></thead><tbody id="sftp-list"></tbody></table></div></div></div></div></div></div></div>
<div class="modal fade" id="modalEditor" data-bs-backdrop="static" data-bs-keyboard="false"><div class="modal-dialog modal-xl modal-dialog-centered"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-pencil-square me-2" style="color:var(--accent)"></i>编辑: <span id="editor-filename" class="font-monospace" style="color:var(--accent-2)"></span></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body p-0"><div id="editor"></div></div><div class="modal-footer"><span id="editor-status" class="me-auto text-muted small"></span><button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">关闭</button><button type="button" class="btn btn-primary btn-sm" onclick="saveFileContent()"><i class="bi bi-save me-1"></i>保存 (Ctrl+S)</button></div></div></div></div>`

const dashScript = `<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script><script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script><script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script><script>
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').then(reg => {
        console.log('SW registered:', reg);
    }).catch(err => console.log('SW registration failed:', err));
}
const uuid=()=>Math.random().toString(36).substr(2,9);let bsModals={},currentServerId="",editingId=null;const dbData={servers:{{.Servers|json}},groups:{{.Groups|json}},credentials:{{.Credentials|json}},snippets:{{.Snippets|json}}};
let pendingAction=null;const bsConfirm=new bootstrap.Modal(document.getElementById('modalConfirm'));
function showConfirm(msg,action){document.getElementById('confirmMessage').innerText=msg;pendingAction=action;bsConfirm.show();}
async function confirmAction(){if(pendingAction)await pendingAction();bsConfirm.hide();}
function showSection(id,btn){document.querySelectorAll('[id^="section-"]').forEach(el=>el.classList.add('hidden'));document.getElementById('section-'+id).classList.remove('hidden');if(btn){document.querySelectorAll('.sidebar a').forEach(a=>a.classList.remove('active'));btn.classList.add('active');}localStorage.setItem('activeSection',id);}
function initTheme(){const t=localStorage.getItem('theme')||'light';document.body.setAttribute('data-theme',t);if(aceEditor)aceEditor.setTheme(t==='dark'?'ace/theme/monokai':'ace/theme/chrome');}
function toggleTheme(){const c=document.body.getAttribute('data-theme');const n=c==='light'?'dark':'light';document.body.setAttribute('data-theme',n);localStorage.setItem('theme',n);if(aceEditor)aceEditor.setTheme(n==='dark'?'ace/theme/monokai':'ace/theme/chrome');}
function initGroupStates(){let s={};try{s=JSON.parse(localStorage.getItem('webssh_group_states')||'{}');}catch(e){}document.querySelectorAll('.group-section').forEach(sec=>{const c=sec.querySelector('.collapse');const t=sec.querySelector('.group-header');if(!c||!t)return;const id=c.id;if(s[id]===false){c.classList.remove('show');t.setAttribute('aria-expanded','false');}c.addEventListener('hide.bs.collapse',()=>{s=JSON.parse(localStorage.getItem('webssh_group_states')||'{}');s[id]=false;localStorage.setItem('webssh_group_states',JSON.stringify(s));});c.addEventListener('show.bs.collapse',()=>{s=JSON.parse(localStorage.getItem('webssh_group_states')||'{}');s[id]=true;localStorage.setItem('webssh_group_states',JSON.stringify(s));});});}
function initGroupCounts(){document.querySelectorAll('.grp-count').forEach(el=>{const gid=el.dataset.group;const list=dbData.servers.filter(s=>s.group_id===gid);el.innerText=list.length;const box=document.querySelector('.grp-servers[data-servers-for="'+gid+'"]');if(box){box.innerHTML=list.length?list.map(s=>'<span class="srv-chip" title="'+s.ip+':'+s.port+'"><i class="bi bi-hdd-network"></i>'+s.name+'</span>').join(''):'<span class="grp-nosrv">该分组下暂无服务器</span>';}});}
window.addEventListener('load',()=>{initTheme();initGroupStates();initGroupCounts();loadCurrentVersion();let last=localStorage.getItem('activeSection')||'servers';let btn=document.querySelector(".sidebar a[onclick*=\"'"+last+"'\"]");if(btn)btn.click();});
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
function openTerminal(id,name){currentServerId=id;document.getElementById('termTitle').innerText=name;document.getElementById('term-dot').className='term-dot connecting';toggleQuickCmd(true);document.querySelector('#termTabs a[href="#tab-ssh"]').click();termModal.show();const menu=document.getElementById('quick-snippets-menu');menu.innerHTML='';if(dbData.snippets&&dbData.snippets.length===0){menu.innerHTML='<li><span class="dropdown-item text-muted">暂无快捷指令</span></li>';}else if(dbData.snippets){dbData.snippets.forEach(s=>{let li=document.createElement('li');let a=document.createElement('a');a.className='dropdown-item cursor-pointer';a.innerHTML='<strong>'+s.name+'</strong><br><small class="text-muted" style="font-size:0.7em">'+s.command.substring(0,25)+'...</small>';a.onclick=function(){sendCommand(s.command);};li.appendChild(a);menu.appendChild(li);});}setTimeout(()=>{const c=document.getElementById('terminal');c.innerHTML='';const isLight=document.body.getAttribute('data-theme')==='light';
const themeObj = isLight ? {
    background: '#ffffff', foreground: '#333333', cursor: '#0066cc', selection: 'rgba(0, 102, 204, 0.2)',
    black: '#000000', red: '#cd3131', green: '#00bc00', yellow: '#949800', blue: '#0451a5', magenta: '#bc05bc', cyan: '#0598bc', white: '#555555',
    brightBlack: '#666666', brightRed: '#cd3131', brightGreen: '#14ce14', brightYellow: '#b5ba00', brightBlue: '#0451a5', brightMagenta: '#bc05bc', brightCyan: '#0598bc', brightWhite: '#a5a5a5'
} : {
    background: '#1e1e1e', foreground: '#d4d4d4', cursor: '#ffffff', selection: 'rgba(255, 255, 255, 0.3)',
    black: '#000000', red: '#f14c4c', green: '#23d18b', yellow: '#f5f543', blue: '#3b8eea', magenta: '#d670d6', cyan: '#29b8db', white: '#e5e5e5',
    brightBlack: '#666666', brightRed: '#f14c4c', brightGreen: '#23d18b', brightYellow: '#f5f543', brightBlue: '#3b8eea', brightMagenta: '#d670d6', brightCyan: '#29b8db', brightWhite: '#e5e5e5'
};
term=new Terminal({cursorBlink:true,fontSize:14,fontFamily:'Menlo, Monaco, "Courier New", monospace',theme:themeObj});const f=new FitAddon.FitAddon();term.loadAddon(f);term.open(c);f.fit();let proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
socket=new WebSocket(proto+location.host+'/ws/ssh?id='+id+'&cols='+term.cols+'&rows='+term.rows);socket.onopen=()=>{document.getElementById('term-dot').className='term-dot on';};socket.onmessage=(ev)=>{if(typeof ev.data==='string')term.write(ev.data);else{let r=new FileReader();r.onload=()=>term.write(r.result);r.readAsText(ev.data);}};term.onData(d=>socket.send(d));socket.onclose=()=>{document.getElementById('term-dot').className='term-dot off';term.write('\r\n\x1b[31mConnection Closed.\x1b[0m\r\n');};window.onresize=()=>f.fit();},500);}
function closeTerm(){if(socket)socket.close();if(term)term.dispose();termModal.hide();}
function sendCommand(cmd){if(socket&&socket.readyState===WebSocket.OPEN){socket.send(cmd+"\n");term.focus();}}
async function loadSFTP(path){if(!path)path=currentPath;if(path==='..'){let p=currentPath.split('/');p.pop();path=p.join('/')||'/';}document.getElementById('sftp-status').innerText="加载中...";try{let res=await fetch('/api/sftp/list?id='+currentServerId+'&path='+encodeURIComponent(path));let data=await res.json();currentPath=data.path;document.getElementById('sftp-path').value=currentPath;let tbody=document.getElementById('sftp-list');tbody.innerHTML='';data.files.forEach(f=>{let tr=document.createElement('tr');let icon=f.is_dir?'<i class="bi bi-folder-fill sfi-dir"></i>':'<i class="bi bi-file-earmark-text sfi-file"></i>';let clickFn=f.is_dir?"loadSFTP('"+(f.name==='..'?'..':currentPath+"/"+f.name)+"')":"";let displayName=f.name==='..'?'...':f.name;let nameLink='<span class="sftp-name" onclick="'+clickFn+'">'+displayName+'</span>';let actions='';if(!f.is_dir){actions+='<button class="btn btn-sm btn-icon sfa" title="下载" onclick="window.open(\'/api/sftp/download?id='+currentServerId+'&path='+encodeURIComponent(currentPath+'/'+f.name)+'\')"><i class="bi bi-download"></i></button>';actions+='<button class="btn btn-sm btn-icon sfa" title="编辑" onclick="openEditor(\''+f.name+'\')"><i class="bi bi-pencil-square"></i></button>';}if(f.name!=='..'){actions+='<button class="btn btn-sm btn-icon sfa sfa-danger" title="删除" onclick="deleteFile(\''+f.name+'\')"><i class="bi bi-trash"></i></button>';}tr.innerHTML='<td>'+icon+' '+nameLink+'</td><td><span class="sftp-size">'+(f.is_dir?'-':(f.size/1024).toFixed(1)+' KB')+'</span></td><td><span class="sftp-size">'+f.mod_time+'</span></td><td class="text-end"><div class="d-inline-flex gap-1">'+actions+'</div></td>';tbody.appendChild(tr);});document.getElementById('sftp-status').innerText="";}catch(e){document.getElementById('sftp-status').innerText="Error: "+e;}}
async function uploadFile(input){if(input.files.length===0)return;let fd=new FormData();fd.append("file",input.files[0]);fd.append("id",currentServerId);fd.append("path",currentPath);document.getElementById('sftp-status').innerText="上传中...";let res=await fetch('/api/sftp/upload',{method:'POST',body:fd});if(res.ok){loadSFTP();alert('上传成功');}else{alert('上传失败');}input.value='';}
async function deleteFile(fileName){showConfirm("确定要删除 "+fileName+" 吗？此操作不可恢复！",async()=>{let fd=new FormData();fd.append("id",currentServerId);fd.append("path",currentPath+"/"+fileName);let res=await fetch('/api/sftp/delete',{method:'POST',body:fd});if(res.ok){loadSFTP();alert('删除成功');}else{alert('删除失败: 可能是目录非空');}});}
let aceEditor,editingFilePath="";const modalEditor=new bootstrap.Modal(document.getElementById('modalEditor'));
function initEditor(){if(!aceEditor){aceEditor=ace.edit("editor");const t=document.body.getAttribute('data-theme')||'dark';aceEditor.setTheme(t==='dark'?'ace/theme/monokai':'ace/theme/chrome');aceEditor.session.setMode("ace/mode/text");aceEditor.setFontSize(14);aceEditor.commands.addCommand({name:'save',bindKey:{win:'Ctrl-S',mac:'Command-S'},exec:function(){saveFileContent();}});}}
async function openEditor(fileName){initEditor();editingFilePath=currentPath+"/"+fileName;document.getElementById('editor-filename').innerText=fileName;document.getElementById('editor-status').innerText="读取中...";modalEditor.show();let ext=fileName.split('.').pop();let mode="ace/mode/text";const modeMap={'js':'javascript','json':'json','html':'html','css':'css','go':'golang','py':'python','sh':'sh','yaml':'yaml','yml':'yaml','md':'markdown','sql':'sql','xml':'xml','dockerfile':'dockerfile'};if(modeMap[ext])mode="ace/mode/"+modeMap[ext];aceEditor.session.setMode(mode);try{let res=await fetch('/api/sftp/cat?id='+currentServerId+'&path='+encodeURIComponent(editingFilePath));if(!res.ok)throw new Error("Read failed");let content=await res.text();aceEditor.setValue(content,-1);document.getElementById('editor-status').innerText="";}catch(e){aceEditor.setValue("");document.getElementById('editor-status').innerText="读取失败: "+e;}}
async function saveFileContent(){if(!editingFilePath)return;let content=aceEditor.getValue();document.getElementById('editor-status').innerText="保存中...";let fd=new FormData();fd.append("id",currentServerId);fd.append("path",editingFilePath);fd.append("content",content);try{let res=await fetch('/api/sftp/save',{method:'POST',body:fd});if(res.ok){document.getElementById('editor-status').innerText="已保存 "+new Date().toLocaleTimeString();document.getElementById('editor-status').classList.add('text-success');setTimeout(()=>document.getElementById('editor-status').classList.remove('text-success'),2000);}else{alert("保存失败");document.getElementById('editor-status').innerText="保存失败";}}catch(e){alert("错误: "+e);}}

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
async function loadCurrentVersion(){try{let res=await fetch('/api/version');let d=await res.json();let el=document.getElementById('cur-version');if(el)el.innerText=d.version;}catch(e){}}
async function checkUpdate(){const btn=document.getElementById('btn-check-update');const info=document.getElementById('update-info');btn.disabled=true;info.innerText='检查中...';try{let res=await fetch('/api/update/check');if(!res.ok)throw new Error((await res.text()).trim());let d=await res.json();info.innerText='最新版本: '+d.latest+' | '+(d.docker?'Docker 环境请拉取新镜像升级':(d.has_update?'发现新版本，可一键更新':'已是最新版本'));if(d.has_update&&!d.docker)document.getElementById('btn-do-update').classList.remove('hidden');else document.getElementById('btn-do-update').classList.add('hidden');}catch(e){info.innerText='检查失败: '+e;}btn.disabled=false;}
async function runUpdate(){let oldVer=(document.getElementById('cur-version')||{}).innerText||'';showConfirm('确认更新到最新版本？下载完成后服务将自动重启。',async()=>{const info=document.getElementById('update-info');info.innerText='正在下载新版本...';try{let res=await fetch('/api/update/run',{method:'POST'});if(!res.ok)throw new Error((await res.text()).trim());info.innerHTML='<span class="text-success">更新成功，服务正在重启，请稍候...</span>';waitRestart(oldVer);}catch(e){info.innerText='更新失败: '+e;}});}
function waitRestart(oldVer){let sawDown=false;let n=0;let t=setInterval(async()=>{n++;try{let res=await fetch('/api/version',{cache:'no-store'});if(res.ok){let d=await res.json();if(sawDown||d.version!==oldVer){clearInterval(t);location.reload();return;}}}catch(e){sawDown=true;}if(n>80){clearInterval(t);document.getElementById('update-info').innerHTML='<span class="text-warning">重启检测超时，请确认服务状态后手动刷新页面</span>';document.getElementById('btn-check-update').disabled=false;}},1500);}
function sendKey(code){if(socket&&socket.readyState===WebSocket.OPEN){socket.send(code);term.focus();}}
</script>`
