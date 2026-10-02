//go:build linux

package main

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// restartAfterUpdate 更新落地后让新版本接管进程:
//   - systemd: 直接退出，由 Restart=always 拉起（避免与单元重启产生双实例竞争端口）
//   - OpenRC/手动运行: 派生一个脱离会话的后台进程，等待端口释放后 exec 新二进制，随后旧进程退出
func restartAfterUpdate() {
	if os.Getenv("INVOCATION_ID") != "" {
		log.Println("更新完成: 退出旧进程，由 systemd 拉起新版本")
		os.Exit(0)
	}
	exPath, err := os.Executable()
	if err != nil {
		log.Printf("更新完成但无法定位可执行文件，请手动重启服务: %v", err)
		os.Exit(0)
	}
	cmdline := "sleep 2; exec " + shellQuote(exPath)
	for _, a := range os.Args[1:] {
		cmdline += " " + shellQuote(a)
	}
	cmd := exec.Command("sh", "-c", cmdline)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		log.Printf("更新完成但后台拉起新进程失败: %v，请手动重启服务", err)
		os.Exit(1)
	}
	log.Println("更新完成: 已在后台拉起新版本进程，旧进程退出")
	os.Exit(0)
}
