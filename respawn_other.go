//go:build !linux

package main

import "log"

func restartAfterUpdate() {
	log.Println("更新完成，请手动重启服务以加载新版本")
}
