//go:build linux
// +build linux

package systrust

import (
	"os"
	"os/exec"
	"path/filepath"
)

const (
	certDir  = "/usr/local/share/ca-certificates"
	certFile = "hosts++_root_ca.crt"
)

func removeOldSystemCertImpl() error {
	// 删除旧证书文件
	err := os.Remove(filepath.Join(certDir, certFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// 更新系统证书存储
	cmd := exec.Command("update-ca-certificates")
	return cmd.Run()
}

func addNewSystemCertImpl(certPEM []byte) error {
	// 确保证书目录存在
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}

	// 写入新证书
	if err := os.WriteFile(filepath.Join(certDir, certFile), certPEM, 0644); err != nil {
		return err
	}

	// 更新系统证书存储
	cmd := exec.Command("update-ca-certificates")
	return cmd.Run()
}
