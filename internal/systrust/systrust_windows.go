//go:build windows
// +build windows

package systrust

import (
	"os"
	"os/exec"
)

func removeOldSystemCertImpl() error {
	// 使用 certutil 删除旧证书
	cmd := exec.Command("certutil", "-delstore", "ROOT", "Hosts++ Root CA")
	return cmd.Run()
}

func addNewSystemCertImpl(certPEM []byte) error {
	// 保存证书到临时文件
	tmpFile, err := os.CreateTemp("", "hosts++_ca_*.crt")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(certPEM); err != nil {
		return err
	}
	tmpFile.Close()

	// 使用 certutil 添加新证书
	cmd := exec.Command("certutil", "-addstore", "ROOT", tmpFile.Name())
	return cmd.Run()
}
