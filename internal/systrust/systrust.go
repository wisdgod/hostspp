package systrust

// 删除旧的系统信任证书（如果存在）
func RemoveOldSystemCert() error {
	return removeOldSystemCertImpl()
}

// 添加新的系统信任 CA 证书
func AddNewSystemCert(certPEM []byte) error {
	return addNewSystemCertImpl(certPEM)
}
