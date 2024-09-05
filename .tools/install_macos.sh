#!/bin/bash

CERT_PATH="rootCA.pem"

# 安装证书到系统钥匙串
sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "$CERT_PATH"

if [ $? -eq 0 ]; then
    echo "证书已成功安装."
else
    echo "证书安装失败."
fi
