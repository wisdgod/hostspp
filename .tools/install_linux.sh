#!/bin/bash

CERT_PATH="rootCA.pem"
CERT_DEST="/usr/local/share/ca-certificates/rootCA.crt"

# 将证书复制到受信任的CA文件夹并更新CA证书
sudo cp "$CERT_PATH" "$CERT_DEST"
sudo update-ca-certificates

if [ $? -eq 0 ]; then
    echo "证书已成功安装."
else
    echo "证书安装失败."
fi
