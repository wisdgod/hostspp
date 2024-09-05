@ECHO OFF
CHCP 936 >NUL
SETLOCAL
SET "CERT_PATH=ca.pem"
SET "TITLE=安装根证书到Windows受信任的根证书颁发机构"

REM 安装证书
CERTUTIL -addstore "Root" "%CERT_PATH%"

IF %ERRORLEVEL% EQU 0 (
    ECHO 证书已成功安装.
) ELSE (
    ECHO 证书安装失败.
)
ENDLOCAL
