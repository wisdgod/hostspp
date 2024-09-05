@ECHO OFF

REM 确保日志目录存在
IF NOT EXIST "%~dp0temp\logs" (
    MKDIR "%~dp0temp\logs"
)

REM 编译Go程序到临时目录
go build -a -o "%~dp0temp\hosts++.exe" "%~dp0..\cmd\."

REM 复制配置文件到临时目录
COPY "%~dp0..\config.yaml" "%~dp0temp\config.yaml"

REM 在当前控制台窗口中启动程序，并等待其完成
START /B /WAIT "%~dp0temp\hosts++.exe"