# Define the base directory
$baseDir = "ModifyHostProxyServer/pkg"

# Define the directory structure
$directories = @(
    "proxy/http",
    "proxy/socks",
    "proxy/config",
    "ca",
    "logger"
)

# Define the files and their corresponding package names
$files = @{
    "proxy/http/server.go" = "http"
    "proxy/http/https.go" = "http"
    "proxy/http/handler.go" = "http"
    "proxy/socks/socks4.go" = "socks"
    "proxy/socks/socks5.go" = "socks"
    "proxy/socks/server.go" = "socks"
    "proxy/config/config.go" = "config"
    "proxy/config/rules.go" = "config"
    "ca/ca.go" = "ca"
    "ca/cert.go" = "ca"
    "logger/logger.go" = "logger"
}

# Create directories
foreach ($dir in $directories) {
    $fullPath = Join-Path $baseDir $dir
    if (-not (Test-Path -Path $fullPath)) {
        New-Item -Path $fullPath -ItemType Directory | Out-Null
    }
}

# Create files and write package statements
foreach ($file in $files.GetEnumerator()) {
    $fullPath = Join-Path $baseDir $file.Key
    if (-not (Test-Path -Path $fullPath)) {
        New-Item -Path $fullPath -ItemType File -Force | Out-Null
        $packageStatement = "package " + $file.Value + "`n"
        Set-Content -Path $fullPath -Value $packageStatement
    }
}
