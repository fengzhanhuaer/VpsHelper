param (
    [string]$secret = "",
    [string]$host = "",
    [string]$repo = "fengzhanhuaer/VpsHelper",
    [string]$dir = "C:\VpsProbe",
    [switch]$menu = $false
)

$ErrorActionPreference = "Stop"
$SERVICE_NAME = "VpsProbe"
$BINARY_NAME = "vpsprobe.exe"

function Show-Menu {
    while ($true) {
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host "         VpsProbe 探针管理菜单 (Windows)" -ForegroundColor Cyan
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host "1. 安装/更新 探针服务 (在线下载)"
        Write-Host "2. 离线安装 探针服务 (需从当前目录读取)"
        Write-Host "3. 查看探针运行状态 (Scheduled Task)"
        Write-Host "4. 重启探针服务"
        Write-Host "5. 停止探针服务"
        Write-Host "6. 卸载探针服务及文件"
        Write-Host "0. 退出菜单"
        Write-Host "======================================" -ForegroundColor Cyan
        $choice = Read-Host "请输入对应的数字 [0-6]"
        
        switch ($choice) {
            "1" { return "online" }
            "2" { return "offline" }
            "3" {
                $task = Get-ScheduledTask -TaskName $SERVICE_NAME -ErrorAction SilentlyContinue
                if ($task) {
                    Write-Host "计划任务状态: $($task.State)" -ForegroundColor Green
                } else {
                    Write-Host "未找到名为 $SERVICE_NAME 的计划任务。" -ForegroundColor Yellow
                }
            }
            "4" {
                Stop-ScheduledTask -TaskName $SERVICE_NAME -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                Start-ScheduledTask -TaskName $SERVICE_NAME -ErrorAction SilentlyContinue
                Write-Host "已尝试重启探针服务。" -ForegroundColor Green
            }
            "5" {
                Stop-ScheduledTask -TaskName $SERVICE_NAME -ErrorAction SilentlyContinue
                Write-Host "已停止探针服务。" -ForegroundColor Green
            }
            "6" {
                Unregister-ScheduledTask -TaskName $SERVICE_NAME -Confirm:$false -ErrorAction SilentlyContinue
                Stop-Process -Name "vpsprobe" -Force -ErrorAction SilentlyContinue
                Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "已卸载探针计划任务并删除文件夹。" -ForegroundColor Green
                return "exit"
            }
            "0" { return "exit" }
            default { Write-Host "无效选择，请输入 0-6 之间的数字。" -ForegroundColor Red }
        }
        Write-Host ""
    }
}

$offlineMode = $false

if ($menu) {
    $action = Show-Menu
    if ($action -eq "exit") { exit 0 }
    if ($action -eq "offline") { $offlineMode = $true }
}

if (-not $secret -and $menu) {
    $secret = Read-Host "请输入为您分配的探针节点密钥 (-secret)"
}
if (-not $host -and $menu) {
    $host = Read-Host "请输入主控端访问地址 (-host, 如 https://example.com)"
}

if (-not $secret -or -not $host) {
    Write-Host "错误：安装探针必须提供 -secret 和 -host 参数" -ForegroundColor Red
    Write-Host "例如: irm https://.../install-probe.ps1 | iex ; install-probe.ps1 -secret XXX -host https://..." -ForegroundColor Yellow
    exit 1
}

$hostUrl = $host.TrimEnd("/")
if (-not ($hostUrl.StartsWith("http://") -or $hostUrl.StartsWith("https://"))) {
    $hostUrl = "https://" + $hostUrl
}

# Determine OS Architecture
$arch = $env:PROCESSOR_ARCHITECTURE.ToLower()
$goarch = "amd64"
if ($arch -eq "arm64") { $goarch = "arm64" }
elseif ($arch -eq "x86") { $goarch = "386" }

$asset = "vpsprobe_windows_${goarch}.exe"

# Prepare Directories
if (!(Test-Path -Path "$dir\bin")) { New-Item -ItemType Directory -Force -Path "$dir\bin" | Out-Null }
if (!(Test-Path -Path "$dir\userdata")) { New-Item -ItemType Directory -Force -Path "$dir\userdata" | Out-Null }

$binPath = "$dir\bin\$BINARY_NAME"
$tmpPath = "$binPath.download"

# Stop existing task if running
Unregister-ScheduledTask -TaskName $SERVICE_NAME -Confirm:$false -ErrorAction SilentlyContinue
Stop-Process -Name "vpsprobe" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

if ($offlineMode) {
    $localFile = ""
    if (Test-Path ".\$asset") { $localFile = ".\$asset" }
    elseif (Test-Path ".\vpsprobe.exe") { $localFile = ".\vpsprobe.exe" }
    
    if (-not $localFile) {
        Write-Host "错误：当前目录未找到离线安装包 $asset 或 vpsprobe.exe！" -ForegroundColor Red
        exit 1
    }
    Write-Host "正在使用本地包进行离线安装: $localFile" -ForegroundColor Cyan
    Copy-Item -Path $localFile -Destination $tmpPath -Force
} else {
    $downloadUrl = "$hostUrl/api/probe/latest_binary?os=windows&arch=${goarch}"
    Write-Host "下载探针 Release: $downloadUrl" -ForegroundColor Cyan
    
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpPath -UseBasicParsing -Headers @{ "Authorization" = "Bearer $secret" }
    } catch {
        Write-Host "通过主控代理下载失败，尝试直接从 GitHub 获取..." -ForegroundColor Yellow
        $githubUrl = "https://github.com/$repo/releases/latest/download/$asset"
        Invoke-WebRequest -Uri $githubUrl -OutFile $tmpPath -UseBasicParsing
    }
}

if (-not (Test-Path $tmpPath) -or (Get-Item $tmpPath).Length -lt 1000000) {
    Write-Host "下载的文件看起来无效或太小，下载可能失败。" -ForegroundColor Red
    if (Test-Path $tmpPath) { Remove-Item $tmpPath -Force }
    exit 1
}

$backupPath = "$binPath.backup"
$hasBackup = $false
if (Test-Path $binPath) {
    Write-Host "发现旧版探针，正在备份..." -ForegroundColor Cyan
    Copy-Item -Path $binPath -Destination $backupPath -Force
    $hasBackup = $true
}

Move-Item -Path $tmpPath -Destination $binPath -Force

# Write config file to ensure args are persisted even without arguments in scheduled task if needed, though we will pass them.
$jsonConfig = @{
    Host = $hostUrl
    Secret = $secret
} | ConvertTo-Json
$jsonConfig | Out-File -FilePath "$dir\bin\vpsprobe.json" -Encoding utf8 -Force

# Register Scheduled Task to run on boot, hidden, as SYSTEM or Admin
Write-Host "正在注册系统计划任务以便后台运行..." -ForegroundColor Cyan

$action = New-ScheduledTaskAction -Execute $binPath -WorkingDirectory "$dir\bin"
# Note: we omit arguments in the task action and let the probe read vpsprobe.json
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit 0

$task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings -Description "VpsHelper Probe Node Service"
Register-ScheduledTask -TaskName $SERVICE_NAME -InputObject $task -Force | Out-Null

Write-Host "启动探针服务..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName $SERVICE_NAME

Start-Sleep -Seconds 3
$runningTask = Get-ScheduledTask -TaskName $SERVICE_NAME
if ($runningTask.State -ne 'Running') {
    Write-Host "======================================" -ForegroundColor Red
    Write-Host "错误: 探针进程启动失败！状态为: $($runningTask.State)" -ForegroundColor Red
    if ($hasBackup) {
        Write-Host "正在触发回滚机制..." -ForegroundColor Yellow
        Move-Item -Path $backupPath -Destination $binPath -Force
        Start-ScheduledTask -TaskName $SERVICE_NAME
    }
    Write-Host "======================================" -ForegroundColor Red
    exit 1
} else {
    Write-Host "✅ 探针进程启动/运行健康，安装/更新完成。目录位于: $dir" -ForegroundColor Green
}

if ($menu) { Show-Menu }
