# Quick service startup - no GVM delays
Write-Host "Starting backend services..." -ForegroundColor Cyan

# Start PostgreSQL
Write-Host "  Starting PostgreSQL..." -ForegroundColor Yellow
wsl bash -c 'sudo service postgresql start 2>&1' | Out-Null
Start-Sleep -Seconds 2

# Start Redis
Write-Host "  Starting Redis..." -ForegroundColor Yellow
wsl bash -c 'redis-server --bind 0.0.0.0 --protected-mode no --daemonize yes 2>&1' | Out-Null
Start-Sleep -Seconds 1

# Verify
$redisOk = (wsl bash -c 'redis-cli ping 2>&1') -match "PONG"
$pgOk = (wsl bash -c 'sudo service postgresql status 2>&1') -match "active"

Write-Host "`nStatus:" -ForegroundColor Cyan
if ($pgOk) { Write-Host "  PostgreSQL: OK" -ForegroundColor Green } else { Write-Host "  PostgreSQL: FAILED" -ForegroundColor Red }
if ($redisOk) { Write-Host "  Redis: OK" -ForegroundColor Green } else { Write-Host "  Redis: FAILED" -ForegroundColor Red }

# Get WSL IP
$wslIP = (wsl hostname -I).Trim()
Write-Host "  WSL IP: $wslIP" -ForegroundColor Gray

# Create .env
@"
DATABASE_URL=postgresql://postgres:postgres@$wslIP:5432/vulnerability_scanner
REDIS_HOST=$wslIP
REDIS_PORT=6379
FLASK_ENV=development
FLASK_DEBUG=1
"@ | Out-File .env -Encoding utf8

Write-Host "`nReady to start API and Worker manually" -ForegroundColor Green
Write-Host "Run: python run_api.py" -ForegroundColor White
Write-Host "Run: python start_worker.py" -ForegroundColor White
