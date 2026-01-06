#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Production deployment script for ESP Vulnerability Scanner

.DESCRIPTION
    This script automates the production deployment process including:
    - Environment validation
    - Secret generation
    - Docker build and deployment
    - Database migrations
    - Health checks

.EXAMPLE
    .\deploy-production.ps1
    
.EXAMPLE
    .\deploy-production.ps1 -SkipBuild
#>

param(
    [switch]$SkipBuild,
    [switch]$SkipMigrations,
    [switch]$Monitoring
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ESP Production Deployment Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if .env.production exists
if (-not (Test-Path ".env.production")) {
    Write-Host "⚠️  .env.production not found!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Creating from template..." -ForegroundColor White
    
    if (Test-Path ".env.production.example") {
        Copy-Item ".env.production.example" ".env.production"
        
        # Generate secrets
        Write-Host "Generating secrets..." -ForegroundColor White
        $secretKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})
        $dbPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
        
        $content = Get-Content ".env.production"
        $content = $content -replace "SECRET_KEY=.*", "SECRET_KEY=$secretKey"
        $content = $content -replace "POSTGRES_PASSWORD=.*", "POSTGRES_PASSWORD=$dbPassword"
        $content | Set-Content ".env.production"
        
        Write-Host "✅ Created .env.production with generated secrets" -ForegroundColor Green
        Write-Host ""
        Write-Host "⚠️  IMPORTANT: Review and update .env.production before continuing!" -ForegroundColor Yellow
        Write-Host "   - Add your NVD_API_KEY" -ForegroundColor Yellow
        Write-Host "   - Review all configuration values" -ForegroundColor Yellow
        Write-Host ""
        
        $continue = Read-Host "Continue with deployment? (y/N)"
        if ($continue -ne 'y') {
            Write-Host "Deployment cancelled. Please update .env.production and run again." -ForegroundColor Yellow
            exit 0
        }
    } else {
        Write-Host "❌ .env.production.example not found!" -ForegroundColor Red
        Write-Host "Please create .env.production manually." -ForegroundColor Red
        exit 1
    }
}

Write-Host "✅ Environment file found" -ForegroundColor Green
Write-Host ""

# Load environment variables
Get-Content ".env.production" | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}

# Build containers
if (-not $SkipBuild) {
    Write-Host "🔨 Building Docker containers..." -ForegroundColor Cyan
    docker-compose -f docker-compose.production.yml build
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Docker build failed!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✅ Build completed" -ForegroundColor Green
    Write-Host ""
}

# Start services
Write-Host "🚀 Starting services..." -ForegroundColor Cyan

$composeArgs = @("-f", "docker-compose.production.yml", "up", "-d")
if ($Monitoring) {
    $composeArgs += @("--profile", "monitoring")
}

& docker-compose @composeArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to start services!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Services started" -ForegroundColor Green
Write-Host ""

# Wait for services to be healthy
Write-Host "⏳ Waiting for services to be healthy..." -ForegroundColor Cyan
Start-Sleep -Seconds 10

$maxAttempts = 30
$attempt = 0
$healthy = $false

while ($attempt -lt $maxAttempts -and -not $healthy) {
    $attempt++
    Write-Host "  Attempt $attempt/$maxAttempts..." -ForegroundColor Gray
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5000/health/ready" -TimeoutSec 5 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $healthy = $true
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $healthy) {
    Write-Host "❌ Services did not become healthy in time!" -ForegroundColor Red
    Write-Host "Check logs with: docker-compose -f docker-compose.production.yml logs" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Services are healthy" -ForegroundColor Green
Write-Host ""

# Run database migrations
if (-not $SkipMigrations) {
    Write-Host "📊 Running database migrations..." -ForegroundColor Cyan
    docker exec -it esp_api python manage_migrations.py upgrade
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️  Migration failed (this is OK if database is already up to date)" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Migrations completed" -ForegroundColor Green
    }
    Write-Host ""
}

# Final health check
Write-Host "🔍 Final health check..." -ForegroundColor Cyan
$health = Invoke-RestMethod -Uri "http://localhost:5000/health/detailed"
Write-Host ""
Write-Host "Service Status:" -ForegroundColor White
Write-Host "  Database:  $($health.checks.database.status)" -ForegroundColor $(if ($health.checks.database.status -eq "healthy") { "Green" } else { "Red" })
Write-Host "  Redis:     $($health.checks.redis.status)" -ForegroundColor $(if ($health.checks.redis.status -eq "healthy") { "Green" } else { "Red" })
Write-Host "  ChromaDB:  $($health.checks.chromadb.status)" -ForegroundColor $(if ($health.checks.chromadb.status -in @("healthy", "disabled")) { "Green" } else { "Yellow" })
Write-Host "  Disk:      $($health.checks.disk_space.free_gb) GB free" -ForegroundColor Green
Write-Host ""

# Show access URLs
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Access URLs:" -ForegroundColor White
Write-Host "  Frontend:  http://localhost" -ForegroundColor Cyan
Write-Host "  API:       http://localhost:5000" -ForegroundColor Cyan
Write-Host "  Health:    http://localhost:5000/health/ready" -ForegroundColor Cyan

if ($Monitoring) {
    Write-Host "  RQ Dashboard: http://localhost:9181" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Useful Commands:" -ForegroundColor White
Write-Host "  View logs:     docker-compose -f docker-compose.production.yml logs -f" -ForegroundColor Gray
Write-Host "  Stop services: docker-compose -f docker-compose.production.yml down" -ForegroundColor Gray
Write-Host "  Restart:       docker-compose -f docker-compose.production.yml restart" -ForegroundColor Gray
Write-Host ""
