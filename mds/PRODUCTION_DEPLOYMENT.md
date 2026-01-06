# Production Deployment Guide

## 🚀 Quick Start

### 1. Prerequisites
- Docker & Docker Compose installed
- Domain name configured (optional but recommended)
- SSL certificates (optional, recommended for production)

### 2. Initial Setup

```bash
# Clone the repository
git clone <your-repo>
cd ESP

# Create production environment file
cp .env.production.example .env.production

# Edit .env.production and change ALL sensitive values
nano .env.production  # or use your preferred editor
```

### 3. Generate Secrets

```bash
# Generate SECRET_KEY
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"

# Generate strong database password
python -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(32))"
```

### 4. Build and Deploy

```bash
# Build all containers
docker-compose -f docker-compose.production.yml build

# Start services
docker-compose -f docker-compose.production.yml up -d

# Check health
docker-compose -f docker-compose.production.yml ps
```

### 5. Initialize Database

```bash
# Run migrations
docker exec -it esp_api python manage_migrations.py upgrade

# Verify database
docker exec -it esp_api python manage_migrations.py current
```

### 6. Verify Deployment

```bash
# Check API health
curl http://localhost:5000/health/ready

# Check frontend
curl http://localhost/

# View logs
docker-compose -f docker-compose.production.yml logs -f
```

## 📊 Monitoring

### View Queue Dashboard
```bash
# Start with monitoring profile
docker-compose -f docker-compose.production.yml --profile monitoring up -d

# Access dashboard at http://localhost:9181
```

### Check Logs
```bash
# All services
docker-compose -f docker-compose.production.yml logs -f

# Specific service
docker-compose -f docker-compose.production.yml logs -f api_gateway
docker-compose -f docker-compose.production.yml logs -f worker
docker-compose -f docker-compose.production.yml logs -f frontend
```

### Health Checks
```bash
# API readiness
curl http://localhost:5000/health/ready

# Detailed health info
curl http://localhost:5000/health/detailed

# Database status
docker exec -it esp_postgres pg_isready -U postgres
```

## 🔒 Security Hardening

### 1. Use SSL/TLS

Configure a reverse proxy (nginx/traefik) with Let's Encrypt:

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass http://localhost:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 2. Firewall Configuration

```bash
# Allow only necessary ports
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS
ufw allow 22/tcp   # SSH
ufw enable
```

### 3. Environment Isolation

```bash
# Never commit .env.production
echo ".env.production" >> .gitignore

# Set proper permissions
chmod 600 .env.production
```

### 4. Database Security

```bash
# Connect to PostgreSQL
docker exec -it esp_postgres psql -U postgres -d vulnerability_scanner

# Check current connections
SELECT * FROM pg_stat_activity;

# Set connection limits
ALTER ROLE postgres CONNECTION LIMIT 50;
```

## 🔄 Updates & Maintenance

### Update Application

```bash
# Pull latest code
git pull origin main

# Rebuild containers
docker-compose -f docker-compose.production.yml build

# Apply migrations
docker exec -it esp_api python manage_migrations.py upgrade

# Restart services
docker-compose -f docker-compose.production.yml restart
```

### Backup Database

```bash
# Backup
docker exec -it esp_postgres pg_dump -U postgres vulnerability_scanner > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore
cat backup_20251127_120000.sql | docker exec -i esp_postgres psql -U postgres vulnerability_scanner
```

### Clean Up

```bash
# Remove stopped containers
docker-compose -f docker-compose.production.yml down

# Remove volumes (DANGER: deletes data!)
docker-compose -f docker-compose.production.yml down -v

# Clean old images
docker image prune -a
```

## 📈 Scaling

### Horizontal Scaling (Multiple Workers)

```bash
# Scale workers
docker-compose -f docker-compose.production.yml up -d --scale worker=3

# Verify
docker-compose -f docker-compose.production.yml ps
```

### Database Connection Pooling

Already configured in `config/database.py`:
- Min connections: 1
- Max connections: 10
- Adjust based on load

## 🐛 Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose -f docker-compose.production.yml logs <service_name>

# Check container status
docker-compose -f docker-compose.production.yml ps

# Restart specific service
docker-compose -f docker-compose.production.yml restart <service_name>
```

### Database Connection Issues

```bash
# Test database connectivity
docker exec -it esp_api python -c "from config.database import test_connection; print('OK' if test_connection() else 'FAILED')"

# Check database logs
docker logs esp_postgres
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Check queue status
curl http://localhost:9181  # If monitoring profile enabled

# Check database connections
docker exec -it esp_postgres psql -U postgres -d vulnerability_scanner -c "SELECT count(*) FROM pg_stat_activity;"
```

## 📝 Environment Variables Reference

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `POSTGRES_PASSWORD` | Database password | - | ✅ |
| `SECRET_KEY` | Flask secret key | - | ✅ |
| `NVD_API_KEY` | NVD API key | - | ⚠️ Recommended |
| `FLASK_ENV` | Environment | `production` | ✅ |
| `ENABLE_RATE_LIMITING` | Rate limiting | `false` | ❌ |
| `ENABLE_RAG_CHATBOT` | AI chatbot | `true` | ❌ |
| `API_PORT` | API port | `5000` | ❌ |
| `FRONTEND_PORT` | Frontend port | `80` | ❌ |

## 🔗 URLs

- **Frontend**: http://localhost (or your domain)
- **API**: http://localhost:5000
- **Health Check**: http://localhost:5000/health/ready
- **RQ Dashboard**: http://localhost:9181 (with --profile monitoring)

## 📞 Support

For issues:
1. Check logs: `docker-compose logs`
2. Review health endpoints: `/health/ready`, `/health/detailed`
3. Check database migrations: `python manage_migrations.py current`
4. Verify environment variables in `.env.production`

## ⚠️ Production Checklist

Before going live:

- [ ] Changed all default passwords
- [ ] Generated new SECRET_KEY
- [ ] Configured SSL/TLS certificates
- [ ] Set up automated backups
- [ ] Configured monitoring/alerting
- [ ] Tested database migrations
- [ ] Reviewed security headers
- [ ] Configured firewall rules
- [ ] Set up logging aggregation
- [ ] Tested disaster recovery
- [ ] Documented runbook procedures
- [ ] Load tested application
- [ ] Set up health check monitoring
