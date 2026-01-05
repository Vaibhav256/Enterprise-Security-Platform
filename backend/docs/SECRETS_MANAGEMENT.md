# Secrets Management Guide

## Overview

This document outlines the secrets management practices for the NTRO Vulnerability Scanner. Proper secrets management is **CRITICAL** for security.

## Table of Contents

1. [Environment Variables](#environment-variables)
2. [Local Development Setup](#local-development-setup)
3. [Secret Generation](#secret-generation)
4. [Production Deployment](#production-deployment)
5. [Secret Rotation](#secret-rotation)
6. [Git Security](#git-security)
7. [Secrets Detection Tools](#secrets-detection-tools)
8. [Troubleshooting](#troubleshooting)

---

## Environment Variables

### Required Secrets

The following environment variables **MUST** be set in production:

#### Application Security
- `SECRET_KEY` - Flask session secret (64+ hex characters)
- `JWT_SECRET_KEY` - JWT token signing key (64+ hex characters)
- `API_KEY` - API authentication key

#### Database
- `POSTGRES_PASSWORD` - PostgreSQL database password
- `DATABASE_URL` - Full PostgreSQL connection string

#### Security Tools
- `GVM_PASSWORD` - OpenVAS/GVM scanner password
- `NVD_API_KEY` - National Vulnerability Database API key (optional but recommended)

#### Email/Notifications
- `SMTP_PASSWORD` - Email server password/app-specific password

### Optional Secrets

- `REDIS_PASSWORD` - Redis authentication (recommended in production)
- `SENTRY_DSN` - Error tracking service
- `DATADOG_API_KEY` - Monitoring service

---

## Local Development Setup

### Step 1: Copy Environment Template

```bash
cd backend
cp .env.example .env
```

### Step 2: Generate Secrets

```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Generate JWT_SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Generate API_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Step 3: Edit .env File

Open `.env` and fill in the generated values:

```bash
SECRET_KEY=<your-generated-secret-key>
JWT_SECRET_KEY=<your-generated-jwt-secret>
API_KEY=<your-generated-api-key>

# Set OpenVAS password
GVM_PASSWORD=YourStrongPassword123!

# Database credentials
POSTGRES_PASSWORD=your_local_db_password
```

### Step 4: Verify Configuration

```bash
# Check that .env is NOT tracked by git
git status

# Verify environment loads correctly
python -c "from config.config import Config; print('Config OK')"
```

---

## Secret Generation

### Strong Secret Requirements

| Secret Type | Minimum Length | Character Requirements |
|------------|---------------|----------------------|
| SECRET_KEY | 64 hex chars | Hex digits (0-9, a-f) |
| JWT_SECRET_KEY | 64 hex chars | Hex digits (0-9, a-f) |
| API_KEY | 32 chars | URL-safe base64 |
| Database Password | 16 chars | Mixed case + numbers + symbols |
| GVM Password | 12 chars | Mixed case + numbers |

### Generation Methods

#### Python (Recommended)

```python
import secrets

# Method 1: Hex token (for SECRET_KEY, JWT_SECRET_KEY)
secret = secrets.token_hex(32)  # 64 characters
print(secret)

# Method 2: URL-safe token (for API_KEY)
api_key = secrets.token_urlsafe(32)
print(api_key)

# Method 3: Random password with symbols
import string
import random
chars = string.ascii_letters + string.digits + string.punctuation
password = ''.join(random.SystemRandom().choice(chars) for _ in range(16))
print(password)
```

#### OpenSSL (Alternative)

```bash
# Generate hex secret
openssl rand -hex 32

# Generate base64 secret
openssl rand -base64 32
```

#### PowerShell (Windows)

```powershell
# Generate random hex
-join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })

# Generate random password
-join ((1..16) | ForEach-Object { 
    [char]((33..126) | Get-Random)
})
```

---

## Production Deployment

### Environment-Specific Files

**NEVER** use the same secrets across environments!

Create separate files:
- `.env.development` - Local development
- `.env.staging` - Staging environment
- `.env.production` - Production (NEVER commit!)

### Loading Environment Files

```bash
# Development
export $(grep -v '^#' .env.development | xargs)

# Production
export $(grep -v '^#' .env.production | xargs)
```

### Production Checklist

- [ ] All default secrets changed
- [ ] Secrets generated with cryptographically secure methods
- [ ] Database password: 16+ characters
- [ ] `JWT_COOKIE_SECURE=True` (requires HTTPS)
- [ ] `FLASK_DEBUG=False`
- [ ] `FLASK_ENV=production`
- [ ] CORS restricted to specific domains
- [ ] Redis authentication enabled
- [ ] SSL/TLS for database connections
- [ ] `.env.production` NOT in version control
- [ ] Secrets stored in secrets manager (Vault, AWS Secrets Manager, etc.)

### Secrets Management Services

#### HashiCorp Vault

```python
import hvac

client = hvac.Client(url='http://vault:8200', token='your-token')
secret = client.secrets.kv.v2.read_secret_version(path='ntro/prod')
GVM_PASSWORD = secret['data']['data']['gvm_password']
```

#### AWS Secrets Manager

```python
import boto3
from botocore.exceptions import ClientError

def get_secret(secret_name):
    client = boto3.client('secretsmanager', region_name='us-east-1')
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    except ClientError as e:
        raise e

secrets = get_secret('ntro/production')
```

#### Azure Key Vault

```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://ntro-vault.vault.azure.net/", 
                      credential=credential)
GVM_PASSWORD = client.get_secret("gvm-password").value
```

---

## Secret Rotation

### Rotation Schedule

| Secret Type | Rotation Frequency | Priority |
|------------|-------------------|----------|
| JWT_SECRET_KEY | 90 days | HIGH |
| SECRET_KEY | 90 days | HIGH |
| Database Password | 90 days | CRITICAL |
| GVM_PASSWORD | 90 days | MEDIUM |
| API_KEY | 180 days | MEDIUM |
| NVD_API_KEY | When compromised | LOW |

### Rotation Procedure

1. **Generate New Secret**
   ```bash
   NEW_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
   echo "New secret: $NEW_SECRET"
   ```

2. **Update Environment**
   ```bash
   # Add to .env
   JWT_SECRET_KEY=$NEW_SECRET
   ```

3. **Restart Application**
   ```bash
   sudo systemctl restart ntro-api
   ```

4. **Verify Functionality**
   ```bash
   # Test API authentication
   curl -X POST http://localhost:5000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "test"}'
   ```

5. **Monitor for Issues**
   - Check application logs
   - Verify user sessions
   - Test JWT token generation/validation

6. **Document Rotation**
   - Record date in secret management log
   - Update documentation
   - Notify team

### Database Password Rotation

```bash
# 1. Connect to PostgreSQL
psql -U postgres

# 2. Change password
ALTER USER postgres PASSWORD 'new_secure_password_here';

# 3. Update .env
POSTGRES_PASSWORD=new_secure_password_here
DATABASE_URL=postgresql://postgres:new_secure_password_here@localhost:5432/vulnerability_scanner

# 4. Restart services
sudo systemctl restart ntro-api ntro-worker
```

---

## Git Security

### Pre-Commit Hooks

Install **git-secrets** to prevent committing secrets:

#### Installation (Linux/WSL)

```bash
cd /tmp
git clone https://github.com/awslabs/git-secrets.git
cd git-secrets
sudo make install

# Initialize in repository
cd /path/to/ntro
git secrets --install
git secrets --register-aws
```

#### Installation (Windows - Git Bash)

```bash
git clone https://github.com/awslabs/git-secrets.git
cd git-secrets
./install.sh

cd /d/New\ folder\ \(2\)
git secrets --install
```

#### Configure Patterns

```bash
# Add custom patterns
git secrets --add 'SECRET_KEY.*=.*[a-f0-9]{64}'
git secrets --add 'JWT_SECRET_KEY.*=.*[a-f0-9]{64}'
git secrets --add 'GVM_PASSWORD.*=.*\S+'
git secrets --add 'password.*=.*["\'].+["\']'
git secrets --add --allowed '.env.example'
```

#### Test Hook

```bash
# Try to commit a secret (should fail)
echo "SECRET_KEY=abc123..." >> test_secret.txt
git add test_secret.txt
git commit -m "Test secret detection"  # Should be blocked!
```

### Manual Secret Scan

Scan repository for existing secrets:

```bash
# Using git-secrets
git secrets --scan

# Using gitleaks (alternative)
docker run -v ${PWD}:/path zricethezav/gitleaks:latest detect --source="/path" -v

# Using truffleHog
docker run --rm -v ${PWD}:/repo trufflesecurity/trufflehog:latest filesystem /repo
```

### Removing Committed Secrets

If a secret was committed:

#### 1. Rotate the Secret Immediately
```bash
# Generate new secret
NEW_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")

# Update .env
sed -i "s/SECRET_KEY=.*/SECRET_KEY=$NEW_SECRET/" .env
```

#### 2. Remove from Git History
```bash
# Using BFG Repo-Cleaner (recommended)
java -jar bfg.jar --replace-text passwords.txt

# Using git filter-branch (alternative)
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch .env" \
  --prune-empty --tag-name-filter cat -- --all

# Force push (⚠️ DANGEROUS - coordinate with team!)
git push origin --force --all
```

#### 3. Notify Team
- Inform all team members of the breach
- Rotate ALL affected secrets
- Review access logs for unauthorized use

---

## Secrets Detection Tools

### Recommended Tools

1. **git-secrets** (Pre-commit hook)
   - Pros: Lightweight, fast, customizable
   - Cons: Pattern-based, may miss complex secrets

2. **Gitleaks** (CI/CD scanner)
   ```bash
   # Docker
   docker run -v ${PWD}:/path zricethezav/gitleaks:latest detect --source="/path"
   
   # GitHub Action
   - uses: gitleaks/gitleaks-action@v2
   ```

3. **TruffleHog** (Deep history scan)
   ```bash
   docker run --rm -v ${PWD}:/repo trufflesecurity/trufflehog:latest \
     filesystem /repo --json
   ```

4. **detect-secrets** (Baseline approach)
   ```bash
   pip install detect-secrets
   detect-secrets scan > .secrets.baseline
   detect-secrets audit .secrets.baseline
   ```

### GitHub Actions Workflow

Create `.github/workflows/secrets-scan.yml`:

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Troubleshooting

### Issue: "SECRET_KEY is set to default value"

**Cause**: `.env` file not loaded or SECRET_KEY not set

**Solution**:
```bash
# Check if .env exists
ls -la .env

# Verify SECRET_KEY is set
grep SECRET_KEY .env

# Generate new secret
python -c "import secrets; print(secrets.token_hex(32))" >> .env
```

### Issue: "GVM_PASSWORD not set - OpenVAS scans will fail"

**Cause**: GVM_PASSWORD environment variable missing

**Solution**:
```bash
# Add to .env
echo "GVM_PASSWORD=YourGvmPassword123!" >> .env

# Restart application
sudo systemctl restart ntro-api
```

### Issue: JWT tokens invalid after restart

**Cause**: JWT_SECRET_KEY changed, invalidating existing tokens

**Solution**:
- This is **EXPECTED** behavior when rotating JWT secrets
- Users must re-authenticate
- Consider grace period with dual-key validation for rotation

### Issue: Database connection failed

**Cause**: Incorrect DATABASE_URL or POSTGRES_PASSWORD

**Solution**:
```bash
# Test database connection
psql "$DATABASE_URL"

# Verify password
psql -U postgres -h localhost -d vulnerability_scanner

# Update .env with correct credentials
```

### Issue: ".env file tracked by git"

**Cause**: .env added before .gitignore

**Solution**:
```bash
# Remove from git (keep local file)
git rm --cached .env

# Verify .gitignore includes .env
grep "^\.env$" .gitignore

# Commit removal
git commit -m "Remove .env from version control"
```

---

## Security Audit Checklist

Regular security audits (quarterly):

- [ ] All production secrets rotated in last 90 days
- [ ] No `.env` files in git repository
- [ ] git-secrets pre-commit hook installed
- [ ] CI/CD pipeline includes secret scanning
- [ ] All team members trained on secrets management
- [ ] Secret rotation documented
- [ ] Monitoring for secret exposure (GitHub, PasteBin, etc.)
- [ ] Secrets manager in use (Vault, AWS, Azure)
- [ ] Database connections use SSL/TLS
- [ ] Redis authentication enabled
- [ ] HTTPS enforced in production
- [ ] JWT cookies secure and httpOnly
- [ ] No hardcoded secrets in code
- [ ] `.env.example` up to date
- [ ] Access logs reviewed for anomalies

---

## References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [git-secrets GitHub](https://github.com/awslabs/git-secrets)
- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [12 Factor App: Config](https://12factor.net/config)
- [NIST SP 800-53: Secret Management](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

**Last Updated**: January 2025  
**Maintained By**: NTRO Security Team  
**Review Frequency**: Quarterly
