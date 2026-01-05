# Dependency Installation Fixes

## Issues Fixed

### 1. `get_session` Undefined Errors (alerts_service.py) ✅ **FIXED**
**Problem:** Three methods in `alerts_service.py` were calling undefined `get_session()` function.

**Solution:** Replaced all instances with proper SQLAlchemy session creation pattern:
```python
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
import os

db_url = os.getenv(
    'DATABASE_URL',
    'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'
)
engine = create_engine(db_url)
session = Session(engine)
# ... use session ...
session.close()
engine.dispose()
```

**Files Changed:**
- `backend/services/threat_feeds/alerts_service.py` (Lines 158, 219, 356)

---

### 2. Missing Python Packages

#### ChromaDB (intelligence_layer/rag/indexing.py)
**Status:** ⚠️ In requirements.txt but may not be installed

**Install:**
```powershell
cd backend
pip install chromadb>=0.4.24
```

**Verify:**
```powershell
python -c "import chromadb; print('ChromaDB installed:', chromadb.__version__)"
```

#### Python GVM (services/adapters/gvm_scan_script.py)
**Status:** ❌ Missing from requirements.txt

**Fix Applied:** Added to requirements.txt:
```
python-gvm>=23.0.0
```

**Install:**
```powershell
cd backend
pip install python-gvm>=23.0.0
```

**Verify:**
```powershell
python -c "import gvm; print('GVM installed')"
```

---

### 3. Frontend CSS Warnings (Tailwind) ℹ️ **EXPECTED**

**Issue:** VS Code shows "Unknown at rule @tailwind" warnings

**Explanation:** These are **not errors** - they're valid Tailwind CSS directives:
```css
@tailwind base;
@tailwind components;
@tailwind utilities;
@apply flex items-center;
```

**Why it happens:** CSS linter doesn't recognize Tailwind PostCSS syntax.

**Fix (Optional):**
Add to `.vscode/settings.json`:
```json
{
  "css.lint.unknownAtRules": "ignore"
}
```

---

### 4. TypeScript Unused Variables ℹ️ **MINOR**

**Files:** `frontend/src/pages/CVEDetailPage.tsx`

**Warnings:**
- `parseCVSSVector` (line 105)
- `explanations` (line 108)
- `getMetricLabel` (line 166)

**Fix:** Remove unused variables or prefix with underscore:
```typescript
const _parseCVSSVector = ... // Indicates intentionally unused
```

---

## Quick Installation Commands

### Install All Missing Dependencies
```powershell
cd "d:\New folder (2)\backend"
pip install -r requirements.txt
```

### Verify Critical Packages
```powershell
# ChromaDB
python -c "import chromadb; print('✅ ChromaDB:', chromadb.__version__)"

# GVM
python -c "import gvm; print('✅ GVM: Installed')"

# SQLAlchemy
python -c "import sqlalchemy; print('✅ SQLAlchemy:', sqlalchemy.__version__)"
```

---

## Summary

| Issue | Severity | Status | Action Required |
|-------|----------|--------|-----------------|
| `get_session` undefined | 🔴 Critical | ✅ Fixed | None - code updated |
| ChromaDB import | 🟠 High | ⚠️ Check | Run `pip install chromadb` |
| GVM import | 🟡 Medium | ⚠️ Added | Run `pip install python-gvm` |
| Tailwind CSS warnings | 🟢 Low | ℹ️ Expected | Optional - ignore warning |
| TypeScript unused vars | 🟢 Low | ℹ️ Minor | Optional - cleanup |

---

## Next Steps

1. **Restart Backend Services** (to load fixed code):
   ```powershell
   Get-Process python | Stop-Process -Force
   cd backend
   python start_worker.py  # Terminal 1
   python run_api.py       # Terminal 2
   ```

2. **Install Missing Packages:**
   ```powershell
   pip install chromadb python-gvm
   ```

3. **Verify Installation:**
   ```powershell
   python -c "import chromadb, gvm; print('All dependencies OK')"
   ```

---

**Date:** November 3, 2025  
**Fixed By:** AI Assistant - Dependency Resolution
