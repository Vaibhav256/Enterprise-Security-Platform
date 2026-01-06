# Dynamic Timeout System

## Overview
All scan adapters now use dynamic, high timeouts that allow scans to run until natural completion rather than being terminated prematurely by hardcoded time limits.

## Implementation

### Adapter-Specific Timeouts

| Tool | Default Timeout | Hours | Use Case |
|------|----------------|-------|----------|
| **Nmap** | 21600s | 6.0h | Port scanning, service detection, OS fingerprinting |
| **Nikto** | 7200s | 2.0h | Web server scanning (base default) |
| **OpenVAS** | 28800s | 8.0h | Comprehensive vulnerability scanning |
| **Nuclei** | 14400s | 4.0h | Template-based vulnerability detection |

### Nikto Advanced Timeouts
Nikto has additional dynamic logic based on scan type:

```python
# User can override
options = {"timeout": 7200}  # 2 hours custom

# Or disable timeout completely
options = {"timeout": 0}  # 24 hour safety maximum

# Auto-calculated based on scan type
- Basic:         5400s  (1.5 hours)
- Comprehensive: 10800s (3 hours)
- Full:          21600s (6 hours)
```

## Key Features

### 1. **Natural Completion**
Scans are no longer killed after arbitrary time limits. They run until:
- The tool naturally completes
- The target is fully scanned
- An error occurs
- User manually cancels

### 2. **Safety Limits**
High timeouts prevent infinite runs:
- **Nikto Full**: 6 hours (previously 15 minutes)
- **OpenVAS**: 8 hours (previously 2 hours)
- **Nmap**: 6 hours (previously 10 minutes)
- **Nuclei**: 4 hours (previously 5 minutes)

### 3. **Real-Time Progress**
Progress monitoring thread updates every 30 seconds:
```
0:00  - 30% "Executing nikto scan..."
0:30  - 35% "nikto scan in progress..."
2:00  - 43% "nikto scan running... (2 min elapsed)"
15:00 - 55% "nikto scan running... (15 min - large target, please wait)"
```

### 4. **User Override**
Users can customize timeout behavior:
```python
# Custom timeout
scan_options = {"timeout": 3600}  # 1 hour

# Disable timeout (24h max)
scan_options = {"timeout": 0}
```

## Code Locations

### Base Adapter
**File:** `services/adapters/base_adapter.py`
- Line 237: `get_default_timeout()` - 2 hours base default

### Individual Adapters
1. **Nmap** - `services/adapters/nmap_adapter.py` (Line 66)
   - 6 hour timeout for comprehensive scans

2. **Nikto** - `services/adapters/nikto_adapter.py` (Line 247)
   - Dynamic logic: 1.5h / 3h / 6h based on scan type
   - User override support
   - 24h safety maximum

3. **OpenVAS** - `services/adapters/openvas_adapter.py` (Line 87)
   - 8 hour timeout for vulnerability scans

4. **Nuclei** - `services/adapters/nuclei_adapter.py` (Line 94)
   - 4 hour timeout for template-based scans

### Progress Monitoring
**File:** `services/scan_orchestrator/tasks.py` (Line 240)
- Real-time updates every 30 seconds
- Gradual progress increments (5% → 3% → 2% → 1%)
- Time-aware status messages
- Auto-caps at 65%

## Benefits

### Before
```
❌ Nikto scan timeout: 15 minutes
❌ Large sites killed prematurely
❌ "Command timed out after 600 seconds"
❌ Scans fail before completion
```

### After
```
✅ Nikto full scan: 6 hours maximum
✅ Scans complete naturally
✅ "Scan completed in 47.5 minutes"
✅ Large sites fully scanned
```

## Examples

### Successful Long-Running Scan
```
2024-12-11 14:30:00 - Starting nikto full scan of sspu.ac.in
2024-12-11 14:30:00 - Full scan mode - allowing up to 6.0 hours for completion
2024-12-11 14:30:00 - 🚀 Starting scan - will run until completion (max: 6.0 hours)
2024-12-11 14:30:30 - Progress: 35% - nikto scan in progress...
2024-12-11 14:32:00 - Progress: 43% - nikto scan running... (2 min elapsed)
2024-12-11 15:17:30 - Progress: 65% - nikto scan running... (47 min - large target, please wait)
2024-12-11 15:17:47 - ✅ Nikto scan completed in 2847.3 seconds (47.5 minutes)
```

### User Override
```python
# REST API request
POST /api/scans/create
{
  "target": "sspu.ac.in",
  "tool": "nikto",
  "scan_type": "full",
  "options": {
    "timeout": 0  # Disable timeout (24h max)
  }
}
```

## Migration Notes

### Old Behavior
- Nikto: 900s (15 min) → Killed large scans
- Nmap: 600s (10 min) → Insufficient for OS detection
- OpenVAS: 7200s (2h) → Sometimes too short
- Nuclei: 300s (5 min) → Default base timeout

### New Behavior
- Nikto: 21600s (6h full) → Natural completion
- Nmap: 21600s (6h) → Comprehensive scans finish
- OpenVAS: 28800s (8h) → Vulnerability scans complete
- Nuclei: 14400s (4h) → Template scans finish

## Testing

Verified all adapters load successfully:
```bash
$ python
>>> from services.adapters.nmap_adapter import NmapAdapter
>>> from services.adapters.nikto_adapter import NiktoAdapter
>>> from services.adapters.openvas_adapter import OpenVASAdapter
>>> from services.adapters.nuclei_adapter import NucleiAdapter
>>> # All import without errors ✓
```

## Troubleshooting

### Scan Still Timing Out?
1. Check scan options: `options.get("timeout")`
2. Verify adapter timeout: `adapter.get_default_timeout()`
3. Check logs for actual execution time
4. Consider setting `timeout=0` for very large targets

### Progress Not Updating?
1. Verify progress thread started (logs show "Progress: X%")
2. Check 30-second interval is working
3. Ensure scan is still running (not completed/failed)

### Scan Running Too Long?
1. Manually cancel via API: `POST /api/scans/{id}/cancel`
2. Check if target is responsive
3. Verify scan isn't stuck (check logs for progress)
4. Consider reducing scan scope or options

## Future Enhancements

Potential improvements:
- [ ] Per-target timeout estimation based on size
- [ ] Machine learning to predict scan duration
- [ ] Auto-tuning based on historical data
- [ ] Parallel scanning with distributed timeouts
- [ ] User-configurable global timeout limits
