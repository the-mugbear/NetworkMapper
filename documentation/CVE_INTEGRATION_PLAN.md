# CVE Database Integration Plan

## Current State (Honest Assessment)

**What we currently have:**
- **Hardcoded vulnerability patterns** in risk assessment service
- **Local VulnerabilityDatabase** with ~10 test CVE records
- **No external API integration** - completely offline
- **Manual CVSS scores** rather than official data
- **Pattern-based detection** instead of comprehensive CVE matching

**What users currently see:**
- Misleading references to "CVE database" in UI
- Progress messages claiming "CVE database lookups"
- **No actual live vulnerability data**

## Real CVE Integration Options

### 1. National Vulnerability Database (NVD) API
**URL:** https://nvd.nist.gov/developers/vulnerabilities
**API Key:** Required (free)
**Rate Limits:** 50 requests per 30 seconds (without key), 5000/30s (with key)
**Data Format:** JSON API with CVE details, CVSS scores, CWE mappings

```python
# Example API call
GET https://services.nvd.nist.gov/rest/json/cves/2.0
?cveId=CVE-2021-44228
&apiKey=YOUR_API_KEY
```

**Pros:**
- Official NIST data
- Comprehensive CVE information
- Free with registration
- JSON API format

**Cons:**
- Rate limits may impact bulk operations
- Requires API key management
- Network dependency

### 2. MITRE CVE API
**URL:** https://cveawg.mitre.org/api/
**API Key:** None required
**Rate Limits:** More permissive
**Data Format:** JSON with basic CVE information

**Pros:**
- No API key required
- Direct from CVE authority
- Good for basic CVE lookups

**Cons:**
- Less detailed than NVD
- No CVSS v3 scores
- Limited search capabilities

### 3. CVE JSON Data Feeds
**URL:** https://github.com/CVEProject/cvelistV5
**Format:** Git repository with JSON files
**Update Method:** Git pulls or archive downloads

**Pros:**
- Complete offline capability
- No rate limits
- Full historical data
- No API key required

**Cons:**
- Large dataset (~GB)
- Requires local processing
- Manual update management

### 4. Commercial Solutions
- **VulnDB** (Rapid7)
- **Vulners API**
- **CVEDetails API**

## Recommended Implementation Strategy

### Phase 1: Integrate Existing VulnerabilityDatabase Service
**Status:** Can implement immediately
**Effort:** Low
**Impact:** Medium

1. Connect risk assessment service to existing VulnerabilityDatabase
2. Add product/version matching logic
3. Use local database for offline operation
4. Seed with more comprehensive test data

### Phase 2: Add NVD API Integration
**Status:** Requires API key
**Effort:** Medium
**Impact:** High

1. Register for NVD API key
2. Implement NVD client service
3. Add CVE lookup and caching
4. Handle rate limiting and retries
5. Update local database with fetched data

### Phase 3: Automated CVE Feed Updates
**Status:** Production feature
**Effort:** High
**Impact:** High

1. Implement scheduled CVE feed processing
2. Add vulnerability matching algorithms
3. Version comparison and impact assessment
4. Delta updates and change tracking

## Implementation Details

### API Key Requirements
- **NVD API Key:** Free registration at https://nvd.nist.gov/developers/request-an-api-key
- **Storage:** Environment variables, secure configuration
- **Fallback:** Local database when API unavailable

### Data Privacy Considerations
- **What data is sent:** Product names, versions (from network scans)
- **What data is received:** CVE details, CVSS scores, vulnerability descriptions
- **No sensitive data:** Host IPs, internal network information not transmitted

### Rate Limiting Strategy
```python
# Example rate limiting implementation
import time
from functools import wraps

def rate_limit(calls_per_period=50, period=30):
    def decorator(func):
        call_times = []

        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            # Remove old calls outside the period
            call_times[:] = [t for t in call_times if now - t < period]

            if len(call_times) >= calls_per_period:
                sleep_time = period - (now - call_times[0])
                time.sleep(sleep_time)

            call_times.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

### Caching Strategy
- **Local database cache** for API responses
- **TTL-based expiration** (daily/weekly updates)
- **Offline fallback** when APIs unavailable
- **Background refresh** for active vulnerabilities

## Immediate Actions

1. **Update UI transparency** ✅ (completed)
2. **Connect existing VulnerabilityDatabase** (in progress)
3. **Document API integration requirements**
4. **Plan NVD API key acquisition**

## Long-term Vision

Transform from hardcoded patterns to comprehensive vulnerability intelligence:
- Real-time CVE lookups during risk assessments
- Automated vulnerability database updates
- Product-specific vulnerability matching
- Exploit availability tracking
- Patch status monitoring