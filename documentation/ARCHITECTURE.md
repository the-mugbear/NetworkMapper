# NetworkMapper v2 Architecture - Host Deduplication

## Overview

This document describes the v2 architecture that eliminates duplicate host entries by implementing host deduplication at the database and parser level. Instead of creating separate host records for each scan, the system now maintains a single host record per IP address and tracks scan history through audit tables.

## Problem Solved

**Before (v1):** 
- Same IP address appeared multiple times when found in different scans
- Each scan created separate host records even for identical IPs
- Frontend required complex aggregation logic to display unified view
- Database grew unnecessarily large with redundant data

**After (v2):**
- Single host record per IP address across all scans
- Ports aggregated from all scans for each host
- Clean, deduplicated view in the UI by default
- Audit tables maintain complete scan history
- More efficient storage and queries

## Architecture Changes

### Database Schema v2

#### New Host Model (`hosts_v2`)
```sql
- ip_address (unique, indexed) -- No more scan_id foreign key
- hostname, state, os_info... -- Merged from all scans
- first_seen, last_seen -- Audit timestamps  
- last_updated_scan_id -- Reference to most recent scan
```

#### New Port Model (`ports_v2`)
```sql
- Unique constraint on (host_id, port_number, protocol)
- first_seen, last_seen -- Port lifecycle tracking
- is_active -- Whether port is currently active
- last_updated_scan_id -- Track source of latest data
```

#### Audit Tables
- `host_scan_history` - Which scans discovered each host
- `port_scan_history` - Port state changes over time
- Full audit trail for compliance and debugging

### Conflict Resolution Strategy

#### Host Metadata
- **Hostname:** Longer/more detailed wins
- **OS Information:** Higher accuracy score wins  
- **State:** Most recent scan wins
- **Timestamps:** Always track first/last seen

#### Port Information
- **Service Detection:** Higher confidence score wins
- **State:** Most recent scan wins
- **Scripts:** Merge all unique scripts from all scans

### Services and Components

#### HostDeduplicationService
Core service handling:
- `find_or_create_host()` - Lookup/merge host records
- `find_or_create_port()` - Lookup/merge port records  
- Conflict resolution algorithms
- Audit history tracking
- Statistics updates

#### Parser v2 (NmapXMLParserV2)
- Uses deduplication service instead of direct DB inserts
- Maintains same parsing logic but routes through deduplication
- Tracks scan provenance for all data

#### Feature Flags System
- `USE_V2_SCHEMA` - Enable v2 database tables
- `USE_V2_PARSER` - Use deduplication parser
- `DUAL_WRITE_MODE` - Parse with both v1/v2 for validation
- `MIGRATION_MODE` - Special migration behaviors

## Migration Process

### Phase 1: Deploy v2 Code (Without Enabling)
```bash
# Deploy code with feature flags disabled
git pull origin main
docker-compose build
docker-compose up -d
```

### Phase 2: Create v2 Tables
```bash
# Run migration to create v2 tables alongside v1
docker-compose exec backend python -m app.db.migrate_to_v2 migrate
```

### Phase 3: Enable Dual Write Mode
```bash
# Enable both parsers for validation
export USE_V2_PARSER=true
export DUAL_WRITE_MODE=true
docker-compose restart backend
```

### Phase 4: Validate and Switch
```bash
# Verify data integrity
docker-compose exec backend python -m app.db.migrate_to_v2 verify

# Switch to v2 completely
export USE_V2_SCHEMA=true
export USE_V2_HOSTS_API=true
export DUAL_WRITE_MODE=false
docker-compose restart
```

### Phase 5: Cleanup (Optional)
```bash
# After validation period, remove v1 tables
# This is optional and can be done much later
```

## API Changes

### Hosts Endpoint v2
- **Simpler Implementation:** No more complex aggregation logic
- **Better Performance:** Direct queries on deduplicated data
- **Same Interface:** Frontend compatibility maintained
- **New Features:** Enhanced audit capabilities

### New Endpoints
- `/api/v1/hosts/audit/{host_id}` - View scan history for host
- `/api/v1/hosts/conflicts` - View hosts with conflicting data
- `/api/v1/stats/deduplication` - Deduplication statistics

## Benefits

### Performance
- **Faster Queries:** No more aggregation needed
- **Smaller Database:** ~60-80% reduction in host/port records
- **Better Indexing:** Unique constraints improve query planning

### Data Quality  
- **Consistent View:** Single source of truth per IP
- **Conflict Resolution:** Intelligent merging of scan data
- **Audit Trail:** Complete history preserved

### User Experience
- **Cleaner Interface:** No more duplicate hosts
- **Combined Data:** All ports from all scans in one view
- **Historical Context:** See when data was first/last seen

## Rollback Strategy

If issues are discovered, rollback is simple:

```bash
# Disable v2 features
export USE_V2_SCHEMA=false
export USE_V2_PARSER=false
export USE_V2_HOSTS_API=false
docker-compose restart backend

# Optional: Remove v2 tables
docker-compose exec backend python -m app.db.migrate_to_v2 rollback
```

The v1 schema and data remain untouched during migration, ensuring safe rollback.

## Testing

### Automated Tests
- `simple_dedup_test.py` - Core logic validation ✅
- `test_v2_parser.py` - Full integration test
- Conflict resolution scenarios
- Performance benchmarks

### Manual Testing
1. Upload same scan multiple times - verify deduplication
2. Upload scans with overlapping hosts - verify merging
3. Check audit history in database
4. Verify UI shows unified view

## Monitoring

### Key Metrics
- Deduplication ratio (hosts saved vs. total)
- Conflict resolution frequency  
- Parse performance improvements
- Storage savings

### Health Checks
- Ensure no duplicate IPs in hosts_v2 table
- Verify audit history completeness
- Monitor parse times and error rates

## Future Enhancements

### Planned Features
- **Smart Port State Tracking:** Detect when ports go offline
- **Enhanced Conflict Resolution:** ML-based data quality scoring
- **Cross-Scan Analytics:** Track infrastructure changes over time
- **API Rate Limiting:** Protect against bulk operations

### Schema Optimizations
- **Partitioning:** Partition audit tables by date
- **Archiving:** Move old scan history to archive tables
- **Indexing:** Add specialized indexes for common queries

## Configuration

### Environment Variables
```bash
# Core v2 flags
USE_V2_SCHEMA=true
USE_V2_PARSER=true  
USE_V2_HOSTS_API=true

# Migration flags
MIGRATION_MODE=false
DUAL_WRITE_MODE=false

# Debug flags  
DEBUG_DEDUPLICATION=false
LOG_SCHEMA_OPERATIONS=false
```

### Database Settings
```bash
# Recommended PostgreSQL settings for v2
shared_preload_libraries = 'pg_stat_statements'
max_connections = 200
work_mem = 256MB
```

## Support

### Troubleshooting
- Check feature flags configuration
- Verify v2 tables exist and have data
- Review backend logs for deduplication messages
- Use migration verify command

### Common Issues
- **Duplicate IP Constraint Errors:** Check for data corruption
- **Missing Audit History:** Verify parser is using v2 service
- **Performance Issues:** Check indexes on new tables

This architecture provides a solid foundation for scalable network mapping with clean, deduplicated data while maintaining full backward compatibility and safe migration paths.