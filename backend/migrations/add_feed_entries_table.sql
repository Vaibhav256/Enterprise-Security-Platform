-- Migration: Add feed_entries table for threat intelligence feeds
-- Date: 2025-10-31
-- Description: Migrates threat intelligence data from JSON files to database

-- Create feed_entries table
CREATE TABLE IF NOT EXISTS feed_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Feed metadata
    feed_source VARCHAR(50) NOT NULL,
    feed_type VARCHAR(50) NOT NULL,
    
    -- Entry identification
    entry_id VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    
    -- Severity and scoring
    severity VARCHAR(20),
    cvss_score DECIMAL(3, 1),
    cvss_vector VARCHAR(200),
    
    -- Vulnerability details
    affected_products TEXT[],
    cwe_ids TEXT[],
    ref_urls TEXT[],
    
    -- Exploit information
    exploit_available VARCHAR(10),
    exploit_type VARCHAR(50),
    exploit_platform VARCHAR(50),
    
    -- Temporal data
    published_date TIMESTAMP,
    modified_date TIMESTAMP,
    discovered_date TIMESTAMP,
    
    -- Additional metadata
    metadata JSONB,
    
    -- Tracking
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_feed_source ON feed_entries(feed_source);
CREATE INDEX IF NOT EXISTS idx_feed_source_type ON feed_entries(feed_source, feed_type);
CREATE INDEX IF NOT EXISTS idx_entry_id ON feed_entries(entry_id);
CREATE INDEX IF NOT EXISTS idx_severity ON feed_entries(severity);
CREATE INDEX IF NOT EXISTS idx_published_date ON feed_entries(published_date);
CREATE INDEX IF NOT EXISTS idx_cvss_score ON feed_entries(cvss_score);

-- Create unique constraint on entry_id to prevent duplicates
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_entry_id ON feed_entries(entry_id);

-- Add comment to table
COMMENT ON TABLE feed_entries IS 'Threat intelligence feed entries from NVD, ExploitDB, and other sources';

-- Migration complete
COMMENT ON COLUMN feed_entries.feed_source IS 'Source of the feed: nvd, exploitdb, etc.';
COMMENT ON COLUMN feed_entries.entry_id IS 'Unique identifier from source: CVE-2024-1234, EDB-12345, etc.';
COMMENT ON COLUMN feed_entries.metadata IS 'Additional flexible metadata in JSON format';
