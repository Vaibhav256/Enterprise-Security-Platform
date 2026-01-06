-- Add progress tracking columns to scans table
-- Migration: add_progress_columns
-- Date: 2025-12-12

ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress_percent INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress_message VARCHAR(500);

-- Update existing running scans to have 0 progress
UPDATE scans SET progress_percent = 0 WHERE status = 'running' AND progress_percent IS NULL;

COMMENT ON COLUMN scans.progress_percent IS 'Real-time progress percentage (0-100)';
COMMENT ON COLUMN scans.progress_message IS 'Real-time progress status message';
