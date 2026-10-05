-- 0006: record who ran each scan (same pattern as 0004 for attachments).
ALTER TABLE scans ADD COLUMN uploaded_by_name TEXT NOT NULL DEFAULT '';
