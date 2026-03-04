CREATE TABLE IF NOT EXISTS nodes_static__old_schema (
	hash             TEXT PRIMARY KEY,
	raw_options_json TEXT NOT NULL,
	created_at_ns    INTEGER NOT NULL
);

INSERT INTO nodes_static__old_schema (hash, raw_options_json, created_at_ns)
SELECT hash, raw_options_json, created_at_ns FROM nodes_static;

DROP TABLE nodes_static;

ALTER TABLE nodes_static__old_schema RENAME TO nodes_static;
