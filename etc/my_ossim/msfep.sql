-- MSFEP
-- plugin_id: 9003

DELETE FROM plugin WHERE id = "9003";
DELETE FROM plugin_sid where plugin_id = "9003";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (9003, 1, 'MSFEP', 'MSFEP Malware');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9003, 1, NULL, NULL, 'MSFEP Malware',1, 3);