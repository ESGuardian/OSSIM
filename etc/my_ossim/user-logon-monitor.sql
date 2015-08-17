-- user-logon-monitor
-- plugin_id: 9006

DELETE FROM plugin WHERE id = "9006";
DELETE FROM plugin_sid where plugin_id = "9006";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (9006, 1, 'user-logon-monitor', 'Logon and remote access monitor');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9006, 1, NULL, NULL, 'Hello!',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9006, 2, NULL, NULL, 'Wellcome back!',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9006, 3, NULL, NULL, 'Old friend come back!',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9006, 4, NULL, NULL, 'New kid in town!',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9006, 100, NULL, NULL, 'Error!',1, 3);