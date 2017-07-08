-- activesync-monitor
-- plugin_id: 9007

DELETE FROM plugin WHERE id = "9007";
DELETE FROM plugin_sid where plugin_id = "9007";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (9007, 1, 'activesync-monitor', 'Exchange ActiveSync access monitor');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9007, 1, NULL, NULL, 'Hello!',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9007, 2, NULL, NULL, 'Wellcome back!',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9007, 3, NULL, NULL, 'Old friend come back!',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9007, 4, NULL, NULL, 'New user-device pair!',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9007, 100, NULL, NULL, 'Error!',1, 3);
