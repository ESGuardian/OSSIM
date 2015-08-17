-- myILO
-- plugin_id: 90012

DELETE FROM plugin WHERE id = "90012";
DELETE FROM plugin_sid where plugin_id = "90012";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (90012, 1, 'myILO', 'ILO access');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (90012, 1, NULL, NULL, 'ILO access IPMI',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (90012, 2, NULL, NULL, 'ILO access Browser',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (90012, 3, NULL, NULL, 'ILO logout',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (90012, 4, NULL, NULL, 'ILO access FAILURE',1, 3);