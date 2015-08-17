-- tmg-fws
-- plugin_id: 9005

DELETE FROM plugin WHERE id = "9005";
DELETE FROM plugin_sid where plugin_id = "9005";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (9005, 1, 'tmg-fws', 'TMG-FWS logger');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9005, 1, NULL, NULL, 'TMG FWS Record',1, 3);