-- tmg-web
-- plugin_id: 9004

DELETE FROM plugin WHERE id = "9004";
DELETE FROM plugin_sid where plugin_id = "9004";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (9004, 1, 'tmg-web', 'tmg-web');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9004, 1, NULL, NULL, 'TMG WEB Record',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9004, 11, NULL, NULL, 'TMG WEB Client sent more than received',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9004, 101, NULL, NULL, 'TMG WEB Client sent large amount of data',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9004, 111, NULL, NULL, 'TMG WEB Client sent large amount of data and more than received',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9004, 1001, NULL, NULL, 'TMG WEB unwanted url',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9004, 1011, NULL, NULL, 'TMG WEB Client sent more than received for unwanted url',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9004, 1101, NULL, NULL, 'TMG WEB Client sent large amount of data for unwanted url',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9004, 1111, NULL, NULL, 'TMG WEB Client sent large amount of data and more than received for unwanted url',1, 3);