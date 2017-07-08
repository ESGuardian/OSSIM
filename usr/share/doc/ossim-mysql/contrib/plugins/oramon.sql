-- oramon
-- plugin_id: 9009

DELETE FROM plugin WHERE id = "9009";
DELETE FROM plugin_sid where plugin_id = "9009";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (9009, 1, 'oramon', 'oramon');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 1, NULL, NULL, 'Новый OS_USER',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 2, NULL, NULL, 'Новое место подключения',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 3, NULL, NULL, 'Новый ORACLE_USER',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 4, NULL, NULL, 'С возвращением!',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 5, NULL, NULL, 'Давно не виделись.',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 6, NULL, NULL, 'Прыг-скок',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 7, NULL, NULL, 'Четыре руки!',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 8, NULL, NULL, 'Много неудачных соединений',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 9, NULL, NULL, 'Этим логином Oracle давно не пользовались.',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 10, NULL, NULL, 'Использован новый ORACLE_USER',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 11, NULL, NULL, 'Новая роль ORACLE',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 13, NULL, NULL, 'Использована новая роль ORACLE',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 14, NULL, NULL, 'Этой ролью ORACLE давно не пользовались',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 15, NULL, NULL, 'Кое-кто давно не использовал эту роль ORACLE',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 16, NULL, NULL, 'Ошибка при подключении к БД',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 17, NULL, NULL, 'Ошибка при назначении роли',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 18, NULL, NULL, 'Много ошибок',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 19, NULL, NULL, 'Очень много ошибок!',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9009, 9999, NULL, NULL, 'Новое событие',1, 1);