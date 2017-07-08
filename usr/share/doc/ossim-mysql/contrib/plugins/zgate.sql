-- zgate
-- plugin_id: 9008

DELETE FROM plugin WHERE id = "9008";
DELETE FROM plugin_sid where plugin_id = "9008";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (9008, 1, 'zgate', 'zgate');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9008, 1, NULL, NULL, 'Загружен файл',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9008, 2, NULL, NULL, 'Отправлено письмо',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9008, 3, NULL, NULL, 'Получено сообщение',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9008, 4, NULL, NULL, 'Отправлено сообщение',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9008, 5, NULL, NULL, 'Исходящая почта',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9008, 6, NULL, NULL, 'Изменен статус',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9008, 7, NULL, NULL, 'Входящая почта',1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (9008, 9999, NULL, NULL, 'Новое событие',1, 1);