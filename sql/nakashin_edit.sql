ALTER TABLE users ADD `salt` varchar(6) DEFAULT NULL;
UPDATE users, salts SET users.salt = salts.salt WHERE users.id = salts.user_id;
