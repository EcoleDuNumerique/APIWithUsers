## Structure de la base de donnée
    
    CREATE TABLE `notes` (
     `id` int(11) NOT NULL AUTO_INCREMENT,
     `title` varchar(120) NOT NULL,
     `content` text NOT NULL,
     `user_id` int(11) NOT NULL,
     PRIMARY KEY (`id`),
     KEY `notes_user_id` (`user_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8
    
    CREATE TABLE `users` (
     `id` int(11) NOT NULL AUTO_INCREMENT,
     `email` varchar(60) NOT NULL,
     `firstname` varchar(60) DEFAULT NULL,
     `lastname` varchar(60) DEFAULT NULL,
     `password` varchar(256) NOT NULL,
     PRIMARY KEY (`id`),
     UNIQUE KEY `users_email_unique` (`email`)
    ) ENGINE=MyISAM DEFAULT CHARSET=utf8