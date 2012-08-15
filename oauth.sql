CREATE TABLE IF NOT EXISTS `oauth_clients` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id` varchar(64) NOT NULL,
  `client_secret` varchar(64) NOT NULL,
  `title` varchar(64) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `client_id_secret` (`client_id`,`client_secret`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

CREATE TABLE IF NOT EXISTS `oauth_tokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `access_token` varchar(40) NOT NULL,
  `refresh_token` varchar(40) NOT NULL,
  `token_type` varchar(16) NOT NULL,
  `user_id` int(11) NOT NULL,
  `client_id` varchar(40) NOT NULL,
  `expires_in` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `access_token` (`access_token`),
  KEY `refresh_token` (`refresh_token`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;