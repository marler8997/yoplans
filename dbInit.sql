CREATE database hb;
USE hb;

CREATE TABLE users (
       uid          BIGINT UNSIGNED  NOT NULL UNIQUE PRIMARY KEY AUTO_INCREMENT,
       email        VARCHAR(255)     NOT NULL UNIQUE,
       salt         BINARY(1)        NOT NULL,
       passwordHash BINARY(20)       NOT NULL,
       fName        VARCHAR(64)      NOT NULL,
       lName        VARCHAR(64)      NOT NULL
       );

CREATE TABLE sessions (
       sid          BINARY(20)       NOT NULL PRIMARY KEY,
       genTime      TIME             NOT NULL,
       uid          BIGINT UNSIGNED  NOT NULL,
       lastRequest  TIME             NOT NULL,
       ip           INT   UNSIGNED   NOT NULL
       );

/* 
 * NOTE: Need to keep track of number of attempts, and the time associated.
 *       Then I need to be able to calculate the number of attempts within a given time.
 *       Then I need to create an script that cleans up these bad logins every so often.
 */
CREATE TABLE badLogins (
       ip           INT   UNSIGNED NOT NULL,
       time         TIME           NOT NULL,
       email        VARCHAR(255)
/*
       password varchar(64)
*/
);
