DROP TABLE IF EXISTS Logs;
GO
 
 CREATE TABLE Logs (
  logs_id int identity(1,1) primary key,
  datetime DATETIME2 DEFAULT GETDATE(),
  event varchar(128),
  security_level varchar(32),
  hostname varchar(256),
  source_address varchar(128),
  destination_address varchar(128),
  browser varchar(256),
  description varchar(512)
)
