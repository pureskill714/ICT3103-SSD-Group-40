DROP PROCEDURE IF EXISTS create_log
GO

CREATE PROCEDURE create_log(
@datetime DATETIME,
@event varchar(128),
@security_level varchar(32),
@hostname varchar(256),
@source_address varchar(128),
@destination_address varchar(128),
@browser varchar(256),
@description varchar(512)
)
AS
BEGIN
	IF GETDATE() != @datetime
		SELECT 2
	ELSE
	BEGIN
		INSERT INTO Logs(datetime, event, security_level, hostname, source_address, destination_address, browser, description)
		VALUES (@datetime, @event, @security_level, @hostname, @source_address, @destination_address, @browser, @description)
		SELECT 1
	END
END
GO

-- EXEC create_log GETDATE(), 'testevent', 'warn', 'myhostname', '192.168.0.1', '192.168.0.3', 'firefox', 'something'

SELECT * FROM Logs
