DROP PROCEDURE IF EXISTS check_session
GO

CREATE PROCEDURE check_session (
@username VARCHAR(64),
@session_id VARCHAR(256)
)
AS
BEGIN
	DECLARE @session_created DATETIME2(0)
	DECLARE @last_logon DATETIME2(0)

	SELECT @session_created = Sessions.Created_At, @last_logon = Users.Last_Logon_Time
	FROM Sessions
	JOIN Users
	ON Users.User_ID = Sessions.User_ID

	IF DATEDIFF(MINUTE, @session_created, GETDATE()) < 30 AND DATEDIFF(MINUTE, @last_logon, GETDATE()) < 30
		BEGIN
			SELECT TOP 1 session_id, Role_Name
			FROM Sessions
			JOIN Roles
			ON Sessions.Role_ID = Roles.Role_ID
			JOIN Users
			ON Users.User_ID = Sessions.User_ID
			WHERE username = @username AND Session_ID = @session_id
		END
	ELSE
		BEGIN
			DELETE FROM Sessions WHERE session_ID = @session_id
			SELECT NULL
		END
END
GO

EXEC check_session 'aloycsm', 'THIS IS MY SESSION_ID'

SELECT * FROM Sessions