DROP PROCEDURE IF EXISTS create_session
GO

CREATE PROCEDURE create_session (
@username VARCHAR(64),
@session_id VARCHAR(256)
)
AS
BEGIN
	DECLARE @User_ID INT
	DECLARE @Role_ID INT

	SELECT TOP 1 
	@User_ID = User_ID,
	@Role_ID = Roles.Role_ID 
	FROM Users JOIN ROLES 
	ON Users.Role_ID = Roles.Role_ID 
	WHERE Username = @username

	IF EXISTS(SELECT 1 FROM Users WHERE Username = @username)
		BEGIN
			DELETE FROM Sessions WHERE User_ID = @User_ID
		END
	INSERT into Sessions (User_ID, Role_ID, Session_ID, Created_At)
	VALUES (@User_ID, @Role_ID, @session_id, GETDATE())

	SELECT @@ROWCOUNT
END

GO

--EXEC create_session 'aloycsm', 'THIS IS MY SESSION_ID'

SELECT * FROM Sessions
