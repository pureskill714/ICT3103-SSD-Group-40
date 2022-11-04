DROP PROCEDURE IF EXISTS delete_session
GO

CREATE PROCEDURE delete_session (
@username VARCHAR(64),
@session_id VARCHAR(256)
)
AS
BEGIN
	DECLARE @User_ID INT

	SELECT TOP 1 
	@User_ID = User_ID
	FROM Users
	WHERE Username = @username

	IF EXISTS(SELECT 1 FROM Users WHERE Username = @username)
		BEGIN
			DELETE FROM Sessions WHERE User_ID = @User_ID AND Session_ID = @session_id
		END
END
GO