/*
retrieve_password is a stored procedure used to specifically retrieve the original password hash that was used during registration
*/

DROP PROCEDURE IF EXISTS retrieve_password
GO

CREATE PROCEDURE retrieve_password (
@username VARCHAR(32)
)
AS 
BEGIN
	SELECT TOP 1 Password FROM Users WHERE Username = @username
END
GO

/*
DECLARE @RETURN VARCHAR(255)
EXEC retrieve_password
@username = 'myuser'

SELECT @RETURN
*/