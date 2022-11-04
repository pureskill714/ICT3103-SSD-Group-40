/*
retrieve_password is a stored procedure used to specifically retrieve the original password hash that was used during registration
*/

DROP PROCEDURE IF EXISTS retrieve_token_reset
GO

CREATE PROCEDURE retrieve_token_reset (
@email VARCHAR(255)
)
AS 
BEGIN
	SELECT TOP 1 Token_Reset FROM Users WHERE Email = @email
END
GO
