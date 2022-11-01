DROP PROCEDURE IF EXISTS check_email
GO

CREATE PROCEDURE check_email (
@email VARCHAR(255)
)
AS
BEGIN
	IF EXISTS(SELECT 1 FROM Users WHERE Email = @email)
		SELECT 1
	ELSE
		SELECT 2
END
GO

EXEC check_email 'myemail@google.sg'