DROP PROCEDURE IF EXISTS update_password
GO

CREATE PROCEDURE update_password (
@email VARCHAR(255),
@password VARCHAR(255)
)
AS
BEGIN
	UPDATE Users
	SET Password = @password
	WHERE Email = @email

	SELECT @@ROWCOUNT
END
GO

EXEC update_password 'myemail@google.sg', '1'