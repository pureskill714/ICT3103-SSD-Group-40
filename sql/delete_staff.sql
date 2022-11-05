DROP PROCEDURE IF EXISTS delete_staff
GO

CREATE PROCEDURE delete_staff (
@username VARCHAR(64)
)
AS 
BEGIN
	DELETE FROM Users
	WHERE Username = @username AND Role_ID = 2

	SELECT @@ROWCOUNT
END
GO


SELECT * FROM Users