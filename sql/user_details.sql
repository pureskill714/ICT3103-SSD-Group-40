DROP PROCEDURE IF EXISTS user_details
GO

CREATE PROCEDURE user_details (
@username VARCHAR(32))
AS
BEGIN
	SELECT TOP 1 Firstname, Lastname, Email, Address, DOB, Country, City, PhoneNo 
	FROM Users INNER JOIN UserDetails ON Users.User_ID = UserDetails.User_ID
	WHERE username = @username
END
GO

/* EXEC user_details 'myuser' */