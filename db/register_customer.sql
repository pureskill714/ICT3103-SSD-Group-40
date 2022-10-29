/*
register_customer is a stored procedure used to securely create customer user accounts
It will check if the email or username is already in use.
It will return 1 if the registration was successful and 2 if the registration failed
*/

/* Uses customer role_id and current datetime that registration was performed as default values during creation*/

DROP PROCEDURE IF EXISTS register_customer
GO

CREATE PROCEDURE register_customer (
@username VARCHAR(32), 
@password VARCHAR(64),
@email VARCHAR(255),
@fname VARCHAR(64),
@lname VARCHAR(64))
AS
BEGIN
	IF not exists(SELECT 1 from Users WHERE email = @email OR username = @username)
		BEGIN

			INSERT INTO dbo.Users (Role_ID, Username, Password, Email, Last_Modified)
			VALUES ('1',
			@username,
			@password,
			@email,
			GETDATE())
			
			INSERT INTO dbo.UserDetails (User_ID, Firstname, Lastname)
			VALUES(
			(SELECT User_ID FROM dbo.Users WHERE email = @email), 
			@fname,
			@lname)

			SELECT 2
		END
	ELSE
		BEGIN
			SELECT 1
		END
END
GO

/*
Usage:

DECLARE @RETURN TINYINT
EXEC register_customer 
@username = 'test_user1', 
@password = 'mypasswordisthis', 
@email = 'tesssst.com.org.sg', 
@fname = 'test', 
@lname = 'user1', 
@ret = @RETURN OUTPUT

EXEC register_customer
@username = 'test_user2',
@password = 'mypasswordisthis',
@email = 'testing.com.org.sg',
@fname = 'testing', 
@lname = 'user2', 
@ret = @RETURN OUTPUT

SELECT @RETURN
SELECT * FROM dbo.Users
GO

SELECT * FROM dbo.CustomerDetails
GO
*/