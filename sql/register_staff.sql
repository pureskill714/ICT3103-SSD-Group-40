/*
register_staff is a stored procedure used to securely create staff user accounts
It will check if the email or username is already in use.
It will return 1 if the registration was successful and 2 if the registration failed

unlike register_customer, the role_ID will be set to 2 for staff
the account will also be automatically created disabled by setting the password field to '0'
Since this is impossible for Bcrypt salted hashes, no user can login with this account
*/

/* Uses staff role_id and current datetime that registration was performed as default values during creation*/

DROP PROCEDURE IF EXISTS register_staff
GO

CREATE PROCEDURE register_staff (
@username VARCHAR(32), 
@email VARCHAR(255),
@fname VARCHAR(64),
@lname VARCHAR(64),
@contact BIGINT)
AS
BEGIN
	IF not exists(SELECT 1 from Users WHERE email = @email OR username = @username)
		BEGIN

			INSERT INTO dbo.Users (Role_ID, Username, Password, Email, Last_Modified)
			VALUES ('2',
			@username,
			'0',
			@email,
			GETDATE())
			
			INSERT INTO dbo.UserDetails (User_ID, Firstname, Lastname, PhoneNo)
			VALUES(
			(SELECT User_ID FROM dbo.Users WHERE email = @email), 
			@fname,
			@lname,
			@contact)

			SELECT 2
		END
	ELSE
		BEGIN
			SELECT 1
		END
END
GO