

DROP PROCEDURE IF EXISTS update_details
GO

CREATE PROCEDURE update_details (
@username VARCHAR(32),
@email VARCHAR(255),
@fname VARCHAR(64),
@lname VARCHAR(64),
@address VARCHAR(255),
@DOB VARCHAR(20),
@country VARCHAR(128),
@city VARCHAR(128),
@phone BIGINT)
AS
BEGIN 
	UPDATE UserDetails 
	SET Firstname = @fname, Lastname = @lname, Address = @address, DOB = @DOB, Country = @country, City = @city, PhoneNo = @phone  
	WHERE User_ID = (SELECT TOP 1 User_ID FROM Users WHERE username = @username)

	UPDATE Users
	SET Email = @email, Last_Modified = GETDATE()
	WHERE User_ID = (SELECT TOP 1 User_ID FROM Users WHERE username = @username)

	SELECT 2
END
GO

SELECT * FROM Users
EXEC update_details 'myuser', 'myuser@email.org', 'Aloysius', 'Chong', '10B Jalan Limau Bali', '1998-09-19',
'Singapore', 'Singapore', '82287416'

SELECT * FROM UserDetails
