DROP PROCEDURE IF EXISTS staff_details
GO

CREATE PROCEDURE staff_details (
@username VARCHAR(32))
AS
BEGIN
	SELECT TOP 1 Firstname, Lastname, Email, Address, DOB, Country, City, PhoneNo 
	FROM Users INNER JOIN UserDetails ON Users.User_ID = UserDetails.User_ID
	WHERE username = @username AND Role_ID = 2
END
GO