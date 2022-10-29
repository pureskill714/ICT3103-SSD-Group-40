DROP VIEW IF EXISTS get_staff
GO

CREATE VIEW get_staff AS (
	SELECT Username, User_UUID, Email, Last_Logon_Time, Firstname, Lastname, Address, DOB, Country, City, PhoneNo
	FROM Users
	JOIN UserDetails ON Users.User_ID = UserDetails.User_ID
	WHERE Role_ID = '2'
)
GO 

SELECT * FROM get_staff
