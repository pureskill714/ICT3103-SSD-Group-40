DROP VIEW IF EXISTS get_customer
GO

CREATE VIEW get_customer AS (
	SELECT Username, User_UUID, Email, Last_Logon_Time, Firstname, Lastname, Address, DOB, Country, City, PhoneNo, Booking_ID, Start_Date, End_Date
	FROM Users
	JOIN UserDetails 
	ON Users.User_ID = UserDetails.User_ID

	JOIN Bookings
	ON UserDetails.User_ID = Bookings.User_ID

	WHERE Role_ID = '1'
)
GO

SELECT * FROM get_customer
SELECT COUNT(*) FROM get_customer
