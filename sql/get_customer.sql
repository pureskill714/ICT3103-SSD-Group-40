DROP VIEW IF EXISTS get_customer
GO

CREATE VIEW get_customer AS (
	SELECT Username, User_UUID, Email, Last_Logon_Time, Firstname, Lastname, Address, DOB, Country, City, PhoneNo, COUNT(Booking_ID) Bookings
	FROM Users
	JOIN UserDetails 
	ON Users.User_ID = UserDetails.User_ID

	FULL OUTER JOIN Bookings
	ON UserDetails.User_ID = Bookings.User_ID

	WHERE Role_ID = '1'
	GROUP BY Username, User_UUID, Email, Last_Logon_Time, Firstname, Lastname, Address, DOB, Country, City, PhoneNo
)
GO

SELECT * FROM get_customer
