DROP PROCEDURE IF EXISTS approve_bookings
GO

CREATE PROCEDURE approve_bookings
@UUID VARCHAR(64)
AS

BEGIN
	UPDATE Bookings
	SET Booking_Status = 'Approved'
	WHERE Booking_UUID = @UUID AND Start_Date > GETDATE()
END
GO

/*
EXEC approve_bookings 'EEB5AF5F-CA60-4798-914E-BCC0EB9E5F2C'
*/

SELECT * FROM Bookings