DROP PROCEDURE IF EXISTS approve_bookings
GO

CREATE PROCEDURE approve_bookings
@UUID VARCHAR(64)
AS

BEGIN
	UPDATE Bookings
	SET Booking_Status = 'Approved'
	WHERE Booking_UUID = @UUID AND Start_Date > GETDATE() - 1
END
GO


EXEC approve_bookings '933bbf53-b166-475e-9fcb-59faa3e84b01'


SELECT * FROM Bookings