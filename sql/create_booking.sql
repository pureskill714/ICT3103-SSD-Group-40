DROP PROCEDURE IF EXISTS create_booking
GO

CREATE PROCEDURE create_booking (
@user_id INT,
@room_id INT,
@booking_details VARCHAR(255),
@start_date DATE,
@end_date DATE
)
AS
BEGIN
	SELECT * INTO #TempBooking FROM Bookings
	DECLARE @BookingID INT

	SELECT Rooms.Room_Type_ID, Room_ID INTO #TempRooms FROM RoomTypes JOIN Rooms ON RoomTypes.Room_Type_ID = Rooms.Room_Type_ID
	DECLARE @RoomID INT
	
	IF @start_date > @end_date
		RETURN 2

	IF EXISTS(SELECT * FROM #TempBooking) 
	BEGIN
		WHILE EXISTS(SELECT * FROM #TempBooking)
		BEGIN
			SELECT TOP 1 @BookingID = Booking_ID FROM #TempBooking

			IF EXISTS(SELECT * FROM #TempRooms)
			BEGIN
				
				DELETE FROM #TempRooms WHERE Room_ID = @RoomID
			END

			IF ((SELECT TOP 1 Start_Date FROM #TempBooking WHERE Start_Date >= GETDATE() - 1 AND Booking_Status = 'Approved' AND Room_ID = @room_id) <= @end_date
				AND (SELECT TOP 1 End_Date FROM #TempBooking WHERE Start_Date >= GETDATE() - 1 AND Booking_Status = 'Approved' AND Room_ID = @room_id) >= @start_date)
				OR EXISTS(SELECT 1 FROM #TempBooking WHERE Room_ID = @room_id AND Start_Date = @start_date AND End_Date = @end_date AND User_ID = @user_id)
				RETURN 2
			ELSE
				DELETE FROM #TempBooking WHERE Booking_ID = @BookingID
		END

		INSERT INTO Bookings (User_ID, Room_ID, Booking_Status, Booking_Details, Start_Date, End_Date, Created_At, Last_Modified)
			VALUES(@user_id, @room_id, 'Pending', @booking_details, @start_date, @end_date, GETDATE(), GETDATE())
		RETURN 1
	END

	ELSE
		INSERT INTO Bookings (User_ID, Room_ID, Booking_Status, Booking_Details, Start_Date, End_Date, Created_At, Last_Modified)
			VALUES(@user_id, @room_id, 'Pending', @booking_details, @start_date, @end_date, GETDATE(), GETDATE())
		RETURN 1
END
GO


EXEC create_booking '1', '4', NULL, '2024-10-18', '2024-10-18' 

SELECT * FROM BOOKINGS
