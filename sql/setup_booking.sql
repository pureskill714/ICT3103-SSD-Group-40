DROP PROCEDURE IF EXISTS setup_booking
GO

CREATE PROCEDURE setup_booking (
@user_id INT,
@room_type INT,
@booking_details VARCHAR(255),
@start_date DATE,
@end_date DATE
)

AS
BEGIN
	SELECT Rooms.Room_Type_ID, Room_ID INTO #TempRooms FROM RoomTypes JOIN Rooms ON RoomTypes.Room_Type_ID = Rooms.Room_Type_ID WHERE Rooms.Room_Type_ID = @room_type
	DECLARE @RoomID INT
	DECLARE @return INT

	IF EXISTS(SELECT * FROM #TempRooms) 
	BEGIN
		WHILE EXISTS(SELECT * FROM #TempRooms)
		BEGIN
			SELECT TOP 1 @RoomID = Room_ID FROM #TempRooms

			EXEC @return = [create_booking] @user_ID, @RoomID, @booking_details, @start_date, @end_date
			IF @return = 1
			BEGIN
				SELECT 1
				RETURN 1
			END
			DELETE FROM #TempRooms WHERE Room_ID = @RoomID
		END
		DROP TABLE IF EXISTS #TempRooms
		BEGIN
			SELECT 2
			RETURN 2
		END
	END
END
GO


DECLARE @return2 INT
EXEC @return2 = [setup_booking] '1', '1', '', '2024-10-30', '2024-11-5' 

SELECT @return2

SELECT * FROM Rooms
SELECT * FROM Bookings
