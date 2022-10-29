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
	INSERT INTO Bookings (User_ID, Room_ID, Booking_Status, Booking_Details, Start_Date, End_Date, Created_At, Last_Modified)
	VALUES(@user_id, @room_id, 'Pending', @booking_details, @start_date, @end_date, GETDATE(), GETDATE())
END
GO

/*
INSERT INTO RoomTypes (Room_Type_ID, Room_Cost, Room_Type_Description)
VALUES ('1', '500', 'No Description')

INSERT INTO Rooms (Room_ID, Room_Type_ID, Room_Floor, Room_Number)
VALUES ('1', '1', '2', '123')

EXEC create_booking '1', '1', NULL, '2022-10-30', '2022-10-31' 

SELECT * FROM Bookings
*/