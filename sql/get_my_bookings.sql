DROP PROCEDURE IF EXISTS get_my_bookings
GO

CREATE PROCEDURE get_my_bookings
@UUID VARCHAR(64)
AS
(
SELECT Room_No, Room_Type, Start_Date, End_Date, Booking_Status, Bookings.Created_At, Booking_Details, Booking_UUID
FROM Bookings 

JOIN Users ON Bookings.User_ID = Users.User_ID
JOIN UserDetails ON Users.User_ID  = UserDetails.User_ID
JOIN Rooms ON Rooms.Room_ID = Bookings.Room_ID
JOIN RoomTypes ON Rooms.Room_Type_ID = RoomTypes.Room_Type_ID

WHERE User_UUID = @UUID)
GO

EXEC get_my_bookings 'DD542958-2979-4B20-99CE-615683E7027A'