DROP VIEW IF EXISTS get_bookings
GO

CREATE VIEW get_bookings AS
(
SELECT firstname, lastname, PhoneNo, Room_No, Room_Type, Start_Date, End_Date, Booking_Status, Booking_Details, Bookings.Created_At, Booking_UUID
FROM Bookings 

JOIN Users ON Bookings.User_ID = Users.User_ID
JOIN UserDetails ON Users.User_ID  = UserDetails.User_ID
JOIN Rooms ON Rooms.Room_ID = Bookings.Room_ID
JOIN RoomTypes ON Rooms.Room_Type_ID = RoomTypes.Room_Type_ID
)
GO

SELECT * FROM get_pending_bookings