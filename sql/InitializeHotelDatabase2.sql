DROP TABLE IF EXISTS dbo.Sessions;
GO

DROP TABLE IF EXISTS dbo.Room_Availability;
GO

DROP TABLE IF EXISTS dbo.Transactions;
GO

DROP TABLE IF EXISTS dbo.Bookings;
GO

DROP TABLE IF EXISTS dbo.Rooms;
GO

DROP TABLE IF EXISTS dbo.RoomTypes;
GO

DROP TABLE IF EXISTS dbo.UserDetails;
GO

DROP TABLE IF EXISTS dbo.Users;
GO

DROP TABLE IF EXISTS dbo.Roles;
GO

/* System only allows for 1 user to hold 1 type of role, therefore relation is one-to-one*/
CREATE TABLE dbo.Roles (
  [Role_ID] INT NOT NULL,
  [Role_Name] VARCHAR(255) NOT NULL,
  [Role_Description] VARCHAR(255) NULL,
  PRIMARY KEY ([Role_ID]))

CREATE INDEX roleid ON dbo.Roles(Role_ID)
GO

/* Role ID is set to be 'Customer' by default to prevent exploits that create users with elevated privileges*/
CREATE TABLE dbo.Users (
  [User_ID] INT IDENTITY(1,1),
  [Role_ID] INT NOT NULL DEFAULT 1,
  [User_UUID] UNIQUEIDENTIFIER NOT NULL DEFAULT NEWID(),
  [Username] VARCHAR(32) NOT NULL UNIQUE,
  [Password] VARCHAR(255) NOT NULL,
  [Email] VARCHAR(255) NOT NULL UNIQUE,
  [Last_Logon_Time] DATETIME2(0) NULL,
  [Last_Logon_IP] VARCHAR(40) NULL,
  [No_Of_Attempts] INT NULL DEFAULT 0,
  [No_Of_Logons] INT NULL DEFAULT 0,
  [Created_At] DATETIME2(0) NOT NULL DEFAULT GETDATE(),
  [Last_Modified] DATETIME2(0) NULL DEFAULT GETDATE(),
  [Token_Reset] NVARCHAR(255) NULL DEFAULT NULL,
  PRIMARY KEY ([User_ID]),
  CONSTRAINT FK_UserRole FOREIGN KEY (Role_ID) REFERENCES Roles(Role_ID)) 

CREATE UNIQUE INDEX uq_userid ON dbo.Users(User_ID)
CREATE UNIQUE INDEX uq_email ON dbo.Users(Email)
GO

CREATE TABLE dbo.UserDetails (
  [User_ID] INT NOT NULL,
  [Firstname] VARCHAR(64) NULL DEFAULT NULL,
  [Lastname] VARCHAR(64) NULL DEFAULT NULL,
  [Address] VARCHAR(255) NULL DEFAULT NULL,
  [DOB] DATE NULL DEFAULT NULL, 
  [Country] VARCHAR(128) NULL DEFAULT NULL,
  [City] VARCHAR(128) NULL DEFAULT NULL,
  [PhoneNo] BIGINT NULL DEFAULT NULL,
  PRIMARY KEY ([User_ID]),
  CONSTRAINT FK_UserID FOREIGN KEY (User_ID) REFERENCES Users(User_ID))
GO

CREATE TABLE dbo.RoomTypes (
  [Room_Type_ID] INT NOT NULL,
  [Room_Cost] DECIMAL(10,2) NOT NULL DEFAULT 500,
  [Room_Type] VARCHAR(255) NULL DEFAULT NULL,
  PRIMARY KEY ([Room_Type_ID]))
GO

CREATE TABLE dbo.Rooms (
  [Room_ID] INT IDENTITY(1,1),
  [Room_Type_ID] INT NOT NULL,
  [Room_No] INT UNIQUE,
  PRIMARY KEY ([Room_ID]),
  CONSTRAINT FK_RoomTypeID FOREIGN KEY (Room_Type_ID) REFERENCES RoomTypes(Room_Type_ID))
CREATE UNIQUE INDEX roomid ON dbo.Rooms(Room_ID)
GO

CREATE TABLE dbo.Bookings (
  [Booking_ID] INT IDENTITY(1,1),
  [Booking_UUID] UNIQUEIDENTIFIER NOT NULL DEFAULT NEWID(),
  [User_ID] INT NOT NULL,
  [Room_ID] INT NOT NULL,
  [Booking_Status] VARCHAR(30) NOT NULL,
  [Booking_Details] VARCHAR(255) NULL,
  [Start_Date] DATE NOT NULL,
  [End_Date] DATE NOT NULL,
  [Created_At] DATETIME2(0) NOT NULL DEFAULT GETDATE(),
  [Last_Modified] DATETIME2(0) NULL DEFAULT GETDATE(),
  PRIMARY KEY ([Booking_ID]),
  CONSTRAINT FK_BookingUserID FOREIGN KEY (User_ID) REFERENCES Users(User_ID),
  CONSTRAINT FK_BookingRoomID FOREIGN KEY (Room_ID) REFERENCES Rooms(Room_ID))

CREATE INDEX bookingid ON dbo.Bookings(Booking_ID)
GO

CREATE TABLE dbo.Transactions (
  [Transaction_ID] INT NOT NULL UNIQUE,
  [Booking_ID] INT NOT NULL UNIQUE,
  [Payment_Type] VARCHAR(45) NULL DEFAULT NULL,
  PRIMARY KEY ([Transaction_ID], [Booking_ID]),
  CONSTRAINT FK_TransactionBookingID FOREIGN KEY (Booking_ID) REFERENCES Bookings(Booking_ID))
GO

CREATE TABLE dbo.Sessions  (
  [Session_PK] INT IDENTITY(1,1),
  [User_ID] INT NOT NULL,
  [Role_ID] INT NOT NULL,
  [Session_ID] VARCHAR(256) NOT NULL,
  [Created_At] DATETIME2(0) NOT NULL DEFAULT GETDATE(),
  PRIMARY KEY ([Session_ID]),
  CONSTRAINT FK_SessionUserID FOREIGN KEY (User_ID) REFERENCES Users(User_ID),
  CONSTRAINT FK_SessionUserRole FOREIGN KEY (Role_ID) REFERENCES Roles(Role_ID)) 
GO

/* Initialize the 3 roles that are used within the database for all users*/

/* Currently role IDs are set to 1, 2 and 3. Might need to change. */
INSERT INTO dbo.Roles(Role_ID, Role_Name, Role_Description) VALUES 
(1, 'Customer', 'Customers looking to book rooms at the hotel'),
(2, 'Staff', 'Staff members of the hotel'),
(3, 'Manager', 'Management that handles the staff')

SELECT * FROM dbo.Roles
GO