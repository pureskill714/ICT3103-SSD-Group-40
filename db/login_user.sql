/*
login_user is a stored procedure that verifies the user's username and password during login
Blocks logins if too many logon attempts (>30) have been performed without a successful login
Return value of 1 means that the login was successful and the email of the user is parsed into the @emailMFA output parameter
Return value of 2 means that the login was unsuccessful and no email from database is parsed

If a login is successful:
- Last logon time is updated with the current time
- Last logon IP address is updated with the user's IP address
- No. of logons is incremented by 1
- No. of attempts is reset to 0

If a login is unsuccessful:
- The no. of attempts is incremented by 1
*/

DROP PROCEDURE IF EXISTS login_user
GO

CREATE PROCEDURE login_user (
@username VARCHAR(32), 
@login_success TINYINT, 
@IP_Address VARCHAR(40))
AS 
BEGIN
	DECLARE @Attempts_check INT
	SELECT @Attempts_check = No_Of_Attempts FROM Users WHERE Username = @username
	IF @Attempts_check < 30 AND @Attempts_check IS NOT NULL AND @login_success = 1
		BEGIN
			UPDATE Users 
			SET Last_Logon_Time = GETDATE(), Last_Logon_IP = @IP_Address, No_Of_Logons = No_Of_Logons + 1, No_Of_Attempts = 0
			WHERE Username = @username

			SELECT TOP 1 email, Role_ID, User_UUID
			FROM Users
			WHERE Username = @username
		END
	ELSE
		BEGIN
			UPDATE Users 
			SET No_Of_Attempts = No_Of_Attempts + 1
			WHERE Username = @username
		END
END
GO

/*
Usage:

DECLARE @return TINYINT 
DECLARE @emailMFA VARCHAR(255)
DECLARE @role_id TINYINT

EXEC login_user @username = 'test_user1', @login_success = 1, @IP_Address = '54.189.72.63', @email = @emailMFA OUTPUT, @Role_id = @role_id OUTPUT

SELECT @return, @emailMFA, @role_id
SELECT * FROM dbo.Users
GO
*/