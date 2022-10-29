DROP PROCEDURE IF EXISTS check_permission
GO

CREATE PROCEDURE check_permission (
@username VARCHAR(32),
@specified_role_id INT NOT NULL
AS
BEGIN
	IF @specified_role_id 
END
)