DROP PROCEDURE IF EXISTS update_token_reset
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE update_token_reset 
	-- Add the parameters for the stored procedure here
	@email VARCHAR(255),
	@Token_Reset nvarchar(255)
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	UPDATE Users
	SET Token_Reset = @Token_Reset
	WHERE Email = @email

	SELECT @@ROWCOUNT
END
GO
