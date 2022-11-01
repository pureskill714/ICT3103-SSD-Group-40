DROP USER IF EXISTS flask
DROP LOGIN flask
GO

CREATE LOGIN flask WITH PASSWORD = '12345678'
CREATE USER flask FOR LOGIN flask
GO

DROP USER IF EXISTS Customer
DROP LOGIN Customer
GO

CREATE LOGIN Customer WITH PASSWORD = '12345678'
CREATE USER Customer FOR LOGIN Customer
GO

DROP USER IF EXISTS Staff
DROP LOGIN Staff
GO

CREATE LOGIN Staff WITH PASSWORD = '12345678'
CREATE USER Staff FOR LOGIN Staff
GO

DROP USER IF EXISTS Manager
DROP LOGIN Manager
GO

CREATE LOGIN Manager WITH PASSWORD = '12345678'
CREATE USER Manager FOR LOGIN Manager
GO

GRANT EXECUTE ON create_session TO flask
GRANT EXECUTE ON check_session TO flask
GRANT EXECUTE ON update_password TO flask
GRANT EXECUTE ON register_customer TO flask
GRANT EXECUTE ON retrieve_password TO flask
GRANT EXECUTE ON login_user TO flask
GRANT EXECUTE ON check_email TO flask
GO

GRANT EXECUTE ON setup_booking TO Customer 
GRANT EXECUTE ON update_details TO Customer
GRANT EXECUTE ON user_details TO Customer
GRANT EXECUTE ON get_my_bookings TO Customer
GO  

GRANT SELECT ON get_pending_bookings TO Staff
GRANT SELECT ON get_approved_bookings TO Staff
GRANT SELECT ON get_customer TO Staff
GRANT EXECUTE ON user_details TO Staff
GRANT EXECUTE ON approve_bookings TO Staff
GO

GRANT SELECT ON get_staff TO Manager
GRANT EXECUTE ON register_staff TO Manager
GRANT EXECUTE ON user_details TO Manager
GRANT EXECUTE ON update_details TO Manager
GO
