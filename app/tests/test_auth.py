import pymssql
import pytest
from app import g, session


def test_register_csrf(app, client, app_ctx):
    assert client.get('/register').status_code == 200
    response = client.post("/register", data={"csrf_token": g.csrf_token, 'firstname': "test_firstname",
                                              'lastname': 'test_lastname', 'email': "test15@test.com",
                                              'username': 'test_user15', 'password': '12345678',
                                              'password_confirm': '12345678'})
    assert response.headers["Location"] == "/registersuccess"

    conn = pymssql.connect(server="localhost", user='sa', password='9WoH697&p2oM', database="3203")
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE Username=%s', 'test_user14')
    assert cursor.fetchone() is not None
    conn.close()
    response = client.post("/register", data={"csrf_token": g.csrf_token, 'firstname': "test_firstname",
                                              'lastname': 'test_lastname', 'email': "test15@test.com",
                                              'username': 'test_user15', 'password': '12345678',
                                              'password_confirm': '12345678'})

    assert "Username or Email may already be in use. Please try again." in response.get_data(as_text=True)

# @pytest.mark.parametrize(('username', 'password', 'message'), (
#     ('', '', b'Username is required.'),
#     ('a', '', b'Password is required.'),
#     ('test', 'test', b'already registered'),
# ))
# def test_register_validate_input(client, username, password, message):
#     response = client.post(
#         '/register',
#         data={'username': username, 'password': password}
#     )
#     assert message in response.data

