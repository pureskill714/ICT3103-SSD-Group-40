from app.flaskapp import create_app


def test_config():
    assert not create_app().testing
    assert create_app({'TESTING': True}).testing


def test_mainpage(client):
    response = client.get('/')
    assert  b'The Cozy Inn Hotel' in response.data
