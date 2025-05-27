import requests

def test_dashboard():
    response = requests.get('http://127.0.0.1:5000/')
    assert response.status_code == 200
    assert 'Welcome to the Dashboard' in response.text

if __name__ == '__main__':
    test_dashboard()
    print("Test passed!")
