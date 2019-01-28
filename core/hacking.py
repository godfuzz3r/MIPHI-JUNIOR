import requests, base64

def basic_auth(ip, port, user='admin', pas='admin'):
    userpass=base64.b64encode('{}:{}'.format(user, pas).encode()).decode()
    r=requests.get('http://{}:{}'.format(ip, str(port)), headers={'Authorization': 'Basic {}'.format(userpass)})
    if r.status_code==200:
        return True
    else:
        return False
