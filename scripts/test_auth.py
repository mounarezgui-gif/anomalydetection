import json
import urllib.error
import urllib.request

for action in ('register','login'):
    if action=='register':
        url='http://localhost:8004/auth/register'
        data={'nom':'Test User','email':'test@example.com','password':'TestPass123'}
    else:
        url='http://localhost:8004/auth/login'
        data={'email':'test@example.com','password':'TestPass123'}
    b = json.dumps(data).encode()
    req=urllib.request.Request(url, data=b, headers={'Content-Type':'application/json'})
    try:
        resp=urllib.request.urlopen(req)
        print(action.upper(), resp.status, resp.read().decode())
    except urllib.error.URLError as e:
        print(action.upper(),'ERROR', e)
