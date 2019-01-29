def get_telnet(ip, port=23):
    import telnetlib
    with telnetlib.Telnet(ip, port, timeout=1) as s:
        return s.read_some().decode()
        
def recon(ip, port):
    import requests, models
    r=requests.get("http://{}:{}/".format(ip, port))
    data=r.text+str(r.headers)
    try:
        data+=get_telnet(ip)
    except:
        pass
    for brand in models.dataset:
        here=list(filter(lambda i: i in data, models.dataset[brand]))
        if here:
            return brand+' '+here[0]
