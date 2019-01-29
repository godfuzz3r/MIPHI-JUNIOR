import requests
import bs4

def model_to_cves(link):
    vendor = link.split('vendor_id=')[-1].split('&')[0]
    idd, brand = link.split('/')[2:4]
    brand=brand.split('?')[0]
    return 'https://www.cvedetails.com/vulnerability-list/vendor_id-{}/product_id-{}/{}'.format(vendor, idd, brand)
def get_cves(model):
    #main function here
    #model is a string like 'DIR-300' or 'RT-AC66U'
    r = requests.get('https://www.cvedetails.com/product-search.php?vendor_id=0&search={}'.format(model))
    soup = bs4.BeautifulSoup(r.text, 'html.parser').find('table', {'class':'listtable'}).find_all('tr')[1:]
    if 'Could not find any products' not in soup[0].text:
        vulns=model_to_cves(soup[0].a['href'][2:])
        soup=bs4.BeautifulSoup(requests.get(vulns).text, 'html.parser').find('table', {'id':'vulnslisttable'})
        return list(map(lambda i: 'https://www.cvedetails.com'+i.find_all('a')[1]['href'], soup.find_all('tr', {'class':'srrowns'})))
    else:
        return []
