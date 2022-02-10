
import requests
import re, tldextract, whois, favicon, socket #pip install python-whois
import dns.resolver #pip install dnspython
import xmltodict
import tarfile
import os.path, time, datetime


suspectScore = 0

#for low and high severity suspecious : Score = Score + 1

#1
def checkIp(url):
    global suspectScore
    checkIp=re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",url) or re.search("(([+-]?(?=\.\d|\d)(?:\d+)?(?:\.?\d*))(?:[eE]([+-]?\d+))?([a-zA-Z]+([+-]?(?=\.\d|\d)(?:\d+)?(?:\.?\d*))(?:[eE]([+-]?\d+))?)+)",url)
    if checkIp:
        suspectScore=suspectScore+1
        return True
    else:
        return False
#2
def checkUrlLength(url):
    global suspectScore
    if len(url) < 54:
        return False
    elif(len(url)>=54 and len(url)<=75):
        suspectScore=suspectScore+1
        return True
    else:
        suspectScore=suspectScore+1
        return True
#3
def checkUrlSymbol(url):
    global suspectScore
    if "@" in url:
        suspectScore=suspectScore+1
        return True
    else:
        return False
#4
def checkDomainHyphen(url):
    global suspectScore
    ext = (tldextract.extract(url)).domain
    if "-" in ext:
        suspectScore=suspectScore+1
        return True
    else:
        return False
#5
def checkDomainAge(url):
    global suspectScore
    w = whois.whois(url)
    w = w['creation_date'][0]
    now = datetime.datetime.today()
    days = int((str((now - w)).split())[0])
    if days < 182:
        suspectScore=suspectScore+1
        return True
    else:
        return False
#6
def checkDomainExpiry(url):
    global suspectScore
    w = whois.whois(url)
    w = w['expiration_date'][0]
    now = datetime.datetime.today()
    days = int((str((w - now)).split())[0])
    if days < 365:
        suspectScore=suspectScore+1
        return True
    else:
        return False

#7
def checkFaviconSource(url):
    global suspectScore
    givenUrl = (tldextract.extract(url)).domain
    icon = (tldextract.extract(favicon.get(url)[0][0])).domain
    if givenUrl != icon:
        suspectScore=suspectScore+1
        return True
    else:
        return False
#8
def checkShortenUrl(url):
    global suspectScore
    sProviders=['T.LY', 'bit.ly', 'is.gd', 'Ow.ly', 'shrunken.com', 'p.asia', 'g.asia', '3.ly', '0.gp', '2.ly', '4.gp', '4.ly', '6.ly', '7.ly', '8.ly', '9.ly', '2.gp', '6.gp', '5.gp', 'ur3.us', 'tiny.cc', 'soo.gd', 'clicky.me', 'bl.ink', 'buff.ly', 'rb.gy', 't2mio', 'bit.do', 'cutt.ly', 'shorturl.at', 'urlzs.com', 'LinkSplit', 'short.io', 'kutt.it', 'switchy.io', 'han.gl', 'lh.ms']
    for i in sProviders:
        if i in url:
            suspectScore=suspectScore+1
            return True
        else:
            return False
#9
def checkOpenPorts(url):
    global suspectScore
    if(tldextract.extract(url).subdomain):
        ip=tldextract.extract(url).subdomain+"."+tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    else:
        ip=tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    print(ip)
    portsToBeChecked=[21,22,23,80,443,445,1433,1521,3306,3389]
    OpenPortsShouldBe=[80,443]
    OpenPorts=[]
    for port in portsToBeChecked:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((ip, int(port)))
            OpenPorts.append(port)
        except:
            continue
    if(OpenPorts!=OpenPortsShouldBe):
        suspectScore=suspectScore+1
        return True
    else:
        return False
#10
def checkHttpsInDomain(url):
    global suspectScore
    if(tldextract.extract(url).subdomain):
        url=tldextract.extract(url).subdomain+"."+tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    else:
        url=tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    if "https" in url:
        suspectScore=suspectScore+1
        return True
    else:
        return False
#11
def checkDNSRecord(url):
    global suspectScore
    if(tldextract.extract(url).subdomain):
        url=tldextract.extract(url).subdomain+"."+tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    else:
        url=tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    if(dns.resolver.resolve(url, 'MX') or dns.resolver.resolve(url, 'A') or dns.resolver.resolve(url, 'NS') ):
        return False
    else:
        suspectScore=suspectScore+1
        return True
#12
def checkDomainRank(url):
    global suspectScore
    url=tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    url='http://data.alexa.com/data?cli=100&dat=s&url='+str(url)
    response = requests.get(url)
    dict_data = xmltodict.parse(response.content)
    try:
        if(int(dict_data['ALEXA']['SD'][1]['REACH']['@RANK'])<100000):
            return False
        elif(int(dict_data['ALEXA']['SD'][1]['REACH']['@RANK'])>100000):
            suspectScore=suspectScore+1
            return True
    except:
        suspectScore=suspectScore+1
        return True
#13
def checkRedirection(url):
    global suspectScore
    r = requests.get(url, allow_redirects=True)
    if(len(r.history)<=1):
        return False
    elif(len(r.history)>=2 and len(r.history)<4):
        suspectScore=suspectScore+1
        return True
    else:
        suspectScore=suspectScore+1
        return True
#14
def checkMaliciousIframe(url):
    global suspectScore
    r = requests.get(url)
    if('frameborder="0"' in r.text):
        suspectScore=suspectScore+1
        return True
    else:
        return False
#15
def checkRequestURL(url):
    global suspectScore
    domain = (tldextract.extract(url)).domain + "." + (tldextract.extract(url)).suffix
    response = requests.get(url)
    response = response.text
    allurl=re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', response)
    relatedurl=[]
    nonrelatedurl=[]

    for i in allurl:
        if domain in i:
            relatedurl.append(i)
        else:
            nonrelatedurl.append(i)
    try:
        percentagerelatedurl=(((len(relatedurl)/len(allurl)))*100)
        percentagenonrelatedurl=(((len(nonrelatedurl)/len(allurl)))*100)
    except:
        return False
    if(percentagenonrelatedurl < 22):
        return False
    elif(percentagenonrelatedurl>=22 and percentagenonrelatedurl<=61):
        suspectScore=suspectScore+1
        return True
    else:
        suspectScore=suspectScore+1
        return True
#16

def checkPhishDatabase(url):
    global suspectScore
    ti=time.ctime(os.path.getmtime("ALL-phishing-domains.tar.gz"))
    date_time_obj = datetime.datetime.strptime(ti, '%a %b %d %H:%M:%S %Y')

    now=datetime.datetime.today()
    days = (str((now - date_time_obj)).split())
    days=days[0].split(":")
    
    if (int(days[0])>=24):
        response=requests.get("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-domains.tar.gz")
        open('ALL-phishing-domains.tar.gz', 'wb').write(response.content)
        (tarfile.open('ALL-phishing-domains.tar.gz')).extractall('./')

    domain = (tldextract.extract(url)).domain + "." + (tldextract.extract(url)).suffix
    phishdomain = open("ALL-phishing-domains.txt", "r")
    lines = set(phishdomain.read().splitlines())

    if domain in lines:
        suspectScore=suspectScore+1
        return True
    else:
        return False

#17
def checkSlashRedirection(url):
    global suspectScore
    count=len(re.findall("//",url))
    if count>1:
        return True   
    else:
        return False

#18
def checkSubdomainCount(url):
    global suspectScore
    if(tldextract.extract(url).subdomain):
        url=(tldextract.extract(url).subdomain).split(".")
        print(url)
        subdomain=len(url)
        if subdomain>1:
            return True
        else:
            return False
    else:
        return False