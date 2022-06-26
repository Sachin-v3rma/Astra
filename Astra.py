#!/usr/bin/python3
# By Sachin verma

import asyncio, aiohttp
import re, time, argparse, sys
from html import unescape as us
from aiohttp.client_exceptions import InvalidURL
from bs4 import BeautifulSoup as bs4
import urllib.parse as urlparse

regex_url = r"""
    (?:
    (?<=['|"|=])[a-zA-Z0-9_/:-]{1,}/[a-zA-Z0-9_./-]{3,}(?:[?|#][^"|\']{0,}|)|                   # URLs
    [a-zA-Z0-9_/.:-]{1,}.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?|#][^"|\']{0,})|  # URLs with d/f extension
    (?:(?<=['|"|=|:])/|\.\./|\./)[A-Za-z0-9_/.-]+|                                              # Paths like /,../,/./
    [a-zA-Z0-9_/-]{1,}/[a-zA-Z0-9_/-]{1,}\.(?:[a-zA-Z./]{1,}|action)(?:[\?|#][^"|']{0,}|)|      # Endpoints
    (?:https?|ftp|file)://[^,;:()"\n<>`'\s]+                                                    # URLs d/f protocols
    )
"""
regex_secret = {
    'AWS Access key':r'((?:A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})',
    'Amazon_AWS_Auth_Token':r'(amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
    'Zapier Webhook Token':r'(https://(?:www.)?hooks\.zapier\.com/hooks/catch/[A-Za-z0-9]+/[A-Za-z0-9]+/)',
    'Stripe Secret Key':r'([prs]k_(?:live|test)_[0-9a-zA-Z]{24})',
    'Slack Bot':r'(xoxb-[0-9A-Za-z\\-]{51})', 
    'Slack user':r'(xoxp-[0-9A-Za-z\\-]{72})',
    'Slack Webhook':r'(https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})',
    'Braintree-access-token':r'(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})',
    'Zoho Webhook':r'(https://creator\.zoho\.com/api/[A-Za-z0-9/_.-]+\?authtoken=[A-Za-z0-9]+)',
    'Firebase-server-key':r'(AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140})',
    'oauth-access-key':r'(ya29\.[0-9A-Za-z_-]+)',
    'google-calendar-link':r'(https://www\.google\.com/calendar/embed\?src=[A-Za-z0-9%@&;=_./-]+)',
    'google-api-key':r'(AIza[0-9A-Za-z_\\-]{35})',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'general token':r'((?:K|k)ey(?:up|down|press))',
    'general token':r'((T|t)(O|o)(K|k)(E|e)(N|n)[\-|_|A-Za-z0-9]*(\'|")?( )*(:|=)+()*(\'|")?[ 0-9A-Za-z_-]+(\'|")?)',
    'general token':r'((A|a)(P|p)(Ii)[\-|_|A-Za-z0-9]*(\'|")?( )*(:|=)( )*(\'|")?[0-9A-Za-z_-]+(\'|")?)',
    'general token':r'((K|k)(E|e)(Y|y)[\-|_|A-Za-z0-9]*(\'|")?( )*(:|=)( )*(\'|")?[0-9A-Za-z_-]+(\'|")?)',
    'general token':r'(eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]{10,})',
    'jdbc-connection-string':r'(jdbc:[a-z:]+://[A-Za-z0-9\.\-_:;=/@?,&]+)',
    'credentials-disclosure':r'(zopim[_-]?account[_-]?key(=| =|:| :))',
    'Zhuliang Token':r'(zhuliang[_-]?gh[_-]?token(=| =|:| :))',
    'Zensona':r'(zensonatypepassword(=| =|:| :))',
    'Picatic-api-key':r'(sk_live_[0-9a-z]{32})',
    'artifactory-api-token':r'((?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,})',
    'artifactory-api-password':r'((?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,})',
    'amazon-sns-topic':r'(arn:aws:sns:[a-z0-9\-]+:[0-9]+:[A-Za-z0-9\-_]+)',
    'microsoft-teams-webhook':r'(https://outlook\.office\.com/webhook/[A-Za-z0-9@-]+/IncomingWebhook/[A-Za-z0-9-]+/[A-Za-z0-9-]+)',
    'sonarqube-token':r'(sonar.{0,50}(?:"|\'|`)?[0-9a-f]{40}(?:"|\'|`)?)',
    'bitly-secret-key':r'(R_[0-9a-f]{32})',
    'sendgrid-api-key':r'(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})',
    'discord-webhook':r'(https://discordapp\.com/api/webhooks/[0-9]+/[A-Za-z0-9-]+)',
    'cloudinary-credentials':r'(cloudinary://[0-9]+:[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+)',
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_.=:_\+\/-]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_-]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z_-]{43}|sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z_-]{22}|EAAA[a-zA-Z0-9]{60}',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9_=-]+.[A-Za-z0-9_=-]+\.?[A-Za-z0-9_.+/=-]*$',
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'API_Key' : r'(?i)apikey\s?[=|:]\s?(["|\'].*["|\'])(?= ;)',
}

class col:
    magenta = '\033[95m'
    cyan = '\033[96m'
    green = '\033[92m'
    red = '\033[91m'
    reset = '\033[0m'

async def fetch(session, url):
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
    }
    async with session.get(url, allow_redirects=True, headers=headers) as response:
        html = await response.text()
        return html
        
async def linkfinder(url, html):
    regex_url_compiled = re.compile(regex_url, re.VERBOSE)
    url_set = set()
    for data in regex_url_compiled.findall(html):
        url_set.add(urlparse.unquote(us(data)))
    soup = bs4(html, 'html.parser')
    for link in soup.find_all(['iframe','script','link','a','form']):
        url_set.add(link.get('href'))
        url_set.add(link.get('src'))
        url_set.add(link.get('action'))
    for link in url_set:
        parsed_url = urlparse.urljoin(url,link)
        print(f'{parsed_url}')
    for bucket in re.findall(r'(?:[a-zA-Z0-9_-]+s3.amazonaws.com|[a-zA-Z0-9_.-]+amazonaws.com|[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+)', html):
            print(f'[^] {bucket}')
    for ip in re.findall(r'((?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3})', html):
        print(f'[IP] {ip}')
    for script in re.findall(r'src\s*=\s*(?:"|\')[a-zA-Z0-9\!\#\$\&-\:\;\=\?-\[\]_~\|%\/]+(?:"|\')', html):
        parsed_url = urlparse.urljoin(url,script.split('=')[1].strip('"'))
        print(parsed_url)

    global url_counter
    url_counter = url_counter + len(url_set)

async def secretfinder(url,html):
    secret_set = set()
    for regex in regex_secret:
        regex_secret_compiled = re.compile(regex_secret[regex],re.VERBOSE)
        for secret in regex_secret_compiled.findall(html):
            secret_set.add(f'{regex} : {secret} >> [ {url} ]')
    for secret in secret_set:
        print(f'[$] {secret}')
    global secret_counter
    secret_counter = secret_counter + len(secret_set)

async def parser(session, url):
    found = set()
    try:
        html = await fetch(session=session, url=url)
    except (ConnectionRefusedError, aiohttp.client_exceptions.ClientConnectorError):
        print(f'{col.red}Cannot connect to {url}{col.reset}')
        return found
    except asyncio.exceptions.TimeoutError:
        print(f'{col.red}Request Timeout : {url}{col.reset}')
        return found
    except UnicodeDecodeError:
        pass
        return found
    else:
        await linkfinder(url, html)
        if no_secret == False:
            await secretfinder(url,html)

async def start(urls:set, threads) -> None:
    connector = aiohttp.TCPConnector(limit_per_host=threads)
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(connector=connector,timeout=timeout) as session:
        tasks = []
        for url in urls:
            tasks.append(parser(session=session, url=url))
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    tic = time.perf_counter()
    url_counter = 0
    secret_counter = 0
    
    # Arguments
    help_msg = '''
    This Program Scrapes all URLs, S3Buckets, domains, endpoints, IPs, tokens and API keys from a given URL/s.
    It can be a HTML page or JS file or anything like that.

    Example Usage: cat wayback.txt | python3 astra.py
                   echo https://www.google.com | python3 astra.py |tee data.txt
                   cat subdomains.txt | python3 astra.py -t 50 -ns
    '''

    arg_parser = argparse.ArgumentParser(description=help_msg, formatter_class=argparse.RawTextHelpFormatter)
    arg_parser.add_argument('-t', help='Number of threads', dest='threads', type=int, default=10)
    arg_parser.add_argument('-ns', help='Don\'t use SecretFinder', action='store_true',dest='no_secret')
    args = arg_parser.parse_args()
    
    try:
        #Input
        threads = args.threads
        no_secret = args.no_secret
        urls = sys.stdin.readlines()
        urls = set(map(str.strip, urls))

        # Start
        asyncio.get_event_loop().run_until_complete(start(urls, threads))
        # Output
        print(f'\n{col.cyan}Total URLs found : {col.magenta}{url_counter}{col.reset}')
        if no_secret == False:
            print(f'{col.cyan}Total Secrets found : {col.magenta}{secret_counter}{col.reset}')
        print(f"{col.cyan}Finished in {col.magenta}{time.perf_counter() - tic:0.4f}{col.cyan} seconds{col.reset}")
    except KeyboardInterrupt:
        print(f'\n{col.magenta}[-]{col.red} Exiting{col.reset}')
        sys.exit()
    except (InvalidURL,AssertionError):
        print(f'\n{col.magenta}[-]{col.red} Invalid URL. Please make sure, it starts with http/s{col.reset}')
        sys.exit()
    except re.error:
        print(f'\n{col.magenta}[-]{col.red} Error in regex pattern{col.reset}')
        sys.exit()
    except Exception as err:
        print(f'\n{col.magenta}[-]{col.red} Error : {repr(err)}{col.reset}')
        sys.exit()
        
