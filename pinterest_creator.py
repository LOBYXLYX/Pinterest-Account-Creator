import re
import json
import time
import httpx
import random
import secrets
import requests
import ua_generator

from colr import Colr
from datetime import datetime
from solver import Solver
from concurrent.futures import ThreadPoolExecutor

L = '\033[90m'  # Grey
G = '\033[92m'  # Green
W = '\033[0m'   # White

# Config

ACCOUNT_USERNAME = 'Patikk'

FOLLOW_USER = True
PROFILE_USER_OPTIONS = '{"options":{"user_id":"1081638172913321258"},"context":{}}'
PROFILE_USERNAME = '/kaxygutky/'


class Console:
    def log(content, mode, color, ms=None):
        colors_list = {
            'blue': f'\x1b[48;5;21m',
            'green': f'\x1b[48;5;34m',
            'red': f'\x1b[48;5;161m'
        }
        white = Colr().hex('#FFFFFF')
        _time = datetime.now().strftime('%H:%M:%S')

        color = colors_list[color]
        print(_time, f'{L}|{W} {color}{mode.title()}{W} {L}|{W} {ms}s', f'{L}|{W}', content, W)

class TempMailAPI:
    def __init__(self) -> None:
        self.api = 'http://disposablemail.com'
        self.client = httpx.Client(follow_redirects=True)
        self.client.headers = {
            'x-requested-with': 'XMLHttpRequest'
        }

        self.attempt = 0
        self.email = None
        self._setup()

    def _setup(self) -> None:
        site = self.client.get(self.api)
        self.client.cookies = site.cookies

    def new_email(self) -> str:
        email_data = self.client.get(f'{self.api}/index/index/').text
        self.email = str(email_data).split('{"email":"')[1].split('","heslo"')[0]
        return self.email

    def verify_account(self):
        verify_url = None

        while not verify_url or self.attempt >= 25:
            messages = self.client.get(f'{self.api}/index/refresh')

            for message in messages.json():
                print(message)
                index_id = message['id']

                if index_id in [2, 3]:
                    window = self.client.get(f'{self.api}/email/id/{index_id}/')
                    print(window.text)
                    verify_url = str(window.text).split('class="pd_dm_df" href="')[1].split('"')[0]
                    print(verify_url)
                    break
                
                self.attempt += 1
                time.sleep(1)
        
        if verify_url is not None:
            verify = self.client.get(verify_url)
            if verify.status_code == 200:
                return True
            else:
                return False
        return False

class Pinterest:
    def __init__(self, username):
        self.username = username + '_' + str(random.randint(10000,30000))

        self.session = requests.Session()
        ua = ua_generator.generate(device='desktop', browser=('chrome', 'edge'))
        self.session.headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-language": "es-US,es-419;q=0.9,es;q=0.8",
            "cache-control": "max-age=0",
            "sec-ch-ua": ua.ch.brands,
            "sec-ch-ua-mobile": ua.ch.mobile,
            "sec-ch-ua-platform": ua.ch.platform,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": ua.text
        }
        self.proxies = open('proxies.txt', 'r').read().strip().splitlines()
        self.url = 'https://co.pinterest.com'
        self.solution = Solver(
            '6Ldx7ZkUAAAAAF3SZ05DRL2Kdh911tCa3qFP0-0r',
            self.url
        )

    def _pinterest_setup(self):
        site = self.session.get(self.url)

        self.session.cookies = site.cookies
        self.session.headers.update({
            'X-App-Version': 'd31bac2',
            'X-Csrftoken': site.cookies['csrftoken'],
            'X-Pinterest-Appstate': 'active',
            'X-Pinterest-Source-Url': '/signup/step3/',
            'X-Pinterest-Pws-Handler': 'www/signup/step[step].js',
            'X-Requested-With': 'XMLHttpRequest'
        })

    def _get_recaptcha_token(self):
        start = time.time()
        re_token = self.solution.token()
        endof = round(time.time() - start, 3)

        Console.log(f'reCaptcha Enterprise {L}|{G} {re_token[:50]}....', mode='solved', color='blue', ms=endof)
        return re_token

    def get_account_user_id(self):
        me = self.session.get(self.url)

        comp = re.compile(r'"id":"([^"]+)"')
        return comp.findall(me.text)[0]

    def follow_user(self):
        self.session.headers['X-Pinterest-Source-Url'] = PROFILE_USERNAME
        self.session.headers['X-Pinterest-Pws-Handler'] = 'www/[username].js'

        start = time.time()
        follow = self.session.post(
            f'{self.url}/resource/UserFollowResource/create/',
            data={
                'source_url': PROFILE_USERNAME,
                'data': PROFILE_USER_OPTIONS
            }
        )
        endof = round(time.time() - start, 3)
        if follow.status_code == 200:
            Console.log(f'{PROFILE_USER_OPTIONS}', mode='followed', color='green', ms=endof)
        else:
            Console.log(f'Follow User Error: {follow.status_code}', mode='failed', color='red', ms=endof)

    def _random_string(self, length=16):
        strings = 'qwertyuiopasdfghjklzxcvbnm'
        return ''.join([random.choice(strings) for i in range(length)])

    def create_account(self, email):
        password = secrets.token_urlsafe(8)

        signup_data_options = {
            "options": {
                "type": "email",
                "birthday": "988934400",
                "email": email,
                "first_name": self.username,
                "password": password,
                "has_ads_credits": False,
                "recaptchaV3Token": self._get_recaptcha_token(),
                "user_behavior_data": "{}",
                "visited_pages": "",
                "get_user": ""
            },
            "context": {}
        }
        start = time.time()
        register = self.session.post(
            f'{self.url}/resource/UserRegisterResource/create/',
            data={
                'source_url': '/signup/step3/',
                'data': json.dumps(signup_data_options)
            }
        )
        endof = round(time.time() - start, 3)

        if register.status_code == 200:
            pina_token = register.json()['resource_response']['data']['v5_access_token']
            Console.log(f'{self.username} {L}|{W} {pina_token[:40]}....', mode='created', color='green', ms=endof)

            open('pin_accounts.txt', 'a+').write(f'{self.username}:{email}:{password}\n')

            self.session.cookies.update(register.cookies.get_dict())
            if FOLLOW_USER:
                self.follow_user()
        else:
            error = register.json()['resource_response']['error']['message']
            Console.log(f'{self.username} {L}|{W} {error}', mode='failed', color='red', ms=endof)

    def run_thread(self):
        try:
            if len(self.proxies) > 999:
                proxy = random.choice(self.proxies)
                self.session.proxies = {
                    'http': proxy,
                    'https': proxy
                }
            print(self.session.proxies)

            self._pinterest_setup()
            #temp = TempMailAPI()

            email = self._random_string(12) + '@gmail.com'
            #print('[success] Generated Email:', email)

            self.create_account(email)

            #temp.verify_account()
            self.session.cookies.clear()
            self.session.proxies.clear()
        except Exception as e:
            print(e)

if __name__ == '__main__':
    amount = int(input('Account Amount: '))
    

    with ThreadPoolExecutor(max_workers=35) as executor:
        for i in range(amount):
            s = Pinterest(ACCOUNT_USERNAME)
            executor.submit(s.run_thread)
