from typing import Any
import logging
import colorlog
import tls_client
import threading
import multiprocessing
import time
import names
import datetime
import secrets
import os
import random
import re
import ctypes
import misc.encrypt as encr

formatter = colorlog.ColoredFormatter(
    '%(white)s[%(asctime)s] %(white)s%(log_color)s%(levelname)-8s %(white)s%(message)s',
    datefmt='%H:%M:%S',
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%'
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger.addHandler(console_handler)


class Utils:
    @staticmethod
    def char_correction(text: str) -> str:
        _pattern = re.compile(r'\\u[\da-fA-F]{4}')

        def replace_seq(match):
            _chars = int(match.group(0)[2:], 16)
            return chr(_chars)

        return _pattern.sub(replace_seq, text)

    @staticmethod
    def generate_birth() -> str:
        b_year = random.randint(1980, 2000)
        b_month = random.randint(1, 12)
        b_day = Utils.get_rnd(b_month, b_year)
        return f"{b_day}:{b_month}:{b_year}"

    @staticmethod
    def get_rnd(b_month: int, b_year: int) -> int:
        days = {
            1: 31,
            2: 29 if b_year % 4 == 0 and (b_year % 100 != 0 or b_year % 400 == 0) else 28,
            3: 31,
            4: 30,
            5: 31,
            6: 30,
            7: 31,
            8: 31,
            9: 30,
            10: 31,
            11: 30,
            12: 31
        }
        return random.randint(1, days[b_month])


class Generator():
    def __init__(self):
        """
        Base information
        """
        self.canary = None
        self.tcxt = None
        self.hpgid = None
        self.fid = None
        self.uaid = None
        self.siteId = None
        self.SKI = None
        self.randomNum = None
        self.key = None

        """
        Session information
        """
        self.session = tls_client.Session(client_identifier='chrome_107')
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0"
        self.site_key = "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"
        self.first_name: str = names.get_first_name()
        self.last_name: str = names.get_last_name()
        self.account_domain = '@outlook.com'
        self.account_country = 'US'
        self.account_mkt = 'en-US'
        self.generated_mail: str = self.last_name + secrets.token_urlsafe(3) + self.account_domain
        self.generated_password: str = self.first_name + secrets.token_hex(2).upper() + secrets.token_hex(2) + '!!B0wGen'
        self.signup_base = f"https://signup.live.com"

        """
        Session init
        """
        self.prepare_session()
        self.encryption = encr.ms_encrypt(self.generated_password, self.generated_mail, self.key)
        
    def solve_captcha(self):
        return "Solve captcha here."

    def prepare_session(self) -> None:
        response_text = self.session.get(f"{self.signup_base}/signup?lic=1&mkt={self.account_mkt}", headers={
            "accept": "application/json",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "hpgid": self.hpgid,
            "origin": f"{self.signup_base}",
            "sec-ch-ua": '" Not A;Brand";v="107", "Chromium";v="96", "Google Chrome";v="96"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "referrer": f"{self.signup_base}/?lic=1"
        }).text

        regex_match = re.search(
            r'var Key="(?P<key>[^"]+)".*?var randomNum="(?P<randomNum>[^"]+)".*?var SKI="(?P<SKI>[^"]+)"',
            response_text, re.DOTALL
        )

        """
        Encryption information
        """
        self.key = regex_match.group('key')
        self.randomNum = regex_match.group('randomNum')
        self.SKI = regex_match.group('SKI')

        """
        Needed information
        """
        self.uaid = re.search(r'"clientTelemetry":{"uaid":"([^"]+)"', response_text).group(1)
        self.tcxt = Utils.char_correction(re.search(r'"tcxt":"([^"]+)"', response_text).group(1))
        self.canary = Utils.char_correction(re.search(r'"apiCanary":"([^"]+)"', response_text).group(1))

        """
        MISC information
        """
        self.siteId = re.search(r'"siteId":"([^"]+)"', response_text).group(1)
        self.fid = re.search(r'"fid":"([^"]+)"', response_text).group(1)
        self.hpgid = re.search(r'"hpgid":(\d+)', response_text).group(1)

    def obtain_body(self) -> dict:
        return {
            "RequestTimeStamp": datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "MemberName": self.generated_mail,
            "CheckAvailStateMap": [
                f"{self.generated_mail}:undefined"
            ],
            "EvictionWarningShown": [],
            "UpgradeFlowToken": {},
            "FirstName": self.first_name,
            "LastName": self.last_name,
            "MemberNameChangeCount": 1,
            "MemberNameAvailableCount": 1,
            "MemberNameUnavailableCount": 0,
            "CipherValue": self.encryption,
            "SKI": self.SKI,
            "BirthDate": Utils.generate_birth(),
            "Country": self.account_country,
            "IsOptOutEmailDefault": True,
            "IsOptOutEmailShown": True,
            "IsOptOutEmail": True,
            "LW": True,
            "SiteId": self.siteId,
            "IsRDM": 0,
            "WReply": None,
            "ReturnUrl": None,
            "SignupReturnUrl": None,
            "uiflvr": 1001,
            "uaid": self.uaid,
            "SuggestedAccountType": "OUTLOOK",
            "SuggestionType": "Locked",
            "HFId": self.fid,
            "encAttemptToken": "",
            "dfpRequestId": "",
            "scid": 100118,
            "hpgid": self.hpgid
        }

    def send_create_request(self, body: dict):
        headers = {
            "accept": "application/json",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "canary": self.canary,
            "content-type": "application/json",
            "dnt": "1",
            "hpgid": self.hpgid,
            "origin": f"{self.signup_base}",
            "pragma": "no-cache",
            "scid": "100118",
            "tcxt": self.tcxt,
            "uaid": self.uaid,
            "uiflvr": "1001",
            "user-agent": self.ua,
            "x-ms-apitransport": "xhr",
            "x-ms-apiversion": "2",
            "referrer": f"{self.signup_base}/?lic=1"
        }
        return self.session.post(f"{self.signup_base}/API/CreateAccount?lic=1",
                                 headers=headers,
                                 json=body)

    def _add_captcha_fields(self, body, error, captcha_response) -> dict:
        body['HType'] = "enforcement"
        body['HSol'] = captcha_response
        body['HPId'] = self.site_key
        body['encAttemptToken'] = Utils.char_correction(error['data'].split('encAttemptToken":"')[1].split('"')[0])
        body['dfpRequestId'] = Utils.char_correction(error['data'].split('dfpRequestId":"')[1].split('"')[0])
        return body

    def create_account(self) -> dict[str, Any] | None:
        body = self.obtain_body()
        request = self.send_create_request(body).json()

        error = request['error']
        if error['code'] == '1041':
            captcha_response = self.solve_captcha()
            logger.info(f"Solved captcha {captcha_response.split('|')[0]}")
            body = self._add_captcha_fields(body, error, captcha_response)
            self.send_create_request(body)

            request = self.send_create_request(body)
            if request.status_code == 200:
                logger.info(f"Generated {self.generated_mail}:{self.generated_password}")
                # Return a dict of the username and password or save the account here.
            else:
                logger.info(f"Failed to generate {self.generated_mail}:{self.generated_password} ({error['code']})")
        else:
            logger.info(f"Failed to generate {self.generated_mail}:{self.generated_password} ({error['code']})")
        return None


def run() -> None:
    while True:
        try:
            Generator().create_account()
        except:
            continue
    return None


def run_threads():
    for _ in range(1):
        threading.Thread(target=run).start()


if __name__ == '__main__':
    for _ in range(1):
        multiprocessing.Process(target=run_threads).start()
