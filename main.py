import re
import requests
class Bot:
    def __init__(self, steam_login_secure_cookie):
        self.steam_login_secure_cookie  = steam_login_secure_cookie 
        self.steam_cs2_forum_discussion_url = "https://steamcommunity.com/app/730/discussions/"
        self.user_session = requests.session()
        self.user_session.headers.update({'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"})
        self.user_session.cookies.set('steamLoginSecureCookie', self.steam_login_secure_cookie )
        self.thread_topics_regex_detect = r'<div class="forum_topic_name\s*">([^<]*)<\/div>'

    def send_request(self, request_method, request_url, data = None, params = None):
        response = self.user_session.request(method=request_method, url=request_url, data=data, params=params)
        return response

    def get_last_5_threads_from_cs2_forum(self):
        print(self.send_request("GET", self.steam_cs2_forum_discussion_url))

if __name__ == "__main__":
    instance = Bot()
