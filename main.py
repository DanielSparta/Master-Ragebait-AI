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

    def get_last_15_threads_from_cs2_forum(self):
        response = self.send_request("GET", self.steam_cs2_forum_discussion_url)
        response.encoding = 'utf-8'
        regex_output = re.findall(self.thread_topics_regex_detect, response.text)
        thread_topic_list = []
        for i in range(len(regex_output)):
            thread_topic_list.append(regex_output[i].strip())
        return thread_topic_list
    
    def set_last_15_threads_from_cs2_forum(self, last_15_threads_topics):
        self.last_15_threads_topics = last_15_threads_topics



if __name__ == "__main__":
    instance = Bot("76561198326145114%7C%7CeyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInI6MDAwNl8yNUZCQTI1QV83QTAyRCIsICJzdWIiOiAiNzY1NjExOTgzMjYxNDUxMTQiLCAiYXVkIjogWyAid2ViOmNvbW11bml0eSIgXSwgImV4cCI6IDE3NDMxNDI1MzUsICJuYmYiOiAxNzM0NDE1MTA2LCAiaWF0IjogMTc0MzA1NTEwNiwgImp0aSI6ICIwMDBDXzI2MENEMEQ2X0I0NjUyIiwgIm9hdCI6IDE3NDIzMjgwNjYsICJydF9leHAiOiAxNzYwNTQxMDAyLCAicGVyIjogMCwgImlwX3N1YmplY3QiOiAiNzcuMTM3Ljc0LjI5IiwgImlwX2NvbmZpcm1lciI6ICI3Ny4xMzcuNzQuMjkiIH0.m4BYnfliLGDyiqgrxihbZ2-XBtPyP7Bq-imLkUdrFApB9s_7q6Hcxe2ufb_HSVfqALHUVgHJ4fu8sRXhVcZgDQ")
    all_thread_topics = instance.get_last_15_threads_from_cs2_forum()
    instance.set_last_15_threads_from_cs2_forum(all_thread_topics)
    
