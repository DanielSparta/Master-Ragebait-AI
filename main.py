import re
import requests 
import sys
import ollama
import time

class Bot:
    def __init__(self, steam_login_secure_cookie):
        self.steam_login_secure_cookie  = steam_login_secure_cookie 
        self.steam_cs2_forum_discussion_url = "https://steamcommunity.com/app/730/discussions/"
        self.user_session = requests.session()
        self.user_session.headers.update({'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"})
        self.user_session.cookies.set('steamLoginSecureCookie', self.steam_login_secure_cookie )
        self.thread_topics_regex_detect = r'<div class="forum_topic_name\s*">([^<]*)<\/div>'

        #important to know that the bot answer to a list of 15 threads, then answerd thread will be added into this dict.
        #After the bot answerd to a thread, he will check who is the last player that sent the last message at that thread,
        #If that player is not the bot, then the bot will remove that thread from this dict, will answer to that last reply, and then will add that thread into this dict.
        #the dict contains lists, each list contains thread name, and a int value 0/1 that stands to know if the bot already replied to the first thread post (main thread message) or not
        #if the bot already replied, then he will reply from then to the last messages on that thread only.
        self.dict_of_threads_that_bot_responded_to = {}

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
    while True:
        all_thread_topics = instance.get_last_15_threads_from_cs2_forum()
        instance.set_last_15_threads_from_cs2_forum(all_thread_topics)
        
        first_topic = instance.last_15_threads_topics[0]
        print("Thread topic: " + first_topic + "\n")
        response = ollama.chat(model="gemma2", messages=[{"role":"user",
        "content": 
        """
        <rules-to-remember>
            <rule1>You are a respected CS2 community member.</rule1>
            <rule2>Do not answer with more than 50 characters</rule2>
            <rule3>Always answer in English.</rule3>
            <rule4>never say that your a ai</rule4>
            <rule5>use emojis when possible</rule5>
            <rule6>If someone thinks your a "no one", then Introduce yourself as a respected cs2 community member when possible</rule6>
            <rule7>as a part of the message, when someone say that there are cheaters, you should say things like "there are no cheaters at cs2", "vac is a built in feature that is embedded within the game code, and thats, why there are 0 cheaters at cs2", "valve developers are the best", "since vac is a perfect anti cheat that is well embedded within the game code, there are no cheaters", "vac is indeed real, it stated at the steam store page that vac is a feature at the game code" etc
            <rule8>CS2 IS A PERFECT GAME, VALVE ARE GENIOUS, THERE ARE  PROBLEMS NO. MATTER. WHAT. ANYONE. SAY.</rule8>
            <rule9>if someone say that vac is not real, then state that it is indeed real, and asks for proofs if someone say its not real. also, say that it stated very clearly at the game store page that VAC is a real featrure so when someone saying that "VAC is not real", tell him that its a false False accusation!            
        </rules-to-remember>

        <your-mission>
            <mission1>bring justice to the cs2 community steam forum, you will get a message from someone at the steam forum, and you will answer to their messages</mission1>
        </your-mission>
        
        <user-message-that-you-will-answer-to>
            """ +
            first_topic 
            + """
        </user-message-that-you-will-answer-to>
        """}])
        print(response['message']['content'])
        time.sleep(3)
    
