import os
import json
from gpt import GPT
from rag import RAG
from heads import Heads

class Assist:
    def __init__(self, euclid):
        self.euclid = euclid
        self.gpt = GPT()
        self.system = """
        You are part of an AI Agent that is being used to assist lawyers and legal practitioners in doing their work. Your role
        is to decide on what tool to use to assist the user based on the user's prompt and the history of the chat. The possible
        tools will be provided below and you are required to just pick one. Your response should be in JSON format {'tool': name
        of tool as is}. The following are the tools with a short description:
        [{'name':'Legal Research','desc':'for doing legal research'},
         {'name':'Heads','desc':'For drafting heads of arguments for a lawyer'}
        ]
        """

    # a tool for generating a chat name
    def selector(self, prompt, history):
        messages = [{"role": "system", "content": self.system}]
        for message in history:
            messages.append({"role": "user", "content": message['user']})
            messages.append({"role": "assistant", "content": str(message['system'])})
        messages.append({"role": "user", "content": prompt})
        answ = self.gpt.json_gpt(messages, 20)
        answer=json.loads(answ)

        return answer['tool']

    # run and select the correct assistant
    def run(self, table, prompt,history):
        tool=self.selector(prompt,history)
        if tool=='Heads':
            heads=Heads(self.euclid)
            tables=self.euclid.tables()
            answer,sources=heads.run(str(tables), prompt, history, 3)
            return answer, sources
        else:
            rag=RAG(self.euclid)
            answer, sources=rag.multi_step(table, prompt, history, 3, 3)
            return answer, sources