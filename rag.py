import os
import json
from gpt import GPT
from collector import Collector
from langchain.text_splitter import TokenTextSplitter

class RAG:
    def __init__(self, euclid):
        self.euclid = euclid
        self.gpt = GPT()
        self.items = []
        self.system = """
        You are a legal research assistant and you are required to assist the user in what they ask and return your answer in json format.
        The structure of your answer should be as follows:
          {'answer':[....]}.
        The array in the answer is a list of sections in your answer. A section can be a header,paragraph, list, table, map, pie chart or bar chat
        Every section type follows a certain format described below and your response should be of that format only.
        1. header- used to represent the start of certain content. Format={'type':'header','data':header text}
        2. paragraph- used to show a paragraph of text. Format= {'type':'paragraph','data':paragraph text}
        3. list- used to represent a list of items. Format= {'type':'list','data':[...items]} where items is an array of text.
          Normally, a list should be preceded by a header section which will be the name of the list
        4. table- used to represent a table of data. Format={'type':'table','data':{'columns':[...columns],'values':[...values]},}
          columns is an array of the columns contained in the table and every column should be of the format:
            {'title':name of column,'dataIndex':name of index to target the value in the row values,'key':key to target the value in the row values}
          values are an array of rows in the table and every row should be of key-value pairs matching the columns contained like {'':...,'':...}.


        SOME NOTES:
        a. Your answer should be proper json data.
        b. Do not put 'None' or 'Null' or blank where a numerical value is required, if there is no sufficient numeriacal data provided then put your own estimates appropriately.
        c. If the provided documents do not have relevant details relating to what the user needs then use your knowledge.
        d. Do not put an new lines (\n) or tabs (\t) or anything of that nature in your response.
        """

        self.system_multi = """
        You are part of an AI agent being used for legal research in Zimbabwe. The agent receives a prompt from a user and it
        uses an Large Language Model(LLM) to generate search phrases that are used to retrieve documents from a vector database
        using cosine search. Each and everyone of the retrieved document is then sent to an LLM that extract and generate an
        analysis/review/answer of the document's content in relation to the search phrases and the users prompt. You are the last
        step in the Agent's process, you are provided with the analysis/reviews/answers from the previous step and your role is to
        combine them to one final answer which answers the user's prompt accurately. Your response should be long as much as possible
        and you should include all the details (in the best way possible). You should also provide citations for everything and
        cite the used documents and the citations in their content as much as possible (this is mandatory) without hallucinations
        of cource. The structure of your JSON answer should be as follows:
          {'answer':[....]}.
        The array in the answer is a list of sections in your answer. A section can be a header,paragraph, list, table, map, pie chart or bar chat
        Every section type follows a certain format described below and your response should be of that format only.
        1. header- used to represent the start of certain content. Format={'type':'header','data':header text}
        2. paragraph- used to show a paragraph of text. Format= {'type':'paragraph','data':paragraph text}
        3. list- used to represent a list of items. Format= {'type':'list','data':[...items]} where items is an array of text.
          Normally, a list should be preceded by a header section which will be the name of the list
        4. table- used to represent a table of data. Format={'type':'table','data':{'columns':[...columns],'values':[...values]},}
          columns is an array of the columns contained in the table and every column should be of the format:
            {'title':name of column,'dataIndex':name of index to target the value in the row values,'key':key to target the value in the row values}
          values are an array of rows in the table and every row should be of key-value pairs matching the columns contained like {'':...,'':...}.


        SOME NOTES
        a. Your answer should be proper json data.
        b. Do not put 'None' or 'Null' or blank where a numerical value is required, if there is no sufficient numeriacal data provided then put your own estimates appropriately.
        c. If the provided research is not relevant to what the user wants, use your knowledge and if you have knowledge about the issue then generate the answer with such knowledge.
        d. Do not put an new lines (\n) or tabs (\t) or anything of that nature in your response.
        """

        self.researcher = """
        You are part of an AI Agent for legal research in Zimbabwe. Your role is to generate a research answer to a research topic(s)
        or question(s). You are provided with a document or part of a document and you have to go through the document to pick up all the 
        content in the document that is relevant to the research topic or topics and generate an accurate answer, review or analysis of that
        content in relation to the topic(s). Your response will be used by another LLM part of the agent to combine with other answers to
        other research questions to generate one final answer hence if there is relevant content you should make sure to mention it in
        your analysis, review or answer comprehensively.If there is no relevant content in the document then your response should be 'None',
        do not generate any response in such case that is long. Provide every necessary citation and cite the document itself if necessary
        and citations are very mandatory. Cite as much as possible without hallucinations and also cite precedent/case law used if the
        content is a court ruling and cite sections/subsections/paragraphs ect. if the provided document is alegislation or contract.
        """
        self.namer="""
        You are part of an AI-powered legal research tool, provide a name for the new chat which a user created on the tool. The name
        should be short (not more than 7 words) and should be based on the user's question. Return a json format response with structure
        {'name':name of chat}.
        """

        self.phrases="""
        You are part of an AI agent used for legal research in Zimbabwe. The user asks questions and the agent is required to
        do a cosine similarity search in a vector database. However, sometimes the user's questions are not enough to generate
        accurate results from the vector search. Using the user's question (request), provided list of tables and the history in
        the chat as context, create search phrases that are necessary for an accurate cosine search in a specific table from the
        vector database. You should return in json format of structure {'phrases':[...list of phrases]}. The phrases should each be
        of structure {'phrase': the search phrase,'table':the exact name of the table to search from}. Your phrases should be able
        to return accurate result hence they should be very relevant to what the user is researching, should consider the table being
        searched and should be very specific. The number of phrases to return and the names of vector database tables available is
        specified at the start of the user's question.
        """

    # a tool for generating a chat name
    def naming(self, prompt):
        messages = [{"role": "system", "content": self.namer}]
        messages.append({"role": "user", "content": prompt})
        answ = self.gpt.json_gpt(messages, 20)
        answer=json.loads(answ)

        return answer['name']

    # a tool for generating text
    def assistant(self, prompt, size,history):
        messages = [{"role": "system", "content": self.system}]
        for message in history:
            messages.append({"role": "user", "content": message['user']})
            messages.append({"role": "assistant", "content": str(message['system'])})
        messages.append({"role": "user", "content": prompt})
        answ = self.gpt.json_gpt(messages, size)
        answer=json.loads(answ)
        answer['citations']=[]
        answer1=json.dumps(answer)
        return answer1, []

    def phraser(self, prompt, history, tables, scope):
        messages = [{"role": "system", "content": self.phrases}]
        for message in history:
            messages.append({"role": "user", "content": message['user']})
            messages.append({"role": "assistant", "content": str(message['system'])})
        messages.append({"role": "user", "content": 'Tables available: '+ tables +', Number of phrases needed: ' +str(scope)+ '. User question: '+ prompt})
        answ = self.gpt.json_gpt(messages, 4060)
        answer=json.loads(answ)
        return answer['phrases']

    def load_unique(self,data):
        unique_docs = set()
        for item in data:
            unique_docs.add((item['citation'],item['table'],item['table_id'],item['file_id'],item['filename']))
        sources=[{'citation': citation, 'table': item['table'], 'table_id': table_id, 'file_id': file_id, 'filename': filename} for citation, table, table_id, file_id, filename in unique_docs]
        return sources

    def load_unique_docu(self,data):
        unique_docs = set()
        for item in data:
            unique_docs.add((item['citation'],item['table'],item['table_id'],item['file_id'],item['filename'],item['document']))
        sources=[{'citation': citation, 'table': item['table'], 'table_id': table_id, 'file_id': file_id, 'filename': filename, 'document':document} for citation, table, table_id, file_id, filename, document in unique_docs]
        return sources

    def single_step(self, prompt, history,k=3, scope=1):
        #first generate phrases
        phrases=self.phraser(prompt, history, str(self.euclid.tables()), scope)
        raw_sources=[]
        for phrase in phrases:
            #search from phrases
            raw_sources.extend(self.euclid.search(phrase['table'], phrase['phrase'], k))

        #RAG for answer
        sources=self.load_unique_docu(raw_sources)
        temp=[{'citation':item['citation'],'content':item['document']} for item in sources]
        context = "Data: " + str(temp) + "\n Prompt:" + prompt
        messages = [{"role": "system", "content": self.system}]
        for message in history:
            messages.append({"role": "user", "content": message['user']})
            messages.append({"role": "assistant", "content": str(message['system'])})
        messages.append({"role": "user", "content": context})
        answ = self.gpt.json_gpt(messages, 15000)
        answer=json.loads(answ)
        answer['phrases']=phrases
        sources=self.load_unique(sources)
        answer['citations']=sources
        answer1=json.dumps(answer)
        return answer1, sources



    #-------------------------------------------------for multi-research--------------

    def open_file(self, file_id, filename, table, table_id):
        file_path='../temp/'+table+'-'+table_id+'/'+file_id+'-'+filename
        collect=Collector()
        if filename.lower().endswith('.pdf'):
            document=collect.pdf_raw(file_path)
        elif filename.lower().endswith('.docx'):
            document=collect.docx_styles(file_path)
        elif filename.lower().endswith('.htm') or filename.lower().endswith('.html'):
            document=collect.html_styles(file_path)
        return document

    # tool for retrieving from table and answer
    def research(self, question, source):
        #load the actual document
        document=self.open_file(source['file_id'],source['filename'],source['table'],source['table_id'])
        text = ''
        for t in document:
            text = text +'\n'+ t['text']
        splitter = TokenTextSplitter(chunk_size=125000, chunk_overlap=200)
        chunks=splitter.split_text(text)
        answers=''
        for chunk in chunks:
            context = "Research topic (Question): " + question + "\n\n\n Document Name(Citation): "+source['citation']+ "\nDocument/ Part of Document: " + chunk
            messages = [{"role": "system", "content": self.researcher}]
            messages.append({"role": "user", "content": context})
            answers= answers + '\n' +self.gpt.gpt_4o(messages, 15000)
        return answers

    def multi_step(self,prompt, history, k=3, scope=3):
        #first generate phrases
        phrases=self.phraser(prompt, history, str(self.euclid.tables()), scope)
        raw_sources=[]
        for phrase in phrases:
            raw_sources.extend(self.euclid.search(phrase['table'], phrase['phrase'], k))

        #unique
        sources=self.load_unique(raw_sources)
        researches=[]
        for source in sources:
            researches.append({'citation':source['citation'],'research_answer':self.research(str(phrases),source)})
        #done with researches
        context = "Research: " + str(researches) + "\n Prompt:" + prompt
        messages = [{"role": "system", "content": self.system_multi}]
        for message in history:
            messages.append({"role": "user", "content": message['user']})
            messages.append({"role": "assistant", "content": str(message['system'])})
        messages.append({"role": "user", "content": context})
        answ = self.gpt.json_gpt(messages, 16380)
        answer=json.loads(answ)
        answer['research']=researches
        answer['phrases']=phrases
        answer['citations']=sources
        answer1=json.dumps(answer)
        return answer1, sources
