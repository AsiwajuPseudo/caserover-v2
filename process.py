import json
import traceback
from gpt import GPT
from euclid import Euclid
from langchain.text_splitter import TokenTextSplitter

class Process:
    def __init__(self):
        self.gpt = GPT()
        self.court = '''
        You are part of a legal citator system in Zimbabwe which is being used to analyze court rulings and format them in an appropriate way.
        The following is from a document of a legal ruling made by a court. You are required to analyze the ruling like you are a professional lawyer.
        Generate the following metadata in json format for this ruling following the rules provided for each data point:
        1. name: generate the correct case name for this case as provided in the ruling.
        2. citation: generate the Case Citation, this will be used to reference this case in the future and it key in this legal citation system.
           A citation should be of the format=> Case name + Court abbreviation + judgement number/judgement year.
           e.g. Bobson v Nyatwa & Anor HH 34/23 or State vs Gilbert SC 197/24
        3. court: this is the court in which the ruling is coming from e.g. High Court of Zimbabwe
        4. date: date when the ruling was made.
        5. case_number: the number of the case if provided.
        6. judges: an array of the name/s of judge/s that decided the matter e.g. ['Dube J','N. Moyo]
        7. summary: this is a summary of the matter which should be less than 300 words.
        8. keywords: pick up keywords that you see fit and put them in an array, the maximum number of keywords is 10.
        9. jurisdiction: The jurisdiction to which this case applies to (geographically or otherwise).
        10. parties: An array of all the parties involved in the case with the role of each applicant specified
            e.g. {'name':'Leeroy Ben','role':'applicant'} or {'name':'Troy Mary','role':'defendant'}
        11. case_law: An array of precedents that were used in this case, the description of the precedents themselves (the description should be more than 20 words highlighting the precedent in full but less than 200 words) and citations of their cases and a result of how that precedent was taken by the case i.e either referred or overruled.
            e.g. {'citation':'Mary v Gideon HH 87/12','desc':'Sets out the criteria for condonation applications.','result':'overruled'}
                 {'citation':'Bishi v Secretary for Education 1989 (2) ZLR 240 (H)','desc':'Discussion on balancing factors in condonation applications.', 'result':'referred'}
        12. legislation: An array of all the sections of legislations used or challenged in the ruling and the result as per interpretation of the ruling. The citation should just be of the legislation's name and the section number (no subsection or paragraphs needed). The description should be more than 20 words highlighting the context in which the legslation was used in full but less than 200 words.
            e.g. {'citation':'Mines Act 2019, Section 2','legislation':'Mines Act 2019','section':'Section 2', 'desc':'Legality of owning a mine','result':'referred'}
                 {'citation':'S.I 23 of 2020, Section 13','legislation':'S.I 23 of 2020','section':'Section 13','desc':'Regulations on operating a mine','result':'overruled'}
        13. set_precedent: An array of any new precedent (can be empty if there is no new precedent) which was established by this case and a description of those precedents in a summary of less than 200 words.
            e.g. {'precedent':'late noting of appeals','desc':'The late noting of an appeal should be done in reasonable time such that....'}
        '''


        self.act = '''
        You are part of a legal citator system which is being used to analyze legislations and extract metadata.
        Retrieve metadata from the following legislation and return in json format. The metadata should be returned in the json object
        of: {'metadata':{'juris':jurisdiction of the legislation,'citation':appropriate citation of a legislation}}. Citation is a specific
        identification of the legislation; for example:
        'Electoral Act, Chapter 24:03', 'Elections Regulations of 2019, Electoral Act' etc.
        '''

    # Method for generating an analysis of court rulings
    def court_proc(self,table, table_id, file_id, filename, document):
        text = ''
        for t in document:
            text = text + t['text']
        messages = [{'role': 'system', 'content': [{'type': 'text', 'text': self.court}]}]
        messages.append({'role': 'user', 'content': [{'type': 'text', 'text': text}]})
        try:
            raw_json = self.gpt.json_gpt(messages)
            content = json.loads(raw_json)
            #embedd rulings
            vector=Euclid()
            meta={'citation':content['citation'],'table_id':table_id,'file_id':file_id,'filename':filename}
            cite=content['citation']+' : '+ content['summary']
            cite_embeds=self.gpt.embedd_text(cite)
            vector.add(table,cite,meta,cite_embeds)
            if len(content['case_law'])>0:
                case_l=''
                for c in content['case_law']:
                    case_l=case_l +'; '+ c['desc']
                #append
                case_embedds=self.gpt.embedd_text(case_l)
                vector.add(table,case_l,meta,case_embedds)
            if len(content['legislation'])>0:
                legi=''
                for c in content['legislation']:
                    legi=legi +'; '+ c['citation'] + ': '+c['desc']
                #append
                legi_embedds=self.gpt.embedd_text(legi)
                vector.add(table,legi,meta,legi_embedds)
            if len(content['set_precedent'])>0:
                case_l=''
                for c in content['set_precedent']:
                    case_l=case_l +'; '+ c['desc']
                #append
                case_embedds=self.gpt.embedd_text(case_l)
                vector.add(table,case_l,meta,case_embedds)
            return {'result': 'success', 'content': content}
        except Exception as e:
            print(traceback.format_exc())
            return {'result': str(e), 'content': {}}

    def sectioning_html(self, document):
        #process doc
        sections = []
        current_section = None
        juris=document[0]['text']
        title=document[1]['text']
        citation=document[2]['text']

        for paragraph in document:
            if paragraph['style'] == 'h1':
                if current_section:
                    current_section['annotations']=[]
                    sections.append(current_section)
                current_section = {"title": paragraph['text'],"content": []}
            elif current_section:
                current_section["content"].append(paragraph)

        if current_section:
            current_section['annotations']=[]
            sections.append(current_section)
        return {'citation':title+', '+citation,'jurisdiction':juris,'sections':sections}

    def sectioning(self, document):
        #process doc
        text = ''
        for t in document:
            text = text +'\n'+ t['text']
        splitter1 = TokenTextSplitter(chunk_size=4000, chunk_overlap=200)
        chunker=splitter1.split_text(text)
        messages = [{'role': 'system', 'content': [{'type': 'text', 'text': self.act}]}]
        messages.append({'role': 'user', 'content': [{'type': 'text', 'text': chunker[0]}]})
        try:
            raw_json = self.gpt.json_gpt(messages)
            content = json.loads(raw_json)
            citation=content['metadata']['citation']
            juris=content['metadata']['juris']
            splitter = TokenTextSplitter(chunk_size=1500, chunk_overlap=200)
            chunks=splitter.split_text(text)
            sections = []
            n=1
            for chunk in chunks:
                sections.append({'title':'Chunk number '+ str(n), 'annotations':[], 'content':[{'style':'p','ident':'0','text':chunk}]})
                n=n+1

            return {'citation':citation,'jurisdiction':juris,'sections':sections}
        except Exception as e:
            print(traceback.format_exc())
            return {}

    # Method to process sections of a legislation
    def legislation_html(self, table, table_id, file_id, filename, document):
        try:
            legi=self.sectioning_html(document)
            meta={'citation':legi['citation'],'table_id':table_id,'file_id':file_id,'filename':filename}
            vector=Euclid()
            new_sections=[]
            for section in legi['sections']:
                section_title=section['title']
                temp=[]
                for line in section['content']:
                    temp.append(line['text'])
                new_sections.append({'title':section_title,'lines':temp})
            #end for
            for section in new_sections:
                sec_text=' '.join(section['lines'])
                splitter = TokenTextSplitter(chunk_size=500, chunk_overlap=150)
                chunks=splitter.split_text(sec_text)
                for chunk in chunks:
                    sec_embedd=self.gpt.embedd_text(chunk)
                    vector.add(table,sec_text,meta,sec_embedd)

            #return the document
            return {'result': 'success', 'content': legi}
        
        except Exception as e:
            print(traceback.format_exc())
            return {'result': str(e), 'content': {}}

    # Method to process sections of a legislation
    def legislation(self, table, table_id, file_id, filename, document):
        try:
            legi=self.sectioning(document)
            meta={'citation':legi['citation'],'table_id':table_id,'file_id':file_id,'filename':filename}
            vector=Euclid()
            new_sections=[]
            for section in legi['sections']:
                section_title=section['title']
                temp=[]
                for line in section['content']:
                    temp.append(line['text'])
                new_sections.append({'title':section_title,'lines':temp})
            #end for
            for section in new_sections:
                sec_text=' '.join(section['lines'])
                sec_text=legi['citation']+' : '+sec_text
                splitter = TokenTextSplitter(chunk_size=500, chunk_overlap=150)
                chunks=splitter.split_text(sec_text)
                for chunk in chunks:
                    sec_embedd=self.gpt.embedd_text(chunk)
                    vector.add(table,sec_text,meta,sec_embedd)

            #return the document
            return {'result': 'success', 'content': legi}
        
        except Exception as e:
            print(traceback.format_exc())
            return {'result': str(e), 'content': {}}

    def update_legi(self, table, table_id, file_id, filename, document):
        #document was deleted
        try:
            #end for loop
            meta={'citation':document['citation'],'table_id':table_id,'file_id':file_id,'filename':filename}
            vector=Euclid()
            for section in document['sections']:
                sec_text=' '.join(section['lines'])
                splitter = TokenTextSplitter(chunk_size=500, chunk_overlap=150)
                chunks=splitter.split_text(sec_text)
                for chunk in chunks:
                    sec_embedd=self.gpt.embedd_text(chunk)
                    vector.add(table,sec_text,meta,sec_embedd)
            return 'success'
        
        except Exception as e:
            print(traceback.format_exc())
            return 'error'
