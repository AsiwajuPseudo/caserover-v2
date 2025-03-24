import chromadb
import random
import os

from gpt import GPT

class Euclid:
  def __init__(self):
    self.name="Euclid 1"
    self.handle=chromadb.PersistentClient(path="../euclid/")
    self.size=0

  #list all tables in the database
  def tables(self):
    li=self.handle.list_collections()

    return li

  #create a new table
  def create_table(self, name,metric="cosine"):
    try:
      table=self.handle.create_collection(name=name,metadata={"hnsw:space": metric})

      return "success"
    except Exception as e:
      print(str(e))

      return "Table already exist"
  
  #delete a table
  def delete_table(self,name):
    try:
      self.handle.delete_collection(name=name)
      return "success"
    except Exception as e:
      print(str(e))
      return "failed: "+str(e)

  #add document into table
  def add(self,table,document,meta,embedds):
    try:
      id_=str(random.randint(1000000000,99999999999))
      table=self.handle.get_collection(table)
      table.add(embeddings=[embedds],documents=[document],metadatas=[meta],ids=[id_])
    except Exception as e:
      print(str(e))
  
  #add document into table
  def add_multiple(self,table,data,target):
    ids=[]
    values=[]
    id_=0
    for row in data:
      values.append(row[target])
      ids.append(str(id_))
      id_=id_+1
      #end for
    #end for
    #take metadata
    metadata=[{k: v for k, v in meta.items() if k != target} for meta in data]
    #split into batches
    new_ids=[ids[i:i+10000] for i in range(0, len(ids), 10000)]
    new_values=[values[i:i+10000] for i in range(0, len(values), 10000)]
    new_metadata=[metadata[i:i+10000] for i in range(0, len(metadata), 10000)]
    try:
      size=len(new_ids)
      n=0
      table=self.handle.get_collection(table)
      while n<size:
        table.add(embeddings=new_values[n],metadatas=new_metadata[n],ids=new_ids[n])
        n=n+1

      return {'result':'success'}
    except Exception as e:
      print(str(e))
      return {'result':'table does not exist: '+str(e)}

  #search for top results
  def search(self,name,q,k=1):
    try:
      table=self.handle.get_collection(name)
      gpt=GPT()
      embeds=gpt.embedd_text(q)
      results=table.query(query_embeddings=[embeds],n_results=k)
      distances=results['distances'][0]
      metadata=results['metadatas'][0]
      documents=results['documents'][0]
      ret_content=[]
      n=0
      for data in metadata:
        data['table']=name
        data['distance']=1-distances[n]
        data['document']=documents[n]
        n=n+1
        ret_content.append(data)

      return ret_content
    except Exception as e:
      print("Error: "+ str(e))
      return {'data':[]}

  #delete document into table
  def delete(self,table,key, value):
    try:
      table=self.handle.get_collection(table)
      table.delete(where={key:value})
      return 'success'
    except Exception as e:
      print(str(e))
      return 'error'