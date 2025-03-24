import random
from fuzzywuzzy import fuzz, process
import networkx as nx
from file_control import File_Control

class Graph:
    def __init__(self):
        # Initialize the NetworkX graph and a list for document nodes
        self.nodes = []
        if File_Control.check_path('../graph/') and File_Control.check_path('../graph/graph.pkl'):
        	self.graph=File_Control.open('../graph/graph.pkl')
        else:
        	self.graph = nx.DiGraph()
        	File_Control.create_path('../graph/')
        	File_Control.save('../graph/graph.pkl',self.graph)

    def create_graph(self, documents):
        # Extend nodes list and add nodes to the graph
        self.nodes.extend(documents)
        temp_nodes = []
        citations = []
        docs=[]

        for doc in documents:
            try:
                # Load file content and extract citation details
                file = File_Control.open('../data/' + doc['table'] + '-' + doc['table_id'] + '/' + doc['file_id'] + '-' + doc['filename'] + '.pkl')
                citation = file['citation']
                doc['citation'] = citation
                docs.append(doc)
                citations.append(citation)
                # Add the main document as a node in the graph with its citation as the unique identifier
                self.graph.add_node(citation, **doc)
                # Process related case law and legislation references
                if doc['type'] == 'ruling':
                    for case in file['case_law']:
                        case_node = {'origin': doc,'mode': 'case law','citation': case['citation'],'result': case['result'],'content': case['desc'],'type': 'case law'}
                        temp_nodes.append(case_node)

                    for legi in file['legislation']:
                        legislation_node = {'origin': doc,'mode': 'case law','citation': legi['legislation'],'section': legi['section'],'result': legi['result'],'content': legi['desc'],'type': 'legislation'}
                        temp_nodes.append(legislation_node)
                elif doc['type'] == 'legislation':
                    pass  # Optionally skip adding individual sections
            except Exception as e:
                pass

        # Create edges based on the citation matching logic
        n=len(temp_nodes)
        i=1
        for node in temp_nodes:
            print ('Computing node ' +str(i) +' of ' + str(n))
            i=i+1
            if node['mode'] == 'case law':
                best_match = process.extractOne(node['citation'], citations)
                if best_match and best_match[1] > 90:
                    target_citation = best_match[0]
                    source_citation = node['origin']['citation']
                    target_data=next(item for item in docs if item['citation']==best_match[0])
                    node['target']=target_data
                    
                    # Add the node for the source document if it does not exist
                    if not self.graph.has_node(source_citation):
                        self.graph.add_node(source_citation, **node['origin'])
                    
                    # Add an edge with the pointer type as metadata
                    self.graph.add_edge(source_citation, target_citation, pointer=node)

        File_Control.save('../graph/graph.pkl',self.graph)
        return 'success'

    def delete_node(self, citation):
        # Check if the node exists in the graph
        if not self.graph.has_node(citation):
            return f"Node with citation '{citation}' does not exist in the graph."
        
        # Remove the node and all edges connected to it
        self.graph.remove_node(citation)
        
        # Save the updated graph
        File_Control.save('../graph/graph.pkl', self.graph)
        
        return 'success'

    def search(self, citation):
        # Search and display connections for a given citation
        if not self.graph.has_node(citation):
            return {'outgoing':[],'incoming':[]}
        
        # Get incoming and outgoing connections
        connections = {
            'outgoing': [{'citation':citation,'target': target, 'node':self.graph.edges[citation, target]['pointer']}
                         for target in self.graph.successors(citation)],
            'incoming': [{'source':source, 'citation':citation,'node':self.graph.edges[source, citation]['pointer']}
                         for source in self.graph.predecessors(citation)]
        }

        return connections

    def graph_data(self):
        nodes=self.graph.nodes()
        edges=self.graph.edges()
        return {"nodes": len(nodes), "edges": len(edges)}