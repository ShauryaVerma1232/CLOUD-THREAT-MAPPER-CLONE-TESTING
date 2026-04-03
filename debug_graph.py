import json
import networkx as nx
from pathlib import Path

# Load the infrastructure model
with open('/app/artifacts/33454c48-7a82-486a-af18-224b9f9a01ca/infrastructure_model.json') as f:
    data = json.load(f)

# Import and build graph
from app.graph.graph_builder import build_graph

G = build_graph(Path('/app/artifacts/33454c48-7a82-486a-af18-224b9f9a01ca/infrastructure_model.json'))

# Print all nodes
print('Nodes:')
for n, attrs in G.nodes(data=True):
    print(f'  {n}: {attrs.get("node_type")}')

print()
print('Edges:')
for src, tgt, attrs in G.edges(data=True):
    print(f'  {src} --{attrs.get("edge_type")}--> {tgt}')

print()
print('IAM Users:')
for n, attrs in G.nodes(data=True):
    if attrs.get('node_type') == 'IAM_USER':
        print(f'  {n}: active_keys={attrs.get("metadata", {}).get("active_key_count", 0)}')

print()
print('Finding paths from cg-bilbo:')
bilbo_arn = 'arn:aws:iam::339713015109:user/cg-bilbo-cgidpam68t854j'
for node in G.nodes():
    if 'role' in node.lower() or 'Role' in node:
        try:
            paths = list(nx.all_simple_paths(G, source=bilbo_arn, target=node, cutoff=6))
            if paths:
                print(f'  Paths to {node}: {len(paths)}')
                for p in paths:
                    print(f'    {p}')
        except:
            pass
