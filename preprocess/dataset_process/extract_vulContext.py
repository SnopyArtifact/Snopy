import json
import sys
import os
import hashlib
import warnings
import pandas as pd
from tqdm import tqdm
from clean_gadget import clean_gadget

NODE_FILE = "nodes.csv"
EDGE_FILE = "edges.csv"

# control dependence
CDG_EDGE_TYPE = "CONTROLS"
# data dependence
DDG_EDGE_TYPE = "REACHES"
# control flow
CFG_EDGE_TYPE = "FLOWS_TO"

warnings.filterwarnings('ignore', category=FutureWarning)
pd.set_option('mode.chained_assignment', None)


def path_traversal(file_dir, filename):
    csv2df = pd.DataFrame()
    for csv_name in os.listdir(file_dir):
        if csv_name.endswith(filename):
            target_path = file_dir + '\\' + csv_name
            df = pd.read_csv(target_path, sep='\t')
            csv2df = df
    return csv2df


def slice_signature_generation(dir_path, target_path):
    signature_path = target_path + 'signature.json'
    signature = []
    counter = 0
    with open(signature_path, 'w') as json_file:
        json.dump(signature, json_file)
    for dir_name in tqdm(os.listdir(dir_path)):
        counter += 1
        vul_code_list = []
        fix_code_list = []
        vul_statement_key = []
        patch_statement_key = []

        file_path = os.path.join(dir_path, dir_name)
        df_vul = path_traversal(file_path, '1_nodes.csv')
        df_fix = path_traversal(file_path, '0_nodes.csv')
        for index, row in df_vul.iterrows():
            if isinstance(row['isCFGNode'], bool):
                vul_code_list.append(row['code'])

        for index, row in df_fix.iterrows():
            if isinstance(row['isCFGNode'], bool):
                fix_code_list.append(row['code'])

        # TODO: may miss CFG node with same name.
        vul_code = set(vul_code_list)
        fix_code = set(fix_code_list)
        vul_statement = vul_code - fix_code
        patch_statement = fix_code - vul_code

        '''1. when patch only adds some statements'''
        if vul_code.issubset(fix_code):
            for item in patch_statement:
                idx = fix_code_list.index(item)
                vul_statement.add(fix_code_list[idx])
            # print(vul_statement)

            for index in range(len(fix_code_list)):
                if fix_code_list[index] in list(vul_statement):
                    patch_statement_key.append(index)

            patch_key = []
            patch_index = 0
            for index, row in df_fix.iterrows():
                if isinstance(row['isCFGNode'], bool):
                    if patch_index in patch_statement_key:
                        patch_key.append(row['key'])
                    patch_index += 1
            # print(patch_key)

            fix_edge = path_traversal(file_path, '0_edges.csv')
            df_cfg = fix_edge[(fix_edge['type'] == CDG_EDGE_TYPE) | (fix_edge['type'] == CFG_EDGE_TYPE)]
            df_dfg = fix_edge[fix_edge['type'] == DDG_EDGE_TYPE]
            cfg = create_graph(df_cfg)
            dfg = create_graph(df_dfg)
            patch_slice = get_slice(cfg, dfg, patch_key)
            # print(program_slice)

            vul_edge = path_traversal(file_path, '1_edges.csv')
            df_pdg = vul_edge[(vul_edge['type'] == CDG_EDGE_TYPE) | (vul_edge['type'] == CFG_EDGE_TYPE)
                              | (vul_edge['type'] == DDG_EDGE_TYPE)]
            df_pdg['type'] = df_pdg['type'].apply(lambda x: 'data' if x == DDG_EDGE_TYPE else 'control')

            patch_slice_signature = get_signature(patch_slice, df_fix)
            vul_signature = get_signature(df_pdg, df_vul)

            overlap = []
            for patch_signature in patch_slice_signature:
                if patch_signature in vul_signature:
                    overlap.append(patch_signature)

            if overlap:
                signature_info = {
                    "file_id": dir_name,
                    "signature": overlap
                }
                signature.append(signature_info)
                # with open(signature_path, 'w') as json_file:
                #     json.dump(signature, json_file, indent=4)

        else:
            '''2. when patch only modifies control flow'''
            if vul_code == fix_code:
                for control_stmt in [i for i, j in zip(vul_code_list, fix_code_list) if i != j]:
                    vul_statement.add(control_stmt)

            for index in range(len(vul_code_list)):
                if vul_code_list[index] in list(vul_statement):
                    vul_statement_key.append(index)

            vul_key = []
            vul_index = 0

            for index, row in df_vul.iterrows():
                if isinstance(row['isCFGNode'], bool):
                    if vul_index in vul_statement_key:
                        vul_key.append(row['key'])
                    vul_index += 1

            vul_edge = path_traversal(file_path, '1_edges.csv')
            df_cfg = vul_edge[(vul_edge['type'] == CDG_EDGE_TYPE) | (vul_edge['type'] == CFG_EDGE_TYPE)]
            df_dfg = vul_edge[vul_edge['type'] == DDG_EDGE_TYPE]
            cfg = create_graph(df_cfg)
            dfg = create_graph(df_dfg)
            vul_slice = get_slice(cfg, dfg, vul_key)
            vul_slice_signature = get_signature(vul_slice, df_vul)

            if vul_slice_signature:
                signature_info = {
                    "file_id": dir_name,
                    "signature": vul_slice_signature
                }
                signature.append(signature_info)
                # with open(signature_path, 'w') as json_file:
                #     json.dump(signature, json_file, indent=4)

        if counter % 500 == 0 or counter == len(os.listdir(dir_path)):
            with open(signature_path, 'r') as json_file:
                signature_json = json.load(json_file)
            signature_json.extend(signature)
            with open(signature_path, 'w') as json_file:
                json.dump(signature_json, json_file, indent=4)
            signature.clear()


def func_signature_generation(dir_path, target_path):
    signature_path = target_path + 'func_signature.json'
    signature = []
    counter = 0
    with open(signature_path, 'w') as json_file:
        json.dump(signature, json_file)
    for dir_name in tqdm(os.listdir(dir_path)):
        counter += 1
        code_list = []
        statement_key = []

        file_path = os.path.join(dir_path, dir_name)
        df = path_traversal(file_path, 'nodes.csv')
        for index, row in df.iterrows():
            if isinstance(row['isCFGNode'], bool):
                code_list.append(row['code'])
                statement_key.append(row['key'])

        edge = path_traversal(file_path, 'edges.csv')
        df_cfg = edge[(edge['type'] == CDG_EDGE_TYPE) | (edge['type'] == CFG_EDGE_TYPE)]
        df_dfg = edge[edge['type'] == DDG_EDGE_TYPE]
        cfg = create_graph(df_cfg)
        dfg = create_graph(df_dfg)
        pdg_slice = get_slice(cfg, dfg, statement_key)
        slice_signature = get_signature(pdg_slice, df)

        if slice_signature:
            signature_info = {
                "file_id": dir_name,
                "signature": slice_signature
            }
            signature.append(signature_info)

        if counter % 500 == 0 or counter == len(os.listdir(dir_path)):
            with open(signature_path, 'r') as json_file:
                signature_json = json.load(json_file)
            signature_json.extend(signature)
            with open(signature_path, 'w') as json_file:
                json.dump(signature_json, json_file, indent=4)
            signature.clear()


def get_signature(dataframe, df_node):
    unique_node = set()
    tuple_dict = []
    node_value = {}
    signature = []
    for index, row in dataframe.iterrows():
        unique_node.add(row['start'])
        unique_node.add(row['end'])
        key_type_tuple = (row['start'], row['end'], row['type'])
        tuple_dict.append(key_type_tuple)

    for node_idx in unique_node:
        for index, row in df_node.iterrows():
            if row['key'] == node_idx and not isinstance(row['code'], float):
                normal_code = clean_gadget([row['code']])
                node_value[node_idx] = getMD5(normal_code)

    for signature_tuple in tuple_dict:
        if signature_tuple[0] in node_value and signature_tuple[1] in node_value:
            stmt_signature_update = (node_value[signature_tuple[0]], node_value[signature_tuple[1]],
                                     signature_tuple[2])
            if stmt_signature_update not in signature:
                signature.append(stmt_signature_update)

    return signature


def create_graph(dataframe):
    key_set = set()
    for index, row in dataframe.iterrows():
        key_set.add(row['start'])

    graph = {key: [] for key in key_set}
    for index, row in dataframe.iterrows():
        # remove duplicate edges
        if row['end'] not in graph[row['start']]:
            graph[row['start']].append(row['end'])

    return graph


def get_slice(cfg, dfg, slice_point):
    slice_edge = pd.DataFrame(columns=['start', 'end', 'type'])
    visited_cfg_forward = {vertex: False for vertex in cfg}
    visited_dfg_forward = {vertex: False for vertex in dfg}
    cfg_forward_slice = {}
    cfg_backward_slice = {}
    dfg_forward_slice = {}
    dfg_backward_slice = {}

    for root in slice_point:
        cfg_backward_slice.update(backward_slicing(cfg, root))
        dfg_backward_slice.update(backward_slicing(dfg, root))
        cfg_forward_slice.update(forward_slicing(cfg, root, visited_cfg_forward))
        dfg_forward_slice.update(forward_slicing(dfg, root, visited_dfg_forward))

    for key in cfg_forward_slice:
        for value in cfg_forward_slice[key]:
            data = {'start': key, 'end': value, 'type': 'control'}
            slice_edge = slice_edge.append(data, ignore_index=True)

    for key in cfg_backward_slice:
        for value in cfg_backward_slice[key]:
            data = {'start': value, 'end': key, 'type': 'control'}
            slice_edge = slice_edge.append(data, ignore_index=True)

    for key in dfg_forward_slice:
        for value in dfg_forward_slice[key]:
            data = {'start': key, 'end': value, 'type': 'data'}
            slice_edge = slice_edge.append(data, ignore_index=True)

    for key in dfg_backward_slice:
        for value in dfg_backward_slice[key]:
            data = {'start': value, 'end': key, 'type': 'data'}
            slice_edge = slice_edge.append(data, ignore_index=True)

    return slice_edge


def forward_slicing(graph, start, visited=None):
    # print(f'------------Starting performing forward slicing of node {start}------------')
    slice_list = {}
    if start not in graph:  # 不存在前向控制流
        return slice_list
    else:
        stack = [start]
        visited[start] = True
        slice_list[start] = graph[start]

        while stack:
            vertex = stack.pop()
            # print(vertex)  # 打印当前节点
            # print(graph[vertex])

            for neighbor in graph[vertex]:
                if neighbor not in graph:
                    continue
                # if not visited[neighbor] or neighbor not in graph:
                if not visited[neighbor]:
                    slice_list[neighbor] = graph[neighbor]
                    stack.append(vertex)  # 将当前节点重新加入栈顶
                    stack.append(neighbor)
                    visited[neighbor] = True
                    break
        # print(f'------------Forward slicing of node {start} complete------------')
        return slice_list


def backward_slicing(graph, end):
    refactor_list = []
    reverse_key_set = set()
    for key, val in graph.items():
        for value in val:
            if [value, key] not in refactor_list:
                reverse_key_set.add(value)
                refactor_list.append([value, key])

    reverse_graph = {key: [] for key in reverse_key_set}

    for value in refactor_list:
        reverse_graph[value[0]].append(value[1])

    visited_backward = {vertex: False for vertex in reverse_graph}

    return forward_slicing(reverse_graph, end, visited_backward)


def getMD5(s: str):
    hl = hashlib.md5()
    hl.update(s.encode("utf-8"))
    return hl.hexdigest()


def file_merge(dir_path, target_path):
    diff_list = []

    print('--------------------Loading graph data--------------------')
    for filename in os.listdir(dir_path):
        identifier = filename.split('_')[:1]
        if ''.join(identifier) in diff_list:
            continue
        else:
            diff_list.extend(identifier)

    for folder in diff_list:
        os.makedirs(target_path + folder)

    for filename in os.listdir(dir_path):
        file_path = os.path.join(dir_path, filename)
        # print(file_path)
        write_path = os.path.join(target_path, filename.split('_')[0])
        # print(write_path)
        keepcols = ['key', 'type', 'code', 'isCFGNode']

        for csv_name in os.listdir(file_path):
            graph_path = file_path + '\\' + csv_name
            if csv_name == NODE_FILE:
                df = pd.read_csv(graph_path, usecols=[1, 2, 3, 7], sep='\t')
                output_path = write_path + '\\' + filename.split('.')[0] + '_' + csv_name
                df[keepcols].to_csv(output_path, sep='\t', index=False)
            else:
                df = pd.read_csv(graph_path, sep='\t')
                output_path = write_path + '\\' + filename.split('.')[0] + '_' + csv_name
                df.to_csv(output_path, sep='\t', index=False)

    print('--------------------Data loading complete!--------------------')


if __name__ == '__main__':
    dataset_dir = os.path.dirname(os.getcwd()) + '/dataset/CPG/'
    csv_dir = sys.argv[1]
    slice_or_not = sys.argv[2]
    csv_path = dataset_dir + csv_dir
    if slice_or_not == 'slice':
        merge_path = csv_path + '_Merge/'
        file_merge(csv_path, merge_path)
        slice_signature_generation(merge_path, dataset_dir)
    elif slice_or_not == 'function':
        func_signature_generation(csv_path, dataset_dir)
