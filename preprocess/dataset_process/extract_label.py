import json
import os
import sys
import xml.etree.ElementTree as ET
from typing import Dict, Set, Tuple, List
from tqdm import tqdm


def process(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    fileInfo: Dict[str, Set[int]] = dict()
    for testcase in list(root):
        for file in testcase.findall("file"):
            path = file.get("path")
            for flaw in file.findall("flaw"):
                if path not in fileInfo.keys():
                    fileInfo[path] = set()
                fileInfo[path].add(int(flaw.get("line")))
                print(fileInfo)
                print(e)
            for flaw in file.findall("mixed"):
                if path not in fileInfo.keys():
                    fileInfo[path] = set()
                fileInfo[path].add(int(flaw.get("line")))

    return fileInfo


def recurse_folder(folder_path, output_json_path):
    total_Info: Dict[str, Set[int]] = dict()
    print(folder_path, output_json_path)
    for root, dirs, files in tqdm(os.walk(folder_path)):
        for file in files:
            if file.startswith("manifest") and file.endswith(".xml"):
                fileInfo = process(os.path.join(root, file))
                total_Info.update(fileInfo)

    total_Info = {file: list(line_set) for file, line_set in total_Info.items()}
    json.dump(total_Info, open(output_json_path, 'w', encoding='utf8'), indent=2)


if __name__ == '__main__':
    current_dir = os.getcwd()
    parent_dir = os.path.dirname(current_dir)
    src_path = sys.argv[1]
    output_json = sys.argv[2]
    print('Input_path is: ' + parent_dir + '/' + src_path)
    print('Output_path is: ' + parent_dir + '/' + output_json)
    # process SARD dataset
    recurse_folder(parent_dir + '/' + src_path, parent_dir + '/' + output_json)
