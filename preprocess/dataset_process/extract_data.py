import pandas as pd
import os
import sys
import json

from typing import Dict, Set
from tqdm import tqdm
from utils import remove_space_before_newline, remove_comments, remove_empty_lines, remove_space_after_newline, get_dir, \
    processed_dir, cache_dir, dfmp, train_val_test_split_df
from clean_gadget import clean_gadget

pd.set_option('mode.chained_assignment', None)


def cleaned_code(func_code):
    func_code = remove_empty_lines(func_code)
    func_code = remove_comments(func_code)

    return func_code
    pass


def clean_abnormal_func(data):
    print('clean_abnormal_func...')
    # Remove functions with abnormal ending (no } or ;)
    # c++ class ending with };
    data = data[
        ~data.apply(
            lambda x: x.func_before.strip()[-1] != "}"
                      and x.func_before.strip()[-1] != ";",
            axis=1,
        )
    ]
    # Remove functions with abnormal ending (ending with ");")
    data = data[~data.func_before.apply(lambda x: x[-2:] == ");")]
    print('clean_abnormal_func done')
    return data


def cleaned_dataset(data):
    print('Data shape before cleaning:', data.shape)
    print('Cleaning Code...')
    data['func_before'] = data['func_before'].apply(lambda x: cleaned_code(x))
    data['func_after'] = data['func_after'].apply(lambda x: cleaned_code(x))
    data = data[~data['func_before'].duplicated(keep=False)]  # Remove duplicate functions
    # remove func_before == func_after
    data = data[(data['vul'] == 0) | (data['vul'] == 1 & (data['func_before'] != data['func_after']))]
    # remove too small/large samples...
    data = data[data['func_before'].apply(lambda x: 10 <= len(x.splitlines()) <= 100)]
    dfv = data[data.vul == 1]
    print(f"There remains {len(data)} samples, including {len(dfv)} vulnerable functions.")  # 102472
    print('Cleaning Code Done!')
    return data


def BigVul_preprocess(dataset, target):
    df = pd.read_csv(dataset, low_memory=False)
    dfv = df[df.vul == 1]
    print(f"The dataset contains {len(df)} samples and {len(dfv)} vulnerable functions.")  # 188636

    # 1.data preprocess
    df = cleaned_dataset(df)  # step1-clean, 188201
    df = clean_abnormal_func(df)  # step2-clean, 188088

    target_dir = target + '\BigVul'
    label = 'label.json'
    label_path = os.path.join(target, label)
    label_info = {}
    total_Info: Dict[str, Set[int]] = dict()

    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
        for index, row in tqdm(df.iterrows(), total=len(df), desc="Processing dataset"):
            filename = str(index) + '_' + str(row['commit_id'])[:6] + '_' + str(row['vul']) + '.c'
            filepath = os.path.join(target_dir, filename)
            with open(filepath, 'w', encoding='UTF-8') as file:
                file.write(row['func_before'])
            if row['vul'] == 1:
                with open(filepath, 'w', encoding='UTF-8') as file:
                    file.write(row['func_before'])
                non_filename = str(index) + '_' + str(row['commit_id'])[:6] + '_0.c'
                non_filepath = os.path.join(target_dir, non_filename)
                with open(non_filepath, 'w', encoding='UTF-8') as file:
                    file.write(row['func_after'])

            # original_code = row['func_before']
            # nor_code = clean_gadget(original_code.splitlines())

            # '''Extracting flaw_lines from processed_data.csv'''
            # if row['vul'] == 0:
            #     with open(filepath, 'w', encoding='UTF-8') as file:
            #         file.write(row['func_before'])
            # elif not isinstance(row['flaw_line_index'], float):
            #     with open(filepath, 'w', encoding='UTF-8') as file:
            #         file.write(row['func_before'])
            #     fileInfo = process(filename, row['flaw_line_index'])
            #     total_Info.update(fileInfo)
    else:
        print('The directory already exists!')
        exit(0)

    # total_Info = {file: list(line_set) for file, line_set in total_Info.items()}
    # json.dump(total_Info, open(label_path, 'w', encoding='utf8'), indent=2)
    print('Complete!')


def Devign_preprocess(dataset, target):
    df = pd.read_json(dataset)
    dfv = df[df.target == 1]
    print(f"The dataset contains {len(df)} samples, including {len(dfv)} vulnerable functions.")  # 188636
    print('Cleaning dataset...')
    df['func'] = df['func'].apply(lambda x: cleaned_code(x))
    df = df[~df['func'].duplicated(keep=False)]  # Remove duplicate functions
    df = df[df['func'].apply(lambda x: 10 <= len(x.splitlines()) <= 100)]
    dfv = df[df.target == 1]
    print(f"There remains {len(df)} samples and {len(dfv)} vulnerable functions.")  # 188636
    print('Cleaning dataset done!')

    target_dir = target + '/Devign'
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
        for index, row in tqdm(df.iterrows(), total=len(df), desc="Processing dataset"):
            filename = str(index) + '_' + str(row['project']) + '_' + str(row['commit_id'])[:6] + \
                       '_' + str(row['target']) + '.c'
            filepath = os.path.join(target_dir, filename)
            with open(filepath, 'w', encoding='UTF-8') as file:
                file.write(row['func'])

    else:
        print('The directory already exists!')
        exit(0)
    print('Complete!')


def preprocess(dataset, project, target):
    df = pd.read_csv(dataset, low_memory=False)
    print(f"The dataset contains {len(df)} samples.")
    print('Cleaning dataset...')
    df['func'] = df['func'].apply(lambda x: cleaned_code(x))
    df = df[df['func'].apply(lambda x: 10 <= len(x.splitlines()) <= 100)]
    print(f"There remains {len(df)} samples.")
    print('Cleaning dataset done!')

    target_dir = target + project
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
        for index, row in tqdm(df.iterrows(), total=len(df), desc="Processing dataset"):
            filename = str(index) + '.c'
            filepath = os.path.join(target_dir, filename)
            with open(filepath, 'w', encoding='UTF-8') as file:
                file.write(row['func'])

    else:
        print('The directory already exists!')
        exit(0)
    print('Complete!')


def process(filename, line_index):
    fileInfo: Dict[str, Set[int]] = dict()
    fileInfo[filename] = set()
    for line_idx in range(len(list(line_index.split(",")))):
        fileInfo[filename].add(int(line_idx))

    return fileInfo


if __name__ == '__main__':
    dataset_dir = os.path.dirname(os.getcwd()) + '/dataset/'
    src_path = sys.argv[1]
    target_project = ['redis', 'FFmpeg', 'openjpeg', 'reactos']
    print("Data loading ...")
    if src_path == 'devign':
        dataset_path = dataset_dir + 'function.json'
        Devign_preprocess(dataset_path, dataset_dir)
    elif src_path == 'bigvul':
        dataset_path = dataset_dir + 'MSR_data_cleaned.csv'
        BigVul_preprocess(dataset_path, dataset_dir)
    elif src_path in target_project:
        dataset_path = dataset_dir + src_path + '.csv'
        preprocess(dataset_path, src_path, dataset_dir)
    else:
        print('Dataset Invalid!')
