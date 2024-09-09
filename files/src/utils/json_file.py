import json


def read_file_as_dict(file_path: str) -> dict:
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def read_file_as_text(file_path: str) -> str:
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


def write_text_to_file(text: str, file_path: str):
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(text)
