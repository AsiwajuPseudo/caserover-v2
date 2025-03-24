"""
    Class File_Control for file management within the directories including creating directories given a path, deleting a directory,
    moving files between 2 directories, deleting individual files, deleting all files in a directory, checking if a path exist, list
    all the files that are in a directory, list all files in a directory that have a certain file extension, save and load pickle files,
    and save and open JSON files.
"""


import os
import json
import shutil
import pickle

class File_Control:
    @staticmethod
    def create_path(path):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            print(f"Error creating folder at {path}: {e}")

    @staticmethod
    def delete_path(path):
        try:
            shutil.rmtree(path)
        except OSError as e:
            print(f"Error deleting folder at {path}: {e}")

    @staticmethod
    def move_files(source_path, destination_path):
        try:
            files = os.listdir(source_path)
            for file in files:
                shutil.move(os.path.join(source_path, file), destination_path)
        except OSError as e:
            print(f"Error moving files from {source_path} to {destination_path}: {e}")

    @staticmethod
    def delete_file(path):
        try:
            os.remove(path)
        except OSError as e:
            print(f"Error deleting file at {path}: {e}")

    @staticmethod
    def delete_all_files(path):
        try:
            files = os.listdir(path)
            for file in files:
                os.remove(os.path.join(path, file))
        except OSError as e:
            print(f"Error deleting files at {path}: {e}")

    @staticmethod
    def check_path(path):
        return os.path.exists(path)

    @staticmethod
    def list_files(path):
        try:
            files_info = []
            for file in os.listdir(path):
                if os.path.isfile(os.path.join(path, file)):
                    name, extension = os.path.splitext(file)
                    files_info.append({"name": name, "type": extension})
            return files_info
        except OSError as e:
            print(f"Error listing files at {path}: {e}")
            return []

    @staticmethod
    def list_files_with_extension(path, extension):
        try:
            return [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)) and f.endswith(extension)]
        except OSError as e:
            print(f"Error listing files with extension {extension} at {path}: {e}")
            return []

    @staticmethod
    def save(path, obj):
        #save pickle file
        try:
            with open(path, 'wb') as f:
                pickle.dump(obj, f)
        except Exception as e:
            print(f"Error saving pickle file at {path}: {e}")

    @staticmethod
    def open(path):
        #open pickle file
        try:
            with open(path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print(f"Error opening pickle file at {path}: {e}")
            return None

    @staticmethod
    def save_json(path, json_object):
        with open(path, 'w') as file:
            json.dump(json_object, file, indent=4)

    @staticmethod
    def load_json(path):
        with open(path, 'r') as file:
            return json.load(file)