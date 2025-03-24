import json
import random
from typing import List, Dict

class Ads:

    def __init__(self):
        self.advertisers = self._load_advertisers('../ads.json')

    def _load_advertisers(self, json_file_path):
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('ads', [])
        except FileNotFoundError:
            print(f"Error: File not found at {json_file_path}")
            return []
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON format in {json_file_path}")
            return []

    def random_advertiser(self):
        if not self.advertisers:
            return None
        return random.choice(self.advertisers)