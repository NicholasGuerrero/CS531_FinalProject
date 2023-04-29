import hashlib
import json
import time
from datetime import datetime
import pytz

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)

# Define the block class
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        sha = hashlib.sha256()
        block_string = json.dumps(self.__dict__, sort_keys=True, cls=DateTimeEncoder)
        sha.update(block_string.encode('utf-8'))
        return sha.hexdigest()

# Define the blockchain class
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, datetime.now(pytz.timezone('US/Pacific')), "Genesis Block", "0")

    def add_block(self, data):
        # block = Block(len(self.chain), datetime.now(pytz.timezone('US/Pacific')), data, self.chain[-1].hash)
        block = Block(len(self.chain), data['date_time'], data, self.chain[-1].hash)
        
        self.chain.append(block)

    def to_dict(self):
        chain_dict = []
        for block in self.chain:
            block_dict = {
                "index": block.index,
                "timestamp": block.timestamp,
                "data": block.data,
                "previous_hash": block.previous_hash,
                "hash": block.hash,
            }
            # block_dict = {
            #     "index": block['index'],
            #     "timestamp": block['timestamp'],
            #     "data": block['data'],
            #     "previous_hash": block['previous_hash'],
            #     "hash": block['hash'],
            # }
            chain_dict.append(block_dict)
        return {"chain": chain_dict}