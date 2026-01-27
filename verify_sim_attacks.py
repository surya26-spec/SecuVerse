from part_simulation import PartSimulator
import os
import time

# Mock database insert to print instead
class MockDatabase:
    def insert_log(self, entry):
        if entry['type'] == 'Intrusion':
            print(f"[ATTACK DETECTED] Part: {entry['src_ip']} | Type: {entry['type']} | Label info: {entry['info']}")

import database
database.insert_log = MockDatabase().insert_log

print("Testing Simulation Logic...")
sim = PartSimulator(os.path.dirname(os.path.abspath(__file__)))

# Run for 2 seconds (1 tick)
sim.start_simulation()
time.sleep(3)
sim.stop_simulation()
print("Test complete.")
