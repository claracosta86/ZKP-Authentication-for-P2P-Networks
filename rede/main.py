import threading
import time
from network import BootstrapServer
from node import VehicleNode
import config

# Start bootstrap server
bootstrap = BootstrapServer(config.BOOTSTRAP_NODE, config.BOOTSTRAP_PORT)
threading.Thread(target=bootstrap.start, daemon=True).start()

time.sleep(1)  # Give bootstrap time to start

# Start nodes
nodes = []
for i in range(config.TOTAL_NODES):
    port = config.MESSAGE_PORT_START + i
    node = VehicleNode('127.0.0.1', port, config.BOOTSTRAP_NODE, config.BOOTSTRAP_PORT)
    node.register_with_bootstrap()
    threading.Thread(target=node.listen, daemon=True).start()
    nodes.append(node)

time.sleep(2)

# Send test messages
for node in nodes:
    node.send_message(f"Hello from {node.port}")

time.sleep(5)
