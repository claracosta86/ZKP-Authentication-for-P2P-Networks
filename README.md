# ZKP-Authentication-for-P2P-Networks

## Project Execution

1. Create a virtual environment and install dependencies:

    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/Mac
    pip install -r requirements.txt
    ```

2. Run the bootstrap server:

    ```bash
    python -m rede.bootstrap_server.start_bootstrap_server 
    ```

3. In other terminals, run the nodes (peers):

    ```bash
    python -m rede.node.start_node --port <port>
    ```

4. To test an attack scenario, where the attacker doesn't have the certificate's private key:
    ```bash
    python -m rede.node.start_node --port <port> --attacker
    ```
## Node client operation:

The following commands can be executed in the terminal:

* `authenticate <port>`: Authenticates with the node using port `<port>`.
* `status`: Displays the node's status.
* `quit`: Ends the node execution.
