# Projeto---Rede-P2P

## Execução do projeto

1. Crie um ambiente virtual e instale as dependências:

    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/Mac
    pip install -r requirements.txt
    ```

2. Execute o bootstrap server:

    ```bash
    python -m rede.bootstrap_server.start_bootstrap_server 
    ```

3. Em outros terminais, execute os nós (peers):

    ```bash
    python -m rede.node.start_node --port <port> --bootstrap <bootstrap_ip>:<bootstrap_port>
    ```

## Funcionamento do client dos nós:

No terminal, podem ser executados os seguintes comandos:

* `authenticate <port>`: Autentica com o nó que utiliza a porta `<port>`.
* `send <port> <message>` *(Não implementado)* 
* `status`: Exibe o status do nó.
* `quit`: Finaliza a execução do nó.