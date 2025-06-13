class Member:
    def __init__(self, id, name, ip, port):
        self.id = id
        self.name = name
        self.ip = ip
        self.port = port
        self.is_certified = False

    def __str__(self):
        return f"Member(id={self.id}, name={self.name}, ip={self.ip}, port={self.port})"

    def __repr__(self):
        return self.__str__()