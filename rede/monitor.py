from collections import defaultdict

class Monitor:
    def __init__(self):
        self.stats = defaultdict(lambda: {
            "sent": 0,
            "success": 0,
            "fail": 0,
            "latencies": []
        })

    def log_sent(self, node_port):
        self.stats[node_port]["sent"] += 1

    def log_result(self, node_port, success, latency):
        if success:
            self.stats[node_port]["success"] += 1
        else:
            self.stats[node_port]["fail"] += 1
        self.stats[node_port]["latencies"].append(latency)

    def report(self):
        for port, data in self.stats.items():
            total = data["sent"]
            success = data["success"]
            fail = data["fail"]
            avg_latency = sum(data["latencies"]) / len(data["latencies"]) if data["latencies"] else 0
            print(f"[Nó {port}] Enviadas: {total}, Sucesso: {success}, Falhas: {fail}, Latência média: {avg_latency:.4f}s")
