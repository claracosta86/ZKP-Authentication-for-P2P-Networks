from collections import defaultdict

class Monitor:
    def __init__(self):
        self.normal_stats = defaultdict(lambda: {
            "sent": 0,
            "success": 0,
            "fail": 0,
            "latencies": []
        })
        self.attack_stats = defaultdict(lambda: {
            "sent": 0,
            "success": 0,
            "fail": 0,
            "latencies": []
        })

        self.latencies = []

    def log_sent(self, node_port, is_attack=False):
        stats = self.attack_stats if is_attack else self.normal_stats
        stats[node_port]["sent"] += 1

    def log_result(self, node_port, success, latency, is_attack=False):
        stats = self.attack_stats if is_attack else self.normal_stats
        if success:
            stats[node_port]["success"] += 1
        else:
            stats[node_port]["fail"] += 1
        stats[node_port]["latencies"].append(latency)

    def _print_table(self, title, stats):
        print(f"\n{'='*60}")
        print(f"{title.center(60)}")
        print(f"{'='*60}")
        print(f"{'Nó':<6} {'Enviadas':<10} {'Sucesso':<10} {'Falhas':<10} {'Latência Média (s)':<20}")
        print('-'*60)

        for port, data in sorted(stats.items()):
            total = data["sent"]
            success = data["success"]
            fail = data["fail"]
            latencies = data["latencies"]
            avg_latency = sum(latencies) / len(latencies) if latencies else 0
            print(f"{port:<6} {total:<10} {success:<10} {fail:<10} {avg_latency:<20.4f}")
        print()

    def report(self):
        self._print_table("Estatísticas de Mensagens Normais", self.normal_stats)
        self._print_table("Estatísticas de Ataques Simulados", self.attack_stats)
