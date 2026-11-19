import duckdb
import networkx as nx


class IdentityResolver:
    def __init__(self, db_path=":memory:"):
        self.con = duckdb.connect(db_path)
        self.graph = nx.Graph()

    @staticmethod
    def _clean(val) -> str:
        if val is None:
            return ""
        s = str(val).strip().lower()
        return "" if s in ("", "nan", "none", "null") else s

    def build_identity_graph(self, identities_csv_path: str, audit_csv_path: str):
        self.con.execute(
            f"CREATE TABLE IF NOT EXISTS identities AS SELECT * FROM read_csv_auto('{identities_csv_path}')"
        )
        self.con.execute(
            f"CREATE TABLE IF NOT EXISTS audit_log AS SELECT * FROM read_csv_auto('{audit_csv_path}')"
        )

        # 1. Link user_id to current name, email, phone, and email_hash
        rows = self.con.execute(
            "SELECT user_id, name, email, phone, email_hash FROM identities"
        ).fetchall()

        for user_id, name, email, phone, email_hash in rows:
            uid = self._clean(user_id)
            if not uid:
                continue
            for val in (name, email, phone, email_hash):
                cleaned = self._clean(val)
                if cleaned:
                    self.graph.add_edge(uid, cleaned)

        # 2. Link user_id to historical old_value and new_value from audit_log
        audit_rows = self.con.execute(
            "SELECT user_id, old_value, new_value FROM audit_log"
        ).fetchall()

        for user_id, old_val, new_val in audit_rows:
            uid = self._clean(user_id)
            if not uid:
                continue
            for val in (old_val, new_val):
                cleaned = self._clean(val)
                if cleaned:
                    self.graph.add_edge(uid, cleaned)

    def get_all_identifiers(self, known_identifier: str) -> set[str]:
        cleaned = self._clean(known_identifier)
        if not cleaned or cleaned not in self.graph:
            return {cleaned} if cleaned else set()
        return set(nx.node_connected_component(self.graph, cleaned))


if __name__ == "__main__":
    resolver = IdentityResolver()
    resolver.build_identity_graph("dataset/user_identities.csv", "dataset/user_audit_log.csv")

    test_email = "amina.elmasri@gmail.com"
    aliases = resolver.get_all_identifiers(test_email)

    print(f"Aliases for {test_email} ({len(aliases)} found):")
    for a in sorted(aliases):
        print(f"  - {a}")