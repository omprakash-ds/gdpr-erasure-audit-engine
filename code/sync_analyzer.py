import duckdb


class SyncAnalyzer:
    def __init__(self, activity_csv_path: str = "dataset/system_activity.csv"):
        self.con = duckdb.connect(":memory:")
        self.con.execute(
            f"CREATE TABLE system_activity AS SELECT * FROM read_csv_auto('{activity_csv_path}')"
        )

    def get_event_types(self) -> list[tuple]:
        return self.con.execute("""
            SELECT event_type, COUNT(*) AS cnt
            FROM system_activity
            GROUP BY event_type
            ORDER BY cnt DESC
        """).fetchall()

    def get_data_flows(self) -> list[tuple]:
        return self.con.execute("""
            SELECT source_system, target_system, event_type, COUNT(*) AS cnt
            FROM system_activity
            GROUP BY 1, 2, 3
            ORDER BY 1, 2, 3
        """).fetchall()

    def find_activity_for_resources(self, resource_ids: set[str], after_time: str = None) -> list[dict]:
        """
        Finds all system_activity rows referencing any of the user's resource_ids.
        Optionally filters for events occurring after the deletion request timestamp.
        """
        if not resource_ids:
            return []

        placeholders = ", ".join(["?"] * len(resource_ids))
        query = f"""
            SELECT activity_id, event_time, event_type, source_system, target_system,
                   resource_id, reported_result, details
            FROM system_activity
            WHERE LOWER(resource_id) IN ({placeholders})
        """
        params = [r.lower() for r in resource_ids]

        if after_time:
            query += " AND event_time >= ?"
            params.append(after_time)

        query += " ORDER BY event_time ASC"
        cols = ["activity_id", "event_time", "event_type", "source_system",
                "target_system", "resource_id", "reported_result", "details"]
        rows = self.con.execute(query, params).fetchall()
        return [dict(zip(cols, row)) for row in rows]


if __name__ == "__main__":
    analyzer = SyncAnalyzer()
    print("=== Event Types ===")
    for et, cnt in analyzer.get_event_types():
        print(f"  - {et}: {cnt}")

    print("\n=== Top System Data Flows ===")
    for src, tgt, et, cnt in analyzer.get_data_flows()[:20]:
        print(f"  - {src} -> {tgt} [{et}]: {cnt}")