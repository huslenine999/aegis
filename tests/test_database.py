from app.database import PostgresConnection, PostgresCursor


def test_postgres_connection_executemany_uses_cursor():
    calls = []

    class Cursor:
        def executemany(self, statement, parameters):
            calls.append((statement, parameters))

    class Connection:
        def cursor(self):
            return Cursor()

    parameters = [(1, "report.html"), (1, "report.md")]
    result = PostgresConnection(Connection()).executemany(
        "INSERT INTO scan_artifacts (scan_run_id, name) VALUES (?, ?)",
        parameters,
    )

    assert isinstance(result, PostgresCursor)
    assert calls == [
        (
            "INSERT INTO scan_artifacts (scan_run_id, name) VALUES (%s, %s)",
            parameters,
        )
    ]
