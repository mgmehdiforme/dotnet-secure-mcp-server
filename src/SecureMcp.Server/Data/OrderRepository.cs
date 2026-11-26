using Microsoft.Data.Sqlite;

namespace SecureMcp.Server.Data;

public sealed record Order(long Id, string CustomerEmail, string Status, decimal Total, string CreatedAt);

public sealed record AuditEntry(long OrderId, string FromStatus, string ToStatus, string Actor, string Reason, string At);

public static class OrderStatus
{
    public const string Pending = "pending";
    public const string Paid = "paid";
    public const string Shipped = "shipped";
    public const string Delivered = "delivered";
    public const string Cancelled = "cancelled";

    public static readonly IReadOnlyList<string> All = [Pending, Paid, Shipped, Delivered, Cancelled];

    /// <summary>The only status changes an agent may make. Everything else is refused.</summary>
    private static readonly Dictionary<string, string[]> Allowed = new(StringComparer.Ordinal)
    {
        [Pending] = [Paid, Cancelled],
        [Paid] = [Shipped, Cancelled],
        [Shipped] = [Delivered],
    };

    public static bool IsValid(string status) => All.Contains(status, StringComparer.Ordinal);

    public static bool CanMove(string from, string to) => Allowed.TryGetValue(from, out var next) && next.Contains(to, StringComparer.Ordinal);
}

public sealed class OrderNotFoundException(long id) : Exception($"Order {id} does not exist.");

public sealed class InvalidTransitionException(string from, string to) : Exception($"An order cannot move from '{from}' to '{to}'.");

/// <summary>
/// Data access for the demo "orders" domain. Every query is parameterized: values the model sends
/// are bound as data and can never change the SQL. Replace SQLite with your own store.
/// </summary>
public sealed class OrderRepository(string connectionString)
{
    private SqliteConnection Open()
    {
        var c = new SqliteConnection(connectionString);
        c.Open();
        return c;
    }

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await using var c = Open();
        await using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY,
                    customer_email TEXT NOT NULL,
                    status TEXT NOT NULL,
                    total_cents INTEGER NOT NULL,
                    created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS order_audit (
                    id INTEGER PRIMARY KEY,
                    order_id INTEGER NOT NULL REFERENCES orders(id),
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_orders_email ON orders(customer_email);
                """;
            await cmd.ExecuteNonQueryAsync(ct);
        }

        await using var count = c.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM orders";
        if ((long)(await count.ExecuteScalarAsync(ct))! > 0)
        {
            return;
        }

        // Fake demo data (example.com addresses only).
        string[] customers = ["ana@example.com", "ben@example.com", "chen@example.com", "dara@example.com"];
        await using var tx = c.BeginTransaction();
        for (var i = 1; i <= 12; i++)
        {
            await using var ins = c.CreateCommand();
            ins.Transaction = tx;
            ins.CommandText = "INSERT INTO orders (id, customer_email, status, total_cents, created_at) VALUES ($id, $email, $status, $total, $at)";
            ins.Parameters.AddWithValue("$id", i);
            ins.Parameters.AddWithValue("$email", customers[i % customers.Length]);
            ins.Parameters.AddWithValue("$status", OrderStatus.All[i % 4]);
            ins.Parameters.AddWithValue("$total", 1999 + (i * 1250));
            ins.Parameters.AddWithValue("$at", new DateTime(2026, 11, 1, 9, 0, 0, DateTimeKind.Utc).AddHours(i * 7).ToString("O"));
            await ins.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
    }

    public async Task<IReadOnlyList<Order>> SearchAsync(string? customerEmail, string? status, int limit, CancellationToken ct = default)
    {
        await using var c = Open();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT id, customer_email, status, total_cents, created_at FROM orders
            WHERE ($email IS NULL OR customer_email = $email COLLATE NOCASE)
              AND ($status IS NULL OR status = $status)
            ORDER BY id DESC
            LIMIT $limit
            """;
        cmd.Parameters.AddWithValue("$email", (object?)customerEmail ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$status", (object?)status ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$limit", limit);
        return await ReadOrders(cmd, ct);
    }

    public async Task<Order?> GetAsync(long id, CancellationToken ct = default)
    {
        await using var c = Open();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, customer_email, status, total_cents, created_at FROM orders WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        var rows = await ReadOrders(cmd, ct);
        return rows.Count > 0 ? rows[0] : null;
    }

    /// <summary>Changes a status and writes the audit row in the same transaction.</summary>
    public async Task<Order> UpdateStatusAsync(long id, string newStatus, string actor, string reason, CancellationToken ct = default)
    {
        await using var c = Open();
        await using var tx = c.BeginTransaction(deferred: false);

        await using var read = c.CreateCommand();
        read.Transaction = tx;
        read.CommandText = "SELECT status FROM orders WHERE id = $id";
        read.Parameters.AddWithValue("$id", id);
        var current = (string?)await read.ExecuteScalarAsync(ct) ?? throw new OrderNotFoundException(id);

        if (!OrderStatus.CanMove(current, newStatus))
        {
            throw new InvalidTransitionException(current, newStatus);
        }

        await using var upd = c.CreateCommand();
        upd.Transaction = tx;
        upd.CommandText = "UPDATE orders SET status = $to WHERE id = $id AND status = $from";
        upd.Parameters.AddWithValue("$to", newStatus);
        upd.Parameters.AddWithValue("$id", id);
        upd.Parameters.AddWithValue("$from", current);
        await upd.ExecuteNonQueryAsync(ct);

        await using var audit = c.CreateCommand();
        audit.Transaction = tx;
        audit.CommandText = "INSERT INTO order_audit (order_id, from_status, to_status, actor, reason, at) VALUES ($id, $from, $to, $actor, $reason, $at)";
        audit.Parameters.AddWithValue("$id", id);
        audit.Parameters.AddWithValue("$from", current);
        audit.Parameters.AddWithValue("$to", newStatus);
        audit.Parameters.AddWithValue("$actor", actor);
        audit.Parameters.AddWithValue("$reason", reason);
        audit.Parameters.AddWithValue("$at", DateTime.UtcNow.ToString("O"));
        await audit.ExecuteNonQueryAsync(ct);

        await tx.CommitAsync(ct);
        return (await GetAsync(id, ct))!;
    }

    public async Task<IReadOnlyList<AuditEntry>> GetAuditAsync(long orderId, CancellationToken ct = default)
    {
        await using var c = Open();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT order_id, from_status, to_status, actor, reason, at FROM order_audit WHERE order_id = $id ORDER BY id";
        cmd.Parameters.AddWithValue("$id", orderId);
        var list = new List<AuditEntry>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new AuditEntry(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5)));
        }
        return list;
    }

    public async Task<long> CountAsync(CancellationToken ct = default)
    {
        await using var c = Open();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM orders";
        return (long)(await cmd.ExecuteScalarAsync(ct))!;
    }

    private static async Task<IReadOnlyList<Order>> ReadOrders(SqliteCommand cmd, CancellationToken ct)
    {
        var list = new List<Order>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new Order(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetInt64(3) / 100m, r.GetString(4)));
        }
        return list;
    }
}
