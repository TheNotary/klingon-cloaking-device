# Access Approval Process Flow — CLI Authorization

To reach a cloaked service, a user runs the `kcd authorize` command which performs a two-phase authentication: a UDP port-knock sequence followed by TLS-secured password verification. The knock password is split into multiple UDP packets sent to port 9000; once the server reassembles and validates them, it briefly opens TCP port 9001 via a NetworkPolicy update. The CLI then connects over TLS, sends the access password, and upon verification the server patches every target Service's `loadBalancerSourceRanges` with the user's IP. Access persists for the configured TTL (default 24 hours) before the sweeper automatically revokes it.

```mermaid
sequenceDiagram
    participant User
    participant CLI as kcd CLI
    participant Server as KCD Server<br/>(api-rs)
    participant K8s as Kubernetes API

    User->>CLI: kcd authorize --server HOST<br/>--knock-password *** --access-password ***

    Note over CLI: Split knock password<br/>into 4 UDP chunks

    loop Each chunk (100ms apart)
        CLI->>Server: UDP :9000 — KnockPacket<br/>(version, seq, total, timestamp, payload)
    end

    Note over Server: Validate each packet<br/>(version, timestamp ±30s)
    Note over Server: Reassemble chunks,<br/>constant-time password compare

    alt Knock password valid
        Server->>K8s: Patch auth NetworkPolicy<br/>— allow client IP on TCP :9001
        Note over CLI: Wait 5s for server processing
        CLI->>Server: TLS connect to TCP :9001
        Server-->>CLI: "Ready"
        CLI->>Server: access password (over TLS)

        Note over Server: Constant-time<br/>password compare

        alt Access password valid
            Server->>K8s: Patch target Services<br/>— append client IP/32 to<br/>loadBalancerSourceRanges
            Server-->>CLI: "AUTHORIZED"
            CLI-->>User: ✓ Access granted for TTL period
        else Access password invalid
            Server-->>CLI: "DENIED"
            CLI-->>User: ✗ Authorization denied
        end

        Server->>K8s: Patch auth NetworkPolicy<br/>— remove client IP from TCP :9001
    else Knock password invalid
        Note over Server: Reject silently,<br/>auth port stays closed
        CLI--xServer: TLS connect fails<br/>(port blocked by NetworkPolicy)
        CLI-->>User: ✗ Connection refused
    end

    Note over K8s: After TTL expires (default 24h),<br/>sweeper removes IP/32<br/>from loadBalancerSourceRanges
```