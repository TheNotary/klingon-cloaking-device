# Operator Process Flow — CloakingDevice CRD Lifecycle

The Klingon Cloaking Device operator protects Kubernetes Services exposed via external load balancers by managing their `loadBalancerSourceRanges`. A cluster admin creates a `CloakingDevice` custom resource that names the Service to protect and an optional IP TTL. The operator watches these CRs cluster-wide, registers each target service, and from that point forward controls which client IPs are allowed through. A background sweeper periodically removes IPs whose TTL has expired, re-cloaking the service.

```mermaid
graph TD
    A[Admin authors CloakingDevice CR<br/><i>spec.serviceName · spec.ttlHours</i>] --> B["kubectl apply -f cloakingdevice.yaml"]
    B --> C[CR created in Kubernetes API]
    C --> D[Operator CRD watcher detects new/updated CR]
    D --> E["Operator registers target<br/>(namespace, serviceName)"]
    E --> F{Service is now cloaked}
    F -->|Authorized IP added<br/>via access approval| G["IP/32 appended to Service's<br/>loadBalancerSourceRanges"]
    G --> H["Client can reach Service<br/>for TTL duration (default 24h)"]
    H --> I["Background sweeper runs<br/>(every 5 min)"]
    I -->|TTL expired| J["IP/32 removed from<br/>loadBalancerSourceRanges"]
    J --> F
    I -->|TTL still valid| H

    C --> K["Admin deletes CR<br/>kubectl delete cloakingdevice ..."]
    K --> L[Operator removes target from tracking]
    L --> M["Service loadBalancerSourceRanges<br/>no longer managed by operator"]

    style A fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style F fill:#d4a84b,stroke:#a07830,color:#fff
    style H fill:#5cb85c,stroke:#3d8b3d,color:#fff
    style J fill:#d9534f,stroke:#a94442,color:#fff
    style M fill:#777,stroke:#555,color:#fff
```