# Core Services Overview :gear:

<div class='grid cards' markdown>
-   :material-shield-check:{ .lg .middle } **Security First**
    
    ---
    
    Zero-trust architecture with comprehensive audit trails.
-   :material-puzzle:{ .lg .middle } **Modular Design**
    
    ---
    
    Plugin-based architecture for extensibility.
</div>

!!! info "Canonical Service — Purpose"
     The Canonical Service centralizes data normalization and transformation across all plugins.

## Core Services Offered:
### Canonical Service:
- Data normalization
- PHI/PII transformation
- Audit logging

```mermaid
graph LR;
A[Canonical Input] --> B[Normalization];
B --> C[Transformation];
C --> D[Audit Log];
```

### Storage Service:
- Encrypted storage layer
- HIPAA-compliant retention policies
- Comprehensive audit integration

!!! danger "HIPAA Reminder"
Ensure all operations comply with HIPAA regulations, especially when handling PHI/PII data.
