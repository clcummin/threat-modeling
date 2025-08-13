# Threat Modeling

Utilities for documenting potential threats on attack surfaces.

## Usage

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Import the module and call `classify_threats` with a DataFrame of attack surfaces:
   ```python
   import pandas as pd
   import app

   df = pd.DataFrame([
       {"Attack Surface": "Login", "Description": "User login"}
   ])
   results = app.classify_threats(df, api_key="sk-...", base_url="https://llm.labs.blackduck.com/v1")
   ```

### Threat Categories

- `information_leakage` – Exposure of sensitive data via the surface.
- `data_integrity_violation` – Unauthorized modification/destruction of data.
- `control_plane_subversion` – Unauthorized modification/execution on the control plane.
- `denial_of_service` – Degradation or loss of availability.
- `illegitimate_use` – Abuse/misuse of resources beyond intended purpose.
- `entity_spoofing` – Masquerading as another principal/service.
- `forgery` – Fabricating messages/requests accepted as if from a trusted source.
- `bypassing_control` – Circumventing security controls (filtering, validation, authN/Z gates).
- `authorization_violation` – Access beyond assigned permissions.
- `trojan` – Malicious/compromised components introduced via supply chain or artifact.
- `guessing` – Ability to deduce or predict sensitive values (e.g., keys, tokens, identifiers).
- `repudiation` – Denying actions/transactions due to insufficient auditability or tamper-proof logging.
