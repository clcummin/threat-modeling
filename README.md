# Threat Modeling

A simple application for documenting potential threats on attack surfaces.

## Streamlit Deployment

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the app:
   ```bash
   streamlit run app.py
   ```
3. Provide your OpenAI API key in the input field and optionally set a custom API endpoint.
4. Add rows and fill in attack surfaces with descriptions.
5. Click **Submit to AI** to classify threats. Two new columns will be filled with threat types and descriptions.

### Threat Categories

| id | description |
| --- | --- |
| `information_leakage` | Exposure of sensitive data via the surface. |
| `data_integrity_violation` | Unauthorized modification/destruction of data. |
| `control_plane_subversion` | Unauthorized modification/execution on the control plane. |
| `denial_of_service` | Degradation or loss of availability. |
| `illegitimate_use` | Abuse/misuse of resources beyond intended purpose. |
| `entity_spoofing` | Masquerading as another principal/service. |
| `forgery` | Fabricating messages/requests accepted as if from a trusted source. |
| `bypassing_control` | Circumventing security controls (filtering, validation, authN/Z gates). |
| `authorization_violation` | Access beyond assigned permissions. |
| `trojan` | Malicious/compromised components introduced via supply chain or artifact. |
| `guessing` | Ability to deduce or predict sensitive values (e.g., keys, tokens, identifiers). |
| `repudiation` | Denying actions/transactions due to insufficient auditability or tamper-proof logging. |
