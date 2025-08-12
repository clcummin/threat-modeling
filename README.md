# Threat Modeling

A simple client-side application for documenting potential threats on attack surfaces.

## Usage

1. Open `index.html` locally or via GitHub Pages.
2. Provide your OpenAI API key in the input field.
3. Add rows and fill in attack surfaces with descriptions.
4. Click **Submit to AI** to classify threats. Two new columns will be filled with threat types and descriptions.

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

## Development

The project is entirely static. Open the HTML file directly or host it with GitHub Pages.
