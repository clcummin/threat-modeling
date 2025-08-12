import streamlit as st
import pandas as pd
import requests
import json
import os

# Threat categories used for classification
CATEGORIES = [
    {"id": "information_leakage", "description": "Exposure of sensitive data via the surface."},
    {"id": "data_integrity_violation", "description": "Unauthorized modification/destruction of data."},
    {"id": "control_plane_subversion", "description": "Unauthorized modification/execution on the control plane."},
    {"id": "denial_of_service", "description": "Degradation or loss of availability."},
    {"id": "illegitimate_use", "description": "Abuse/misuse of resources beyond intended purpose."},
    {"id": "entity_spoofing", "description": "Masquerading as another principal/service."},
    {"id": "forgery", "description": "Fabricating messages/requests accepted as if from a trusted source."},
    {"id": "bypassing_control", "description": "Circumventing security controls (filtering, validation, authN/Z gates)."},
    {"id": "authorization_violation", "description": "Access beyond assigned permissions."},
    {"id": "trojan", "description": "Malicious/compromised components introduced via supply chain or artifact."},
    {"id": "guessing", "description": "Ability to deduce or predict sensitive values (e.g., keys, tokens, identifiers)."},
    {"id": "repudiation", "description": "Denying actions/transactions due to insufficient auditability or tamper-proof logging."},
]

st.title("Threat Modeling Assistant")
st.write(
    "Enter attack surfaces and descriptions. Provide your OpenAI API key and optionally a custom endpoint, then submit to classify threats."
)

default_api_key = os.environ.get("OPENAI_API_KEY", "")
api_key = st.text_input(
    "OpenAI API Key",
    type="password",
    value=default_api_key,
).strip()

api_key = st.text_input("OpenAI API Key", type="password").strip()
endpoint = st.text_input("AI API Endpoint (optional)").strip()

# Initialize table
if "data" not in st.session_state:
    st.session_state.data = pd.DataFrame(
        [{"Attack Surface": "", "Description": ""}]
    )

# Allow user to edit table dynamically
edited = st.data_editor(
    st.session_state.data,
    num_rows="dynamic",
    use_container_width=True,
    key="data_editor",
)
st.session_state.data = edited

if st.button("Submit to AI"):
    if not api_key:
        st.error("API key required.")
    else:
        rows = (
            st.session_state.data[["Attack Surface", "Description"]]
            .fillna("")
            .to_dict(orient="records")
        )
        prompt = f"""
You are a threat modeling assistant. For each attack surface below, identify applicable threat categories from this list and provide a brief description. Omit categories that do not apply. Respond with JSON only in the form:
[
  {{"index":0,"threats":[{{"type":"<category_id>","description":"<text>"}}]}}
]

Threat Categories:
{chr(10).join([f"{c['id']}: {c['description']}" for c in CATEGORIES])}

Attack Surfaces:
{chr(10).join([f"#{i}: {r['Attack Surface']} - {r['Description']}" for i, r in enumerate(rows)])}
"""
        try:
            url = endpoint or "https://api.openai.com/v1/responses"
            response = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4o-mini",
                    "input": prompt,
                    "response_format": {"type": "json_object"},
                },
                timeout=30,
            )
            response.raise_for_status()
            body = response.json()
            parsed = json.loads(body["output"][0]["content"][0]["text"])

            if "Threat Type" not in st.session_state.data.columns:
                st.session_state.data["Threat Type"] = ""
                st.session_state.data["Threat Description"] = ""

            for item in parsed:
                types = "\n".join(t["type"] for t in item["threats"])
                descs = "\n".join(t["description"] for t in item["threats"])
                st.session_state.data.at[item["index"], "Threat Type"] = types
                st.session_state.data.at[
                    item["index"], "Threat Description"
                ] = descs

            st.experimental_rerun()
        except Exception as e:
            st.error(str(e))
