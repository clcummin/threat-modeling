"""Streamlit application for classifying threats on attack surfaces."""

import json
import os

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from openai import OpenAI

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

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

DEFAULT_API_KEY = os.environ.get("OPENAI_API_KEY", "")
DEFAULT_BASE_URL = os.environ.get("OPENAI_BASE_URL", "")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def init_state() -> None:
    """Initialize session state for input and output tables."""
    if "input_data" not in st.session_state:
        # Start with a single empty row for user input. ``st.data_editor``
        # allows users to append rows dynamically, so pre-filling with many
        # blanks is unnecessary.
        st.session_state.input_data = pd.DataFrame([
            {"Attack Surface": "", "Description": ""}
        ])
    if "result_data" not in st.session_state:
        st.session_state.result_data = pd.DataFrame(
            columns=[
                "Attack Surface",
                "Description",
                "Threat Type",
                "Threat Description",
            ]
        )


def get_credentials() -> tuple[str, str]:
    """Render text inputs for API credentials and return their values."""
    api_key = st.text_input(
        "OpenAI API Key", type="password", value=DEFAULT_API_KEY
    ).strip()
    base_url = st.text_input(
        "AI API Base URL (optional)", value=DEFAULT_BASE_URL
    ).strip()
    return api_key, base_url


def edit_table() -> None:
    """Display and update the attack surface input table.

    The previous implementation assigned the result of ``st.data_editor``
    directly to ``st.session_state`` on every rerun. This caused an extra
    rerun while an edit was in progress, occasionally wiping out the user's
    current input. To avoid this, we now update the stored DataFrame only
    when the editor reports a change via ``on_change``.
    """

    def _sync_editor() -> None:
        """Synchronize the widget's value back to ``session_state``."""
        value = st.session_state["data_editor"]
        # ``st.data_editor`` stores its value in ``session_state`` using either a
        # ``dict`` or a ``list``. Converting the widget's value to a proper
        # ``DataFrame`` and writing it back to both ``input_data`` and
        # ``data_editor`` keeps subsequent reruns stable.
        if not isinstance(value, pd.DataFrame):
            if isinstance(value, dict):
                value = pd.DataFrame.from_dict(value, orient="index").reset_index(
                    drop=True
                )
            else:
                value = pd.DataFrame(value)

        # Drop rows where both fields are blank to avoid accumulating extra
        # empty entries when the user edits the table.
        value = value[
            value["Attack Surface"].astype(str).str.strip().ne("")
            | value["Description"].astype(str).str.strip().ne("")
        ].reset_index(drop=True)

        st.session_state.input_data = value
        st.session_state["data_editor"] = value

    st.data_editor(
        st.session_state.input_data,
        num_rows="dynamic",
        use_container_width=True,
        height=600,
        key="data_editor",
        on_change=_sync_editor,
    )


def build_prompt(rows: list[dict]) -> str:
    """Construct the prompt for the AI model."""
    categories = "\n".join(
        f"{c['id']}: {c['description']}" for c in CATEGORIES
    )
    surfaces = "\n".join(
        f"#{i}: {r['Attack Surface']} - {r['Description']}" for i, r in enumerate(rows)
    )
    return (
        "You are a threat modeling assistant. For each attack surface below, "
        "identify applicable threat categories from this list and provide a "
        "contextual and specific description explaining how the threat could be "
        "carried out to achieve its goal. Omit categories that do not apply. "
        "Respond with JSON only in the form:\n"
        "[\n  {\"index\":0,\"threats\":[{\"type\":\"<category_id>\",\"description\":\"<text>\"}]}\n]\n\n"
        f"Threat Categories:\n{categories}\n\n"
        f"Attack Surfaces:\n{surfaces}\n"
    )


def classify_threats(api_key: str, base_url: str) -> None:
    """Call the AI model via OpenAI and populate the output table."""
    # Exclude rows where the user has not provided any information. These
    # placeholder rows would otherwise be sent to the model and also appear in
    # the final output as spurious blank entries.
    data = st.session_state.input_data.copy()
    data = data[
        data["Attack Surface"].astype(str).str.strip().ne("")
        | data["Description"].astype(str).str.strip().ne("")
    ]
    rows = data[["Attack Surface", "Description"]].fillna("").to_dict(
        orient="records"
    )
    prompt = build_prompt(rows)

    client = OpenAI(api_key=api_key, base_url=base_url or None)
    response = client.chat.completions.create(
        model="gpt-4o",
        response_format={"type": "json_object"},
        max_tokens=4000,
        messages=[
            {"role": "system", "content": "You are a threat modeling assistant designed to output JSON without markdown formatting. Output raw JSON"},
            {"role": "user", "content": prompt},
        ],
        temperature=0,
    )
    parsed = json.loads(response.choices[0].message.content)

    # The model is asked to return a JSON list, but in practice the
    # response may be a single object or wrapped in a dictionary.  This
    # normalizes the parsed structure into a list of items so that the
    # subsequent loop works regardless of the exact format and avoids
    # ``TypeError: string indices must be integers`` when iterating over a
    # dictionary's keys.
    if isinstance(parsed, dict):
        # If the dict already represents a single item with "index" and
        # "threats" keys, wrap it in a list.  Otherwise attempt to find a
        # list value inside the dictionary (e.g. under "results" or
        # similar).  If none is found, treat the entire dict as a single
        # item.
        if {"index", "threats"}.issubset(parsed.keys()):
            parsed = [parsed]
        else:
            list_value = next(
                (v for v in parsed.values() if isinstance(v, list)), None
            )
            parsed = list_value if list_value is not None else [parsed]

    # Build a mapping from response index to threats for easier lookup
    items_by_index = {item.get("index"): item.get("threats", []) for item in parsed}

    new_rows = []
    for idx, row in enumerate(rows):
        threats = items_by_index.get(idx, [])
        if threats:
            for threat in threats:
                new_rows.append(
                    {
                        "Attack Surface": row["Attack Surface"],
                        "Description": row["Description"],
                        "Threat Type": threat.get("type", ""),
                        "Threat Description": threat.get("description", ""),
                    }
                )
        else:
            new_rows.append(
                {
                    "Attack Surface": row["Attack Surface"],
                    "Description": row["Description"],
                    "Threat Type": "",
                    "Threat Description": "",
                }
            )

    st.session_state.result_data = pd.DataFrame(new_rows)


def main() -> None:
    """Run the Streamlit application."""
    st.set_page_config(page_title="Threat Modeling Assistant", layout="wide")
    st.title("Threat Modeling Assistant")
    st.write(
        "Enter attack surfaces and descriptions. Provide your OpenAI API key and optionally a custom API base URL, then submit to classify threats."
    )

    init_state()
    tab_input, tab_output = st.tabs(["Inputs", "Threat Mapping"])

    with tab_input:
        api_key, base_url = get_credentials()
        edit_table()

        if st.button("Run"):
            if not api_key:
                st.error("API key required.")
            else:
                try:
                    classify_threats(api_key, base_url)
                    st.session_state.switch_to_output = True
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

    with tab_output:
        st.dataframe(
            st.session_state.result_data,
            use_container_width=True,
        )

    if st.session_state.get("switch_to_output"):
        st.session_state.switch_to_output = False
        components.html(
            """
            <script>
            const tabs = window.parent.document.querySelectorAll('.stTabs button');
            if (tabs.length > 1) { tabs[1].click(); }
            </script>
            """,
            height=0,
        )


if __name__ == "__main__":
    main()
