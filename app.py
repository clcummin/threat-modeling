"""Streamlit application for classifying threats on attack surfaces."""

import json
import os

import pandas as pd
import streamlit as st
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
    if "input_df" not in st.session_state:
        st.session_state.input_df = pd.DataFrame(
            [{"Attack Surface": "", "Description": ""}]
        )
    if "results_df" not in st.session_state:
        st.session_state.results_df = pd.DataFrame()


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
    """Display and update the attack surface input table."""

    def _sync_editor() -> None:
        # Prefer the editor value, fall back to current input/data
        value = st.session_state.get(
            "data_editor",
            st.session_state.get("input_df", st.session_state.get("data")),
        )

        # --- Normalize to a DataFrame robustly ---
        if isinstance(value, pd.DataFrame):
            df = value.copy()
        elif isinstance(value, dict):
            # dict-of-lists/Series -> DataFrame(value)
            if all(isinstance(v, (list, tuple, pd.Series)) for v in value.values()):
                df = pd.DataFrame(value)
            # dict-of-dicts -> from_dict(..., orient="index")
            elif all(isinstance(v, dict) for v in value.values()):
                df = pd.DataFrame.from_dict(value, orient="index")
            else:
                # single flat dict -> one row
                df = pd.DataFrame.from_records([value])
        elif isinstance(value, (list, tuple)):
            # list-of-dicts or list-like -> DataFrame handles both
            df = pd.DataFrame(value)
        else:
            # last resort: wrap as single row
            df = pd.DataFrame.from_records([{"Attack Surface": "", "Description": ""}])

        # Ensure required columns exist
        for col in ["Attack Surface", "Description"]:
            if col not in df.columns:
                df[col] = ""

        # Keep only rows where at least one field has content
        df = df[
            df["Attack Surface"].astype(str).str.strip().ne("")
            | df["Description"].astype(str).str.strip().ne("")
        ].reset_index(drop=True)

        # Write back to state (supporting either input_df or data usage)
        if "input_df" in st.session_state:
            st.session_state.input_df = df
        else:
            st.session_state.data = df
        st.session_state["data_editor"] = df

    st.data_editor(
        st.session_state.get("input_df", st.session_state.get("data")),
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
    data = st.session_state.input_df.copy()
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

    new_rows: list[dict] = []
    for idx, row in enumerate(rows):
        threats = items_by_index.get(idx, []) or []

        for t in threats:
            t_type = (t.get("type") or "").strip()
            t_desc = (t.get("description") or "").strip()
            if not (t_type or t_desc):
                continue
            new_rows.append(
                {
                    "Attack Surface": row["Attack Surface"],
                    "Description": row["Description"],
                    "Threat Type": t_type,
                    "Threat Description": t_desc,
                }
            )

        if not threats:
            new_rows.append(
                {
                    "Attack Surface": row["Attack Surface"],
                    "Description": row["Description"],
                    "Threat Type": "",
                    "Threat Description": "",
                }
            )

    if new_rows:
        out = pd.DataFrame(new_rows).drop_duplicates(
            subset=[
                "Attack Surface",
                "Description",
                "Threat Type",
                "Threat Description",
            ]
        ).reset_index(drop=True)
    else:
        out = pd.DataFrame(
            columns=[
                "Attack Surface",
                "Description",
                "Threat Type",
                "Threat Description",
            ]
        )

    st.session_state.results_df = out


def main() -> None:
    """Run the Streamlit application."""
    st.set_page_config(page_title="Threat Modeling Assistant", layout="wide")
    st.title("Threat Modeling Assistant")
    st.write(
        "Enter attack surfaces and descriptions. Provide your OpenAI API key and optionally a custom API base URL, then submit to classify threats."
    )

    init_state()
    api_key, base_url = get_credentials()
    edit_table()

    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        if st.button("Submit to AI"):
            if not api_key:
                st.error("API key required.")
            else:
                classify_threats(api_key, base_url)
                st.rerun()
    with col2:
        if st.button("Clear results"):
            st.session_state.results_df = pd.DataFrame()
    with col3:
        if st.button("Reset input"):
            st.session_state.input_df = pd.DataFrame(
                [{"Attack Surface": "", "Description": ""}]
            )
            st.session_state["data_editor"] = st.session_state.input_df.copy()

    if not st.session_state.results_df.empty:
        st.subheader("Classified Threats")
        st.dataframe(st.session_state.results_df, use_container_width=True)
        st.download_button(
            "Download results as CSV",
            data=st.session_state.results_df.to_csv(index=False).encode("utf-8"),
            file_name="threats.csv",
            mime="text/csv",
        )


if __name__ == "__main__":
    main()
