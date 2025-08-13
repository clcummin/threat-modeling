"""Utilities for classifying threats on attack surfaces."""

import json
import pandas as pd
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


def format_attack_surfaces(rows: list[dict]) -> str:
    """Return a markdown table of attack surfaces and descriptions."""
    surface_rows = [
        f"| {i} | {r['Attack Surface']} | {r['Description']} |" for i, r in enumerate(rows)
    ]
    return "\n".join([
        "| Index | Attack Surface | Description |",
        "| --- | --- | --- |",
        *surface_rows,
    ])

def build_prompt(rows: list[dict]) -> str:
    """Construct the prompt for the AI model."""
    categories = "\n".join(
        f"{c['id']}: {c['description']}" for c in CATEGORIES
    )
    surfaces = format_attack_surfaces(rows)
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


def classify_threats(
    data: pd.DataFrame, api_key: str, base_url: str = ""
) -> pd.DataFrame:
    """Call the AI model via OpenAI and return classified threats."""
    data = data.copy()
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
            {
                "role": "system",
                "content": (
                    "You are a threat modeling assistant designed to output JSON without markdown formatting. Output raw JSON"
                ),
            },
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
        added_any = False

        for t in threats:
            t_type = (t.get("type") or "").strip()
            t_desc = (t.get("description") or "").strip()
            # Skip incomplete threat entries where either field is missing.
            if not (t_type and t_desc):
                continue
            new_rows.append(
                {
                    "Attack Surface": row["Attack Surface"],
                    "Description": row["Description"],
                    "Threat Type": t_type,
                    "Threat Description": t_desc,
                }
            )
            added_any = True

        if not added_any:
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

    return out


def ensure_blank_surface_row(data: pd.DataFrame) -> pd.DataFrame:
    """Return a copy with a single empty row when appropriate.

    Fully empty rows are dropped. A new blank row is appended only when all
    existing rows are complete so that reruns happen after an entry is finished
    rather than as soon as a single cell is populated.
    """
    df = data.copy()
    if {"Attack Surface", "Description"} - set(df.columns):
        df = df.reindex(columns=["Attack Surface", "Description"], fill_value="")

    mask = (
        df["Attack Surface"].astype(str).str.strip().ne("")
        | df["Description"].astype(str).str.strip().ne("")
    )
    df = df[mask].reset_index(drop=True)

    # Append a blank row only when there is no data or the last row is complete
    if df.empty or (
        df.iloc[-1]["Attack Surface"].strip() and df.iloc[-1]["Description"].strip()
    ):
        blank = pd.DataFrame([{"Attack Surface": "", "Description": ""}])
        df = pd.concat([df, blank], ignore_index=True)

    return df


def main() -> None:
    """Run the Streamlit interface for collecting attack surfaces."""
    import streamlit as st
    st.title("Threat Modeling")

    tab_surfaces, tab_threats = st.tabs(["Attack Surfaces", "Threats"])

    # ------------------------------- Tab 1 ---------------------------------
    with tab_surfaces:
        st.write("Enter attack surfaces and descriptions below.")

        if "attack_surfaces" not in st.session_state:
            st.session_state["attack_surfaces"] = ensure_blank_surface_row(
                pd.DataFrame(columns=["Attack Surface", "Description"])
            )

        st.session_state["attack_surfaces"] = ensure_blank_surface_row(
            st.session_state["attack_surfaces"]
        )

        edited_df = st.data_editor(
            st.session_state["attack_surfaces"],
            num_rows="dynamic",
            use_container_width=True,
            key="attack_surface_editor",
        )

        st.session_state["attack_surfaces"] = ensure_blank_surface_row(edited_df)

        api_key = st.text_input("API Key", type="password")
        base_url = "https://llm.labs.blackduck.com/v1"
        #st.text_input("Base URL", value="")

        if st.button("Generate Threats"):
            if api_key.strip():
                st.session_state["threats"] = classify_threats(
                    st.session_state["attack_surfaces"], api_key, base_url
                )
            else:
                st.warning("Please provide an API key")

    # ------------------------------- Tab 2 ---------------------------------
    with tab_threats:
        threats_df = st.session_state.get("threats")
        if threats_df is not None and not threats_df.empty:
            st.dataframe(threats_df, use_container_width=True)
        else:
            st.write("No threats generated yet.")


if __name__ == "__main__":
    main()
