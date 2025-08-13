import json
import pandas as pd
import streamlit as st
from unittest.mock import patch
import sys
from types import SimpleNamespace
from pathlib import Path

# Ensure repository root is on the import path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import app


def test_build_prompt_contains_surfaces_and_categories():
    rows = [{"Attack Surface": "Login", "Description": "User login"}]
    prompt = app.build_prompt(rows)
    assert "Login - User login" in prompt
    assert "information_leakage" in prompt


def test_classify_threats_populates_dataframe():
    st.session_state.clear()
    st.session_state.input_df = pd.DataFrame([
        {"Attack Surface": "Surface A", "Description": "Desc A"},
        {"Attack Surface": "Surface B", "Description": "Desc B"},
    ])

    mock_response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=json.dumps(
                        [
                            {
                                "index": 0,
                                "threats": [
                                    {
                                        "type": "denial_of_service",
                                        "description": "Example threat",
                                    }
                                ],
                            },
                            {"index": 1, "threats": []},
                        ]
                    )
                )
            )
        ]
    )

    mock_client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=lambda **kwargs: mock_response)
        )
    )
    with patch("app.OpenAI", return_value=mock_client):
        app.classify_threats("test-key", base_url="")

    df = st.session_state.results_df
    assert len(df) == 2
    assert list(df["Attack Surface"]) == ["Surface A", "Surface B"]
    assert df.loc[0, "Threat Type"] == "denial_of_service"
    assert df.loc[0, "Threat Description"] == "Example threat"
    assert df.loc[1, "Threat Type"] == ""


def test_classify_threats_handles_single_object_response():
    """Ensure classify_threats can handle a top-level JSON object."""
    st.session_state.clear()
    st.session_state.input_df = pd.DataFrame([
        {"Attack Surface": "Surface A", "Description": "Desc A"},
        {"Attack Surface": "Surface B", "Description": "Desc B"},
    ])

    # Simulate a response where the model returned a single JSON object
    mock_response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=json.dumps(
                        {
                            "index": 0,
                            "threats": [
                                {
                                    "type": "denial_of_service",
                                    "description": "Example threat",
                                }
                            ],
                        }
                    )
                )
            )
        ]
    )

    mock_client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=lambda **kwargs: mock_response)
        )
    )

    with patch("app.OpenAI", return_value=mock_client):
        app.classify_threats("test-key", base_url="")

    df = st.session_state.results_df
    assert len(df) == 2
    assert df.loc[0, "Threat Type"] == "denial_of_service"
    assert df.loc[0, "Threat Description"] == "Example threat"
    assert df.loc[1, "Threat Type"] == ""


def test_classify_threats_multiple_threats_create_multiple_rows():
    st.session_state.clear()
    st.session_state.input_df = pd.DataFrame([
        {"Attack Surface": "Surface A", "Description": "Desc A"},
    ])

    mock_response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=json.dumps(
                        [
                            {
                                "index": 0,
                                "threats": [
                                    {
                                        "type": "denial_of_service",
                                        "description": "First threat",
                                    },
                                    {
                                        "type": "trojan",
                                        "description": "Second threat",
                                    },
                                ],
                            }
                        ]
                    )
                )
            )
        ]
    )

    mock_client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=lambda **kwargs: mock_response)
        )
    )
    with patch("app.OpenAI", return_value=mock_client):
        app.classify_threats("test-key", base_url="")

    df = st.session_state.results_df
    assert len(df) == 2
    assert all(df["Attack Surface"] == "Surface A")
    assert set(df["Threat Type"]) == {"denial_of_service", "trojan"}


def test_edit_table_persists_edits_via_on_change():
    """Edits in the table should sync to session_state via on_change."""
    st.session_state.clear()
    st.session_state.input_df = pd.DataFrame([
        {"Attack Surface": "", "Description": ""}
    ])

    updated_df = pd.DataFrame([
        {"Attack Surface": "Surface X", "Description": "Desc X"}
    ])

    def fake_data_editor(*args, **kwargs):
        # Ensure on_change callback is provided
        callback = kwargs.get("on_change")
        assert callable(callback)
        # Simulate user edit by setting widget value and invoking callback
        # Streamlit stores the edited value as a ``dict`` in session_state,
        # so emulate that behaviour to ensure ``edit_table`` converts it
        # back into a DataFrame.
        st.session_state["data_editor"] = updated_df.to_dict(orient="index")
        callback()
        return updated_df

    with patch("app.st.data_editor", side_effect=fake_data_editor):
        app.edit_table()

    assert st.session_state.input_df.equals(updated_df)


def test_edit_table_handles_data_state_without_input_df():
    """edit_table should fall back to ``data`` when ``input_df`` is absent."""
    st.session_state.clear()
    st.session_state.data = pd.DataFrame([
        {"Attack Surface": "", "Description": ""}
    ])

    updated_df = pd.DataFrame([
        {"Attack Surface": "Surface Y", "Description": "Desc Y"}
    ])

    def fake_data_editor(*args, **kwargs):
        callback = kwargs.get("on_change")
        assert callable(callback)
        # Directly store DataFrame to simulate editor returning DataFrame
        st.session_state["data_editor"] = updated_df
        callback()
        return updated_df

    with patch("app.st.data_editor", side_effect=fake_data_editor):
        app.edit_table()

    assert "input_df" not in st.session_state
    assert st.session_state.data.equals(updated_df)
