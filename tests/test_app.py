import json
import pandas as pd
import streamlit as st
from unittest.mock import patch
import sys
from types import SimpleNamespace
from pathlib import Path

# Ensure repository root is on the import path
sys.path.append(str(Path(__file__).resolve().parents[1]))

# Provide a lightweight stub for litellm to avoid heavy imports during testing
sys.modules.setdefault('litellm', SimpleNamespace(completion=lambda **kwargs: None))

import app


def test_build_prompt_contains_surfaces_and_categories():
    rows = [{"Attack Surface": "Login", "Description": "User login"}]
    prompt = app.build_prompt(rows)
    assert "Login - User login" in prompt
    assert "information_leakage" in prompt


def test_classify_threats_populates_dataframe():
    st.session_state.clear()
    st.session_state.data = pd.DataFrame([
        {"Attack Surface": "Surface A", "Description": "Desc A"},
        {"Attack Surface": "Surface B", "Description": "Desc B"},
    ])

    mock_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps([
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
                    ])
                }
            }
        ]
    }

    with patch("app.litellm.completion", return_value=mock_response):
        app.classify_threats("test-key", base_url="")

    df = st.session_state.data
    assert "Threat Type" in df.columns
    assert df.loc[0, "Threat Type"] == "denial_of_service"
    assert df.loc[0, "Threat Description"] == "Example threat"
    assert df.loc[1, "Threat Type"] == ""
