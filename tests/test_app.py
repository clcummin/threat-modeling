import json
import sys
from types import SimpleNamespace
from pathlib import Path

import pandas as pd
from unittest.mock import patch

# Ensure repository root is on the import path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import app


def test_build_prompt_contains_surfaces_and_categories():
    rows = [{"Attack Surface": "Login", "Description": "User login"}]
    prompt = app.build_prompt(rows)
    assert "| Index | Attack Surface | Description |" in prompt
    assert "| 0 | Login | User login |" in prompt
    assert "information_leakage" in prompt


def test_classify_threats_populates_dataframe():
    data = pd.DataFrame([
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
        df = app.classify_threats(data, "test-key", base_url="")

    assert len(df) == 2
    assert list(df["Attack Surface"]) == ["Surface A", "Surface B"]
    assert df.loc[0, "Threat Type"] == "denial_of_service"
    assert df.loc[0, "Threat Description"] == "Example threat"
    assert df.loc[1, "Threat Type"] == ""


def test_classify_threats_handles_single_object_response():
    """Ensure classify_threats can handle a top-level JSON object."""
    data = pd.DataFrame([
        {"Attack Surface": "Surface A", "Description": "Desc A"},
        {"Attack Surface": "Surface B", "Description": "Desc B"},
    ])

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
        df = app.classify_threats(data, "test-key", base_url="")

    assert len(df) == 2
    assert df.loc[0, "Threat Type"] == "denial_of_service"
    assert df.loc[0, "Threat Description"] == "Example threat"
    assert df.loc[1, "Threat Type"] == ""


def test_classify_threats_multiple_threats_create_multiple_rows():
    data = pd.DataFrame([
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
        df = app.classify_threats(data, "test-key", base_url="")

    assert len(df) == 2
    assert all(df["Attack Surface"] == "Surface A")
    assert set(df["Threat Type"]) == {"denial_of_service", "trojan"}


def test_classify_threats_ignores_incomplete_threat_entries():
    data = pd.DataFrame([
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
                                    {"type": "denial_of_service", "description": ""},
                                    {"description": "No type"},
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
        df = app.classify_threats(data, "test-key", base_url="")

    # Incomplete threats should be ignored, resulting in an empty threat row
    assert len(df) == 1
    assert df.loc[0, "Threat Type"] == ""
    assert df.loc[0, "Threat Description"] == ""


def test_ensure_blank_surface_row_appends_blank_only_after_complete_row():
    df = pd.DataFrame([{"Attack Surface": "API", "Description": ""}])
    result = app.ensure_blank_surface_row(df)
    # No new row added until both fields are populated
    assert len(result) == 1
    assert result.iloc[0]["Attack Surface"] == "API"

    full = pd.DataFrame([{"Attack Surface": "API", "Description": "Desc"}])
    result = app.ensure_blank_surface_row(full)
    assert len(result) == 2
    assert result.iloc[1]["Attack Surface"] == ""

    # Calling again should not create additional empty rows
    result = app.ensure_blank_surface_row(result)
    assert len(result) == 2

