import json
from types import SimpleNamespace
from pathlib import Path
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
    assert "Login - User login" in prompt
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

