import json

from tools.codex_model_sync import merge_catalog, sync_catalog


def _model(slug: str, visibility: str = "list") -> dict:
    return {
        "slug": slug,
        "display_name": slug,
        "description": "test model",
        "default_reasoning_level": "medium",
        "supported_reasoning_levels": [{"effort": "medium", "description": "test"}],
        "model_messages": {"instructions_template": "test"},
        "visibility": visibility,
        "supported_in_api": True,
        "priority": 1,
    }


def test_merge_adds_models_and_hides_removed_models():
    catalog = {"models": [_model("gpt-5.6-luna"), _model("old-model"), _model("codex-auto-review", "hide")]}
    upstream = [{"id": "gpt-5.6-luna"}, {"id": "gpt-6-luna"}]

    updated, state, added, hidden, restored = merge_catalog(catalog, upstream, {})

    assert added == ("gpt-6-luna",)
    assert hidden == ("old-model",)
    assert restored == ()
    by_slug = {model["slug"]: model for model in updated["models"]}
    assert by_slug["gpt-6-luna"]["visibility"] == "list"
    assert by_slug["old-model"]["visibility"] == "hide"
    assert by_slug["codex-auto-review"]["visibility"] == "hide"
    assert "gpt-6-luna" in state["managed_models"]


def test_merge_restores_a_model_hidden_by_an_earlier_sync():
    catalog = {"models": [_model("gpt-6-luna", "hide")]}
    upstream = [{"id": "gpt-6-luna"}]
    state = {"managed_models": ["gpt-6-luna"], "hidden_by_sync": ["gpt-6-luna"]}

    updated, _, added, hidden, restored = merge_catalog(catalog, upstream, state)

    assert added == ()
    assert hidden == ()
    assert restored == ("gpt-6-luna",)
    assert updated["models"][0]["visibility"] == "list"


def test_sync_marks_restart_pending_after_catalog_change(tmp_path):
    catalog_path = tmp_path / "models.json"
    catalog_path.write_text(json.dumps({"models": [_model("gpt-5.6-luna")]}) + "\n")

    result = sync_catalog(catalog_path, [{"id": "gpt-5.6-luna"}, {"id": "gpt-6.1-sol"}])

    assert result.changed is True
    assert result.restart_pending is True
    state = json.loads((tmp_path / "models.json.sync-state.json").read_text())
    assert state["restart_pending"] is True
    assert json.loads(catalog_path.read_text())["models"][-1]["slug"] == "gpt-6.1-sol"
