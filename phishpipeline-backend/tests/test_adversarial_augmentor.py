import pandas as pd

from services.adversarial_augmentor import ADVERSARIAL_ATTACKS, AdversarialAugmentor


def test_exactly_15_attacks_defined():
    assert len(ADVERSARIAL_ATTACKS) == 15
    names = [name for name, _ in ADVERSARIAL_ATTACKS]
    assert len(set(names)) == 15  # all unique


def test_each_attack_returns_html_and_url_strings():
    for name, attack_fn in ADVERSARIAL_ATTACKS:
        html, url = attack_fn("<html></html>", "https://example.com/page")
        assert isinstance(html, str), f"{name} did not return a string html"
        assert isinstance(url, str), f"{name} did not return a string url"


def test_augment_dataset_adds_3_variants_per_phishing_sample():
    df = pd.DataFrame(
        [
            {"url": "https://phish1.example", "html_features": "<html>1</html>", "label": "phishing"},
            {"url": "https://phish2.example", "html_features": "<html>2</html>", "label": "phishing"},
            {"url": "https://clean1.example", "html_features": "<html>3</html>", "label": "clean"},
        ]
    )

    result = AdversarialAugmentor().augment_dataset(df)

    # 3 original rows + (2 phishing rows * 3 variants each) = 9
    assert len(result) == 9
    assert (result["label"] == "clean").sum() == 1
    assert (result["label"] == "phishing").sum() == 8


def test_augment_dataset_leaves_original_rows_unmodified():
    df = pd.DataFrame(
        [
            {"url": "https://phish1.example", "html_features": "<html>original</html>", "label": "phishing"},
        ]
    )

    result = AdversarialAugmentor().augment_dataset(df)

    original_row = result.iloc[0]
    assert original_row["url"] == "https://phish1.example"
    assert original_row["html_features"] == "<html>original</html>"


def test_augment_dataset_with_no_phishing_samples_returns_unchanged():
    df = pd.DataFrame(
        [{"url": "https://clean1.example", "html_features": "<html></html>", "label": "clean"}]
    )

    result = AdversarialAugmentor().augment_dataset(df)

    assert len(result) == 1


def test_augment_dataset_tracks_attack_type_counts():
    df = pd.DataFrame(
        [
            {"url": f"https://phish{i}.example", "html_features": "<html></html>", "label": "phishing"}
            for i in range(5)
        ]
    )

    result = AdversarialAugmentor().augment_dataset(df)
    counts = result.attrs.get("attack_type_counts", {})

    # 5 phishing samples * 3 variants * 3 attacks per variant = 45 total attack applications
    assert sum(counts.values()) == 45
    assert set(counts.keys()).issubset({name for name, _ in ADVERSARIAL_ATTACKS})
