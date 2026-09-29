"""
Tests for the IOC extractor.
Run with:  pytest -q test_ioc_extractor.py
"""
from llm.gateway.ioc_extractor import extract_iocs


def test_text_without_indicators_returns_nothing():
    # The bug this guards against: a lunch menu used to "contain" 10 threat indicators.
    result = extract_iocs("The cafeteria menu for Monday is rice and dal.")
    assert result["iocs"] == []
    assert result["threat_actors"] == []
    assert result["malware"] == []


def test_finds_indicators_that_are_in_the_text():
    report = (
        "Host 10.14.6.23 beaconed to 185.220.101[.]47 and secure-update-cdn[.]net. "
        "The exploit used cve-2023-23397. "
        "Dropper SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
    )
    result = extract_iocs(report)
    assert result["cves"] == ["CVE-2023-23397"]
    assert result["ips"] == ["10.14.6.23", "185.220.101[.]47"]
    assert result["domains"] == ["secure-update-cdn[.]net"]
    assert result["hashes"] == ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]


def test_never_returns_anything_not_in_the_text():
    report = "Traffic went to 45.134.26.201. Then stopped."
    for value in extract_iocs(report)["iocs"]:
        assert value in report


def test_ignores_things_that_only_look_like_indicators():
    result = extract_iocs("Version 1.2.3.4.5, bad address 999.1.1.1, file report.pdf")
    assert result["iocs"] == []


def test_duplicates_are_listed_once():
    result = extract_iocs("CVE-2023-23397 again: cve-2023-23397, and 8.8.8.8 twice 8.8.8.8")
    assert result["cves"] == ["CVE-2023-23397"]
    assert result["ips"] == ["8.8.8.8"]


def test_ordinary_text_with_dots_is_not_a_domain():
    # The bug this guards against: "document.title" and "Mr.Smith" were listed as domains.
    text = "Mr.Smith checked document.title and window.location, e.g. No.of cases rose."
    assert extract_iocs(text)["domains"] == []


def test_real_and_defanged_domains_are_found():
    text = "Traffic to evil.ru, update-cdn.net, api.malicious-site.co.uk and payload[.]badending"
    assert extract_iocs(text)["domains"] == [
        "evil.ru", "update-cdn.net", "api.malicious-site.co.uk", "payload[.]badending",
    ]
