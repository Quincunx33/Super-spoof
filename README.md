<div align="center">

# ✦ SUPER SPOOF ✦

### Advanced UA Forge

**User-Agent generation, without the learning curve.**

Create browser profiles in seconds. Check matching HTTP headers.  
Explore deeper network diagnostics when you feel ready.

<p>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <a href="https://pypi.org/project/advanced-ua-forge/4.5.0/"><img alt="PyPI release" src="https://img.shields.io/pypi/v/advanced-ua-forge?style=for-the-badge&color=8A63D2&label=PyPI"></a>
  <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-2EA44F?style=for-the-badge">
</p>

<p>
  <img alt="Offline core" src="https://img.shields.io/badge/Core-Works%20Offline-1F8AC0?style=flat-square">
  <a href="https://github.com/Quincunx33/Super-spoof/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/Quincunx33/Super-spoof/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Quincunx33/Super-spoof/releases/tag/v4.5.0"><img alt="Latest GitHub release" src="https://img.shields.io/badge/Release-v4.5.0-2EA44F?style=flat-square"></a>
</p>

**[Get started](#-quick-start)** · **[See examples](#-examples)** · **[PyPI](https://pypi.org/project/advanced-ua-forge/4.5.0/)** · **[GitHub Release](https://github.com/Quincunx33/Super-spoof/releases/tag/v4.5.0)** · **[Advanced guide](docs/ADVANCED.md)**

</div>

---

## 👋 What is Super Spoof?

Ever needed a Chrome, Firefox, Edge, or Safari **User-Agent string**, but didn't want to search for one manually?

That's what **Advanced UA Forge** helps with.

A *User-Agent* is simply a line of text that identifies a browser and device to a website. This Python package can generate sample User-Agent strings, pair them with browser-style HTTP headers, and help you spot inconsistent profile information.

**You can start with one line of Python.** The technical tools are completely optional.

## ⚡ Quick start

**You need:** Python 3.10 or newer.

**Step 1 — Install from PyPI**

~~~bash
python -m pip install advanced-ua-forge
~~~

Version **4.5.0** is available on [PyPI](https://pypi.org/project/advanced-ua-forge/4.5.0/). No repository clone is needed for a normal installation.

<details>
<summary><b>Prefer installing from source?</b></summary>

~~~bash
git clone https://github.com/Quincunx33/Super-spoof.git
cd Super-spoof
python -m pip install .
~~~

</details>

**Step 2 — Try it**

Create a file called <code>main.py</code>:

~~~python
from ua_forge import UserAgent

ua = UserAgent()

print(ua.random)   # Random browser User-Agent
print(ua.chrome)   # Chrome
print(ua.firefox)  # Firefox
print(ua.safari)   # Safari
print(ua.edge)     # Edge
~~~

Run it:

~~~bash
python main.py
~~~

**Done!** You just generated your first browser User-Agent strings.

## ✨ What can it do?

| | Feature | Why it's useful |
|:--:|---|---|
| 🎲 | **Random User-Agents** | Get a sample browser identity in one line |
| 🌐 | **Popular browsers** | Chrome, Firefox, Safari and Edge |
| 📱 | **Device profiles** | Choose desktop, mobile or tablet examples |
| 🧩 | **Matching headers** | Generate HTTP headers alongside a UA |
| ✅ | **Consistency checks** | Find conflicts between UA, headers and metadata |
| 📦 | **Offline core** | Generate profiles without an internet connection |
| 🔬 | **Optional diagnostics** | Inspect TLS/JA4, QUIC, DTLS and HTTP/2 data |

<sub>Profiles are curated examples, not guaranteed copies of the newest installed browsers. Advanced diagnostics require additional tools or permissions.</sub>

## 🧪 Examples

<details open>
<summary><b>1. Generate a specific browser profile</b></summary>

<br>

~~~python
from ua_forge import UserAgent

ua = UserAgent()

profile = ua.profile(
    browser="chrome",
    platform="windows"
)

print(profile.user_agent)
~~~

Choose a browser and operating system instead of picking randomly.

</details>

<details>
<summary><b>2. See headers and device details</b></summary>

<br>

~~~python
from ua_forge import UserAgent

profile = UserAgent(locale="bd").profile(
    browser="chrome",
    platform="android",
    device="mobile"
)

print(profile.headers)
print(profile.metadata)
~~~

The headers are example templates and don't change your actual phone or browser.

</details>

<details>
<summary><b>3. Check whether a profile is consistent</b></summary>

<br>

~~~python
from ua_forge import UserAgent

profile = UserAgent().profile(browser="chrome")

report = profile.validate()

print(report.valid)
print(report.as_dict())
~~~

This checks known profile/header mismatches. A valid report doesn't prove that a request matches a real browser fingerprint.

</details>

<details>
<summary><b>4. Prefer using the terminal?</b></summary>

<br>

~~~bash
ua-forge --browser chrome --platform windows
~~~

The command-line tool is installed with the package.

</details>

## 🛠️ Want to go further?

Start with the simple generator. When you are comfortable, there is more to explore:

| Explore | What's inside |
|---|---|
| **Browser inspection** | Compare observed browser details with sample profiles |
| **TLS & JA3/JA4** | Inspect handshake fingerprints from authorized traffic |
| **QUIC & DTLS** | Examine supported initial handshake formats |
| **PCAP diagnostics** | Analyze your own packet captures with optional tools |
| **Cloudflare analytics** | Read security events for a zone you manage |
| **Browser version refresh** | Opt in to verified release-data updates |

**[Read the full Advanced Guide →](docs/ADVANCED.md)**

The advanced guide includes installation extras, sample code, dependencies, technical specifications, troubleshooting details, and important limitations.

## ❓ A few useful answers

<details>
<summary><b>Do I need to understand networking?</b></summary>

No. For everyday User-Agent generation, just install the package and use <code>UserAgent().random</code>.

</details>

<details>
<summary><b>Does this change my real browser or device?</b></summary>

No. It generates sample strings and metadata; it does not modify your browser, operating system, IP address, or actual network fingerprint.

</details>

<details>
<summary><b>Does it bypass Cloudflare or other firewalls?</b></summary>

No. This is a generator and diagnostic toolkit, not a guaranteed way around website security or access controls.

</details>

<details>
<summary><b>Will it run on an iPhone?</b></summary>

The pure-Python features may work in compatible iOS Python apps, depending on package support. Native capture tools, Playwright browsers, and privileged network features generally need a supported computer or server.

</details>

<details>
<summary><b>Is it available on PyPI?</b></summary>

Yes! **Advanced UA Forge v4.5.0** is published on [PyPI](https://pypi.org/project/advanced-ua-forge/4.5.0/). Install it with <code>python -m pip install advanced-ua-forge</code>. The [GitHub Release](https://github.com/Quincunx33/Super-spoof/releases/tag/v4.5.0) also contains downloadable wheel and source distribution files.

</details>

## 🤝 Contributing & development

Want to improve the project? Open an issue with a clear bug report or feature idea.

To run the local tests:

~~~bash
python -m pip install pytest
python -m pytest -q
~~~

The **v4.5.0 release** passed its GitHub Actions test jobs on **Python 3.10, 3.11, 3.12, and 3.13**, with package build and metadata checks also passing. See the [successful release run](https://github.com/Quincunx33/Super-spoof/actions/runs/41138634190). These offline checks do **not** establish successful live packet capture, every browser engine, or production Cloudflare API compatibility.

## 🔐 Responsible use

Only inspect traffic and Cloudflare zones you own or have explicit permission to analyze. Never share TLS session key logs or API tokens. Sample profiles and matching headers do not guarantee a real-browser identity.

---

<div align="center">

**Made for curious beginners. Ready for deeper diagnostics.**

<sub>Advanced UA Forge v4.5.0 · <a href="https://pypi.org/project/advanced-ua-forge/4.5.0/">PyPI</a> · <a href="https://github.com/Quincunx33/Super-spoof/releases/tag/v4.5.0">Release downloads</a> · <a href="LICENSE">MIT License</a> · <a href="docs/ADVANCED.md">Technical documentation</a></sub>

</div>
