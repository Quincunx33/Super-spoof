# Publish Advanced UA Forge on PyPI

This is a **release candidate**; the artifacts were built and checked locally, but **not uploaded**.

## 1. Before publishing

- Confirm that you own the package name `advanced-ua-forge`. A 404 from PyPI does **not** guarantee a name is claimable.
- Review the LICENSE and replace the copyright attribution if needed.
- Review public API, documentation and security-sensitive diagnostics; verify on your target platforms.
- Create and verify a PyPI account at https://pypi.org/ and preferably enable 2FA.
- Check for any accidental secrets before distributing (API keys, captures, credentials, private data).

## 2. Build + test on a computer/CI

```bash
python -m pip install --upgrade build twine pytest
python -m pytest -q
python -m build
python -m twine check dist/*
```

The published **distribution** is `advanced-ua-forge`. The **Python import** is `ua_forge` and the CLI command is `ua-forge`.

## 3. Test upload (recommended)

Create a separate TestPyPI account and token at https://test.pypi.org/.

```bash
python -m twine upload --repository testpypi dist/*
```

Never paste your API token into public chat or commit it to Git.

## 4. Publish from iPhone with GitHub Actions (recommended)

The source includes `.github/workflows/publish.yml`. You can upload the source as a GitHub repository from your iPhone; you do **not** need to run build tools on the phone.

1. Create your GitHub repository and commit the release source (including the hidden `.github` directory).
2. In the repository, configure an environment named `pypi` under Settings → Environments.
3. In your PyPI account, configure a **Trusted Publisher** for the *exact* GitHub account/repository name, workflow filename `publish.yml`, and environment `pypi` (for a new project, use PyPI pending publishers). See https://docs.pypi.org/trusted-publishers/.
4. Review the metadata and confirm `advanced-ua-forge` is available to your account.
5. From GitHub, create and **publish a Release** with tag `v4.5.0`. GitHub Actions runs tests, builds both artifacts and publishes through PyPI's OIDC trust.
6. Monitor the GitHub Actions output for actual success before telling users to install it.

An unconfigured trusted publisher **cannot** upload. Do not hard-code a PyPI token in the workflow.

## 5. Manual production upload

For manual upload from a Python-capable computer/server:

```bash
python -m twine upload dist/*
```

After PyPI confirms a successful upload, users can run:

```bash
python -m pip install advanced-ua-forge
python -c "from ua_forge import UserAgent; print(UserAgent().random)"
ua-forge --browser chrome --platform windows
```

**Note:** PyPI does not allow overwriting a released version. If a name or version is taken, update `pyproject.toml` and `ua_forge/__init__.py`, then rebuild. Do not attempt to upload the artifacts before reviewing them.

## iPhone/iPad caution

The base package uses Python, but running `pip` and all Python modules on stock iOS depends on the Python app and its restrictions. Native dependencies, Playwright binaries and privileged packet capture should not be advertised as working directly on iOS.
