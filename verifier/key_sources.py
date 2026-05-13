"""
key_sources.py: Pluggable HMAC key retrieval sources for the verifier.

Six key sources are supported. Each is implemented as a class with a
get_key() method returning bytes. SDK imports are lazy: the cloud
client libraries are imported only when their corresponding source is
actually used, so users who only need (for example) GCP Secret Manager
do not need to install boto3 or hvac.

Sources priority for the CLI is one-of: the user picks exactly one
source per invocation. There is no automatic fallback between sources
in the verifier (unlike mcp_tap.py's writer, which falls back through
env -> file -> generate). The verifier is a read-only forensic tool;
ambiguity about which key was used would weaken the evidence.

All sources expect keys stored as hex-encoded text (consistent with
the mcp_tap.py writer convention). Raw-bytes payloads are also
accepted as a fallback for cloud secret backends that prefer binary.
Keys must be at least 16 bytes after decoding.
"""

from abc import ABC, abstractmethod


MIN_KEY_BYTES = 16


class KeySourceError(RuntimeError):
    """Raised when a key source cannot fetch or validate the key."""


def _decode_key(payload: bytes | str, where: str) -> bytes:
    """Decode a key payload as hex text, falling back to raw bytes.

    `where` is included in error messages to help the user fix the source.
    """
    if isinstance(payload, str):
        text = payload.strip()
        try:
            key = bytes.fromhex(text)
        except ValueError:
            # Not hex; treat the raw text bytes as the key
            key = text.encode("utf-8")
    else:
        # Raw bytes payload; try hex-decoding text form first
        try:
            text = payload.decode("utf-8").strip()
            key = bytes.fromhex(text)
        except (UnicodeDecodeError, ValueError):
            key = payload
    if len(key) < MIN_KEY_BYTES:
        raise KeySourceError(
            f"key from {where} is {len(key)} bytes "
            f"(need >= {MIN_KEY_BYTES})"
        )
    return key


class KeySource(ABC):
    """Abstract interface for a key retrieval source."""

    @abstractmethod
    def get_key(self) -> bytes:
        """Fetch and return the HMAC key as bytes. Raises KeySourceError on failure."""

    @abstractmethod
    def describe(self) -> str:
        """Human-readable label for reports (must not include the key itself)."""


class EnvVarKeySource(KeySource):
    """Read the key from an environment variable (hex-encoded)."""

    def __init__(self, var_name: str = "MCP_TAP_HMAC_KEY"):
        self.var_name = var_name

    def get_key(self) -> bytes:
        import os
        value = os.environ.get(self.var_name)
        if not value:
            raise KeySourceError(
                f"environment variable {self.var_name} is not set"
            )
        return _decode_key(value, f"env:{self.var_name}")

    def describe(self) -> str:
        return f"env-var:{self.var_name}"


class FileKeySource(KeySource):
    """Read the key from a local file (hex-encoded)."""

    def __init__(self, path: str):
        self.path = path

    def get_key(self) -> bytes:
        from pathlib import Path
        p = Path(self.path)
        if not p.exists():
            raise KeySourceError(f"key file does not exist: {p}")
        try:
            content = p.read_text()
        except OSError as e:
            raise KeySourceError(f"cannot read key file {p}: {e}") from e
        return _decode_key(content, f"file:{p}")

    def describe(self) -> str:
        return f"file:{self.path}"


class GCPSecretManagerKeySource(KeySource):
    """Read the key from GCP Secret Manager (ADC for auth)."""

    def __init__(
        self,
        secret_name: str,
        project: str | None = None,
        version: str = "latest",
    ):
        self.secret_name = secret_name
        self.project = project
        self.version = version

    def get_key(self) -> bytes:
        try:
            from google.cloud import secretmanager
            import google.auth
        except ImportError as e:
            raise KeySourceError(
                "google-cloud-secret-manager is required for this key source. "
                "Install with: pip install google-cloud-secret-manager"
            ) from e

        # Resolve project from ADC if not explicitly provided
        project = self.project
        if not project:
            try:
                _, project = google.auth.default()
            except Exception as e:
                raise KeySourceError(
                    f"could not determine GCP project from ADC: {e}. "
                    "Pass project explicitly."
                ) from e
            if not project:
                raise KeySourceError(
                    "GCP project not set in ADC; pass project explicitly"
                )

        # Accept either a bare name or a full resource name
        if self.secret_name.startswith("projects/"):
            name = f"{self.secret_name}/versions/{self.version}"
        else:
            name = (
                f"projects/{project}/secrets/{self.secret_name}"
                f"/versions/{self.version}"
            )

        try:
            client = secretmanager.SecretManagerServiceClient()
            response = client.access_secret_version(request={"name": name})
        except Exception as e:
            raise KeySourceError(
                f"GCP Secret Manager fetch failed for {name}: {e}"
            ) from e

        return _decode_key(response.payload.data, f"gcp:{self.secret_name}")

    def describe(self) -> str:
        return f"gcp-secret-manager:{self.secret_name}@{self.version}"


class AWSSecretsManagerKeySource(KeySource):
    """Read the key from AWS Secrets Manager (boto3 default credential chain)."""

    def __init__(self, secret_id: str, region: str | None = None):
        self.secret_id = secret_id
        self.region = region

    def get_key(self) -> bytes:
        try:
            import boto3
        except ImportError as e:
            raise KeySourceError(
                "boto3 is required for this key source. "
                "Install with: pip install boto3"
            ) from e

        try:
            client = boto3.client("secretsmanager", region_name=self.region)
            response = client.get_secret_value(SecretId=self.secret_id)
        except Exception as e:
            raise KeySourceError(
                f"AWS Secrets Manager fetch failed for {self.secret_id}: {e}"
            ) from e

        if "SecretString" in response:
            payload = response["SecretString"]
        elif "SecretBinary" in response:
            payload = response["SecretBinary"]
        else:
            raise KeySourceError(
                f"AWS secret {self.secret_id} returned no value"
            )

        return _decode_key(payload, f"aws:{self.secret_id}")

    def describe(self) -> str:
        region = f"@{self.region}" if self.region else ""
        return f"aws-secrets-manager:{self.secret_id}{region}"


class AzureKeyVaultKeySource(KeySource):
    """Read the key from Azure Key Vault (DefaultAzureCredential for auth)."""

    def __init__(
        self,
        vault_url: str,
        secret_name: str,
        version: str | None = None,
    ):
        self.vault_url = vault_url
        self.secret_name = secret_name
        self.version = version

    def get_key(self) -> bytes:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as e:
            raise KeySourceError(
                "azure-identity and azure-keyvault-secrets are required for "
                "this key source. Install with: "
                "pip install azure-identity azure-keyvault-secrets"
            ) from e

        try:
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=self.vault_url, credential=credential)
            secret = client.get_secret(self.secret_name, version=self.version)
        except Exception as e:
            raise KeySourceError(
                f"Azure Key Vault fetch failed for "
                f"{self.vault_url}/{self.secret_name}: {e}"
            ) from e

        return _decode_key(secret.value, f"azure:{self.secret_name}")

    def describe(self) -> str:
        ver = f"@{self.version}" if self.version else ""
        return f"azure-key-vault:{self.vault_url}/{self.secret_name}{ver}"


class HashiCorpVaultKeySource(KeySource):
    """Read the key from HashiCorp Vault (VAULT_TOKEN env or other auth)."""

    def __init__(
        self,
        vault_addr: str,
        secret_path: str,
        field: str = "key",
        mount_point: str = "secret",
    ):
        self.vault_addr = vault_addr
        self.secret_path = secret_path
        self.field = field
        self.mount_point = mount_point

    def get_key(self) -> bytes:
        try:
            import hvac
        except ImportError as e:
            raise KeySourceError(
                "hvac is required for this key source. "
                "Install with: pip install hvac"
            ) from e

        client = hvac.Client(url=self.vault_addr)
        if not client.is_authenticated():
            raise KeySourceError(
                "HashiCorp Vault authentication failed. Set VAULT_TOKEN "
                "environment variable or configure another auth method "
                "before invoking the verifier."
            )

        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=self.secret_path,
                mount_point=self.mount_point,
            )
        except Exception as e:
            raise KeySourceError(
                f"HashiCorp Vault read failed for "
                f"{self.mount_point}/{self.secret_path}: {e}"
            ) from e

        try:
            value = response["data"]["data"][self.field]
        except (KeyError, TypeError) as e:
            raise KeySourceError(
                f"HashiCorp Vault response missing field {self.field!r} "
                f"at {self.mount_point}/{self.secret_path}"
            ) from e

        return _decode_key(value, f"vault:{self.secret_path}#{self.field}")

    def describe(self) -> str:
        return (
            f"hashicorp-vault:{self.vault_addr}/"
            f"{self.mount_point}/{self.secret_path}#{self.field}"
        )
