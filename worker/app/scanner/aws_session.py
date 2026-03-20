"""
AWS session management for the infrastructure scanner.

Handles:
- Named profile selection (read-only scan profile)
- Region configuration
- Automatic retry with exponential backoff
- Rate limiting to avoid CloudTrail anomaly alerts
"""
import time
from typing import Any

import boto3
import structlog
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

log = structlog.get_logger()

# Conservative retry config — avoids triggering AWS rate limit alarms
BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
    max_pool_connections=10,
)


class AWSSessionError(Exception):
    """Raised when AWS session cannot be established."""
    pass


class AWSSession:
    """
    Thin wrapper around boto3 that enforces:
    - Named profile usage (never default unless explicitly set)
    - Read-only operations only (enforced by IAM policy on the profile)
    - Consistent retry and rate-limit behaviour
    """

    def __init__(self, profile: str, region: str):
        self.profile = profile
        self.region = region
        self._session: boto3.Session | None = None
        self._clients: dict[str, Any] = {}

    def _get_session(self) -> boto3.Session:
        if self._session is None:
            try:
                self._session = boto3.Session(
                    profile_name=self.profile,
                    region_name=self.region,
                )
                log.info(
                    "aws.session_created",
                    profile=self.profile,
                    region=self.region,
                )
            except ProfileNotFound:
                raise AWSSessionError(
                    f"AWS profile '{self.profile}' not found. "
                    f"Check ~/.aws/credentials or ~/.aws/config."
                )
        return self._session

    def client(self, service: str) -> Any:
        """Return a cached boto3 client for the given service."""
        if service not in self._clients:
            session = self._get_session()
            self._clients[service] = session.client(
                service,
                region_name=self.region,
                config=BOTO_CONFIG,
            )
        return self._clients[service]

    def get_account_id(self) -> str:
        """Fetch the AWS account ID for the current credentials."""
        try:
            sts = self.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity["Account"]
            log.info("aws.identity_confirmed", account_id=account_id)
            return account_id
        except NoCredentialsError:
            raise AWSSessionError(
                "No AWS credentials found. "
                "Ensure ~/.aws/credentials is configured for this profile."
            )
        except ClientError as e:
            raise AWSSessionError(f"Failed to verify AWS identity: {e}")

    @staticmethod
    def safe_call(fn, *args, delay: float = 0.1, **kwargs) -> Any:
        """
        Call a boto3 API function with a small delay to avoid rate limiting.
        Returns the result or raises on non-throttle errors.
        """
        time.sleep(delay)
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("Throttling", "RequestLimitExceeded", "TooManyRequestsException"):
                log.warning("aws.throttled", fn=fn.__name__, retrying=True)
                time.sleep(2.0)
                return fn(*args, **kwargs)
            raise
