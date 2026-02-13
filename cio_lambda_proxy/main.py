"""
Lambda entry point with Vault secret loading
"""

import json
import logging
import os
import tempfile
from typing import Any, Dict

from cio_lambda_proxy.handler import lambda_handler as _lambda_handler

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _load_vault_secrets() -> bool:
    """Load secrets from Vault extension file and set as environment variables"""
    # Use environment variable or secure temp directory
    vault_secret_file = os.environ.get("VAULT_SECRET_FILE")
    if not vault_secret_file:
        vault_secret_file = os.path.join(tempfile.gettempdir(), "vault_secrets")

    logger.info(f"Attempting to load Vault secrets from: {vault_secret_file}")

    if not os.path.exists(vault_secret_file):
        logger.warning(f"Vault secrets file not found: {vault_secret_file}")

        # Try alternative secure paths
        temp_dir = tempfile.gettempdir()
        alternative_files = ["vault_response", "secrets"]
        alternative_paths = [os.path.join(temp_dir, f) for f in alternative_files]
        alternative_paths.append("/opt/vault_secrets")  # Lambda layer path

        for alt_path in alternative_paths:
            if os.path.exists(alt_path):
                logger.info(f"Found alternative secrets file: {alt_path}")
                vault_secret_file = alt_path
                break
        else:
            logger.error("No Vault secrets file found in any expected location")
            return False

    success = False
    try:
        with open(vault_secret_file, "r") as f:
            secrets_content = f.read()
            logger.info(f"Vault secrets file content length: {len(secrets_content)}")

            logger.info(
                "Vault secrets file loaded successfully (content masked for security)"
            )
            try:
                secrets_data = json.loads(secrets_content)
                logger.info(
                    f"Successfully parsed secrets JSON, keys: {list(secrets_data.keys())}"
                )

                for key, value in secrets_data.items():
                    if isinstance(value, (str, int, float, bool)):
                        os.environ[str(key)] = str(value)
                        masked_value = (
                            str(value)[:3] + "***" if len(str(value)) > 3 else "***"
                        )
                        logger.info(f"Set environment variable: {key} = {masked_value}")
                    elif isinstance(value, dict):
                        # Handle nested JSON (common with Vault KV v2)
                        if "data" in value and isinstance(value["data"], dict):
                            for nested_key, nested_value in value["data"].items():
                                os.environ[str(nested_key)] = str(nested_value)
                                masked_nested_value = (
                                    str(nested_value)[:3] + "***"
                                    if len(str(nested_value)) > 3
                                    else "***"
                                )
                                logger.info(
                                    f"Set nested environment variable: {nested_key} = {masked_nested_value}"
                                )

                success = True

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse secrets file as JSON: {e}")
                lines = secrets_content.strip().split("\n")
                for line in lines:
                    if "=" in line:
                        key, value = line.split("=", 1)
                        os.environ[key.strip()] = value.strip()
                        masked_value = (
                            value.strip()[:3] + "***"
                            if len(value.strip()) > 3
                            else "***"
                        )
                        logger.info(
                            f"Set environment variable from key=value: {key.strip()} = {masked_value}"
                        )
                success = True

    except Exception as e:
        logger.error(f"Error reading Vault secrets file: {e}")
        return False
    finally:
        # Always try to remove the secrets file for security
        if os.path.exists(vault_secret_file):
            try:
                os.remove(vault_secret_file)
                logger.info(f"Removed secrets file {vault_secret_file} for security")
            except Exception as cleanup_error:
                logger.warning(f"Could not remove secrets file: {cleanup_error}")

    return success


# Load secrets during initialization
_load_vault_secrets()


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main Lambda handler with Vault secret loading"""
    return _lambda_handler(event, context)
