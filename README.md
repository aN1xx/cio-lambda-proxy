# Customer.io Lambda Proxy

> Serverless proxy for [Customer.io](https://customer.io/) API on AWS Lambda + Terraform. Routes mobile app requests to Customer.io Track and App APIs. HTTP Signature auth, credential injection via HashiCorp Vault, anonymous user support. 85%+ test coverage.

Серверный прокси для перенаправления запросов мобильного приложения к Customer.io API через AWS Lambda.

## Architecture

```
[Mobile App]
    | (JWT / HTTP Signature)
[API Gateway / Lambda URL] -> signature verification, header injection
    |
[CIO Lambda Proxy] -> credential injection, request transformation
    |
[Customer.io Track/App API]
```

## Key Features

- **Dual API Support**: Routes to both Customer.io Track API (Basic Auth) and App API (Bearer Token) based on the request path
- **HTTP Signature Verification**: Validates RSA-signed requests from an upstream API gateway
- **Anonymous & Authenticated Flows**: Authorized users identified by email; anonymous users get hashed identifiers
- **Push Notification Tracking**: Transforms mobile-friendly endpoints into Customer.io push/events format
- **Device Registration**: Handles device token registration with automatic path transformation
- **Vault Integration**: Loads secrets from HashiCorp Vault at cold start via Lambda extension
- **No Secrets in Transit**: Customer.io API keys never leave the Lambda environment

## Tech Stack

- **Runtime**: Python 3.9+ on AWS Lambda
- **Infrastructure**: Terraform (API Gateway, Lambda, IAM, VPC, CloudWatch)
- **Auth**: RSA HTTP Signatures (draft-cavage-http-signatures), AWS IAM for Lambda URL
- **Crypto**: pycryptodome (GLIBC-compatible, no cffi dependency)
- **Secrets**: HashiCorp Vault Lambda Extension
- **CI/CD**: GitLab CI (lint, test, security scan, build, deploy)

## Supported Customer.io APIs

### Track API (track.customer.io) - Basic Auth
- **Auth**: Basic Auth (`site_id:api_key`)
- **Env vars**: `CIO_SITE_ID` + `CIO_API_KEY`
- **Endpoints**:
  - `POST /customers/{identifier}/events` - user events
  - `PUT /customers/{identifier}/attributes` - user attributes
  - `PUT /customers/{identifier}/devices` - device data
  - `POST /events` - anonymous events
  - `POST /push/events` - push notification metrics (delivered/opened)

### App API (api.customer.io) - Bearer Token
- **Auth**: Bearer Token
- **Env var**: `CIO_APP_API_KEY`
- **Endpoints**: email/push campaigns, message sending, activities

## Environment Variables

```bash
# Required for Track API
CIO_API_KEY=your_track_api_key_here
CIO_SITE_ID=your_site_id_here

# Required for App API (separate key!)
CIO_APP_API_KEY=your_app_api_key_here

# Required for JWT/signature verification
API_GATEWAY_PUBLIC_KEY=your_rsa_public_key_here

# Optional (defaults to global endpoints)
CIO_TRACK_API_BASE_URL=https://track.customer.io/api/v1/
CIO_APP_API_BASE_URL=https://api.customer.io/v1/
```

> **Note**: Customer.io uses **different API keys** for Track API and App API. They are created separately in the Customer.io dashboard.

### Regional Configuration

| Region | Track API URL | App API URL |
|--------|--------------|-------------|
| Global (default) | `https://track.customer.io/api/v1/` | `https://api.customer.io/v1/` |
| EU | `https://track-eu.customer.io/api/v1/` | `https://api-eu.customer.io/v1/` |

## Local Development

```bash
# Install dependencies
make install

# Copy environment variables
cp environment.example .env
# Edit .env with your keys

# Run tests
make test

# Lint
make lint

# Coverage report
make coverage
```

## Build & Deploy

```bash
# Build Lambda package (local)
./build.sh

# Build in Docker (Amazon Linux 2 compatible)
./build-in-docker.sh

# Terraform deployment
cd infra
terraform init
terraform workspace select dev
terraform plan
terraform apply
```

## Mobile App Endpoints

### Device Registration
```bash
POST /api/v1/cio/device
Content-Type: application/json
Authorization: Bearer <jwt_token>  # optional

{
  "device": {
    "id": "<FCM Token>",
    "platform": "ios|android",
    "attributes": {
      "device_os": "iOS 15.0",
      "device_model": "iPhone 13",
      "app_version": "1.0.0",
      "push_enabled": "true"
    }
  }
}
```

### Notification Received
```bash
POST /api/v1/cio/notification_received
Content-Type: application/json

{
  "notification_id": "<CIO-Delivery-ID>"
}
```

### Notification Opened
```bash
POST /api/v1/notification_opened
Content-Type: application/json

{
  "notification_id": "<CIO-Delivery-ID>",
  "fcm_token": "<FCM Token>"
}
```

## API Examples

### User Events (Track API)
```bash
POST /customers/user123/events
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "name": "item_purchased",
  "data": {
    "item_id": "12345",
    "price": 29.99
  }
}
```

### User Attributes (Track API)
```bash
PUT /customers/user123/attributes
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "email": "user@example.com",
  "first_name": "John",
  "plan": "premium"
}
```

## Testing

```bash
# Full test suite (78 tests)
pytest tests/

# Specific test
pytest tests/test_handler.py::TestLambdaHandler::test_track_api_authorized_request

# With coverage (85%+)
pytest --cov=cio_lambda_proxy tests/
```

## Security

- **HTTP Signature Verification**: All requests verified using RSA public key signatures
- **Credential Isolation**: Customer.io API keys injected server-side, never exposed to clients
- **Vault Integration**: Secrets loaded from HashiCorp Vault at Lambda cold start; secrets file deleted after reading
- **Anonymous Hashing**: Anonymous user identifiers are SHA-256 hashed to prevent tracking

## Architecture Decisions

### Why a separate Lambda function?
- **Security**: Customer.io keys isolated from the API Gateway
- **Scalability**: Independent scaling of the proxy layer
- **Monitoring**: Dedicated CloudWatch metrics for Customer.io integration

### Why Basic Auth for Track API?
Customer.io Track API requires Basic Auth with `site_id:api_key` combination for workspace identification and authorization.

### Why pycryptodome instead of cryptography?
The `cryptography` package requires GLIBC 2.28+ which causes compatibility issues in AWS Lambda Python 3.9 runtime. `pycryptodome` is self-contained and does not require `cffi` or other C extensions.

## Dependencies

### Core
- **Python 3.9+**: AWS Lambda runtime
- **boto3**: AWS SDK for Python
- **requests**: HTTP client for Customer.io API calls
- **pycryptodome**: Cryptographic primitives (RSA signature verification)
- **python-dotenv**: Environment variable management

### Development
- **pytest** + pytest-cov + pytest-mock: Testing
- **black** + isort: Code formatting
- **flake8** + mypy: Linting and type checking
- **bandit** + pip-audit: Security scanning

## License

MIT License. See [LICENSE](LICENSE) for details.
