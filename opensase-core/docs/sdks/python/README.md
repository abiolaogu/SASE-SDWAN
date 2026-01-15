# OpenSASE Python SDK

Official Python SDK for the OpenSASE Platform API.

[![PyPI version](https://badge.fury.io/py/opensase.svg)](https://pypi.org/project/opensase/)
[![Python Versions](https://img.shields.io/pypi/pyversions/opensase.svg)](https://pypi.org/project/opensase/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
pip install opensase
```

## Quick Start

```python
from opensase import OpenSASE

client = OpenSASE(api_key='os_live_abc123...')

# Create a user
user = client.identity.users.create(email='john@example.com')

# List contacts
contacts = client.crm.contacts.list(search='acme', per_page=20)

# Create a payment
payment = client.payments.intents.create(amount=9999, currency='usd')
```

## Async Support

```python
from opensase import AsyncOpenSASE

async with AsyncOpenSASE(api_key='os_live_abc123...') as client:
    user = await client.identity.users.create(email='john@example.com')
```

## Configuration

```python
from opensase import OpenSASE

client = OpenSASE(
    # Required: Your API key
    api_key='os_live_abc123...',
    
    # Optional: Custom base URL (default: https://api.opensase.billyronks.io/v1)
    base_url='https://api.staging.opensase.billyronks.io/v1',
    
    # Optional: Request timeout in seconds (default: 30.0)
    timeout=60.0,
    
    # Optional: Maximum retry attempts (default: 3)
    max_retries=5,
    
    # Optional: Base delay between retries in seconds (default: 1.0)
    retry_delay=2.0,
    
    # Optional: Additional headers
    headers={'X-Custom-Header': 'value'},
)
```

## Services

### Identity

```python
# Users
user = client.identity.users.create(email='john@example.com')
user = client.identity.users.get('user_abc123')
user = client.identity.users.update('user_abc123', profile={'first_name': 'Jane'})
client.identity.users.delete('user_abc123')

# List with pagination
users = client.identity.users.list(page=1, per_page=20)

# Auto-paginate through all users
for user in client.identity.users.list_all():
    print(user['email'])

# Authentication
result = client.identity.auth.login(
    email='john@example.com',
    password='password123'
)

# MFA verification
if result.get('mfa_required'):
    tokens = client.identity.auth.verify_mfa(
        mfa_token=result['mfa_token'],
        method='totp',
        code='123456'
    )

# Groups
group = client.identity.groups.create(name='Engineering')
client.identity.groups.add_members('group_abc123', ['user_1', 'user_2'])
```

### CRM

```python
# Contacts
contact = client.crm.contacts.create(
    first_name='Jane',
    last_name='Smith',
    email='jane@example.com',
    company_name='Acme Corp'
)

contacts = client.crm.contacts.list(
    search='acme',
    status='qualified',
    sort='lead_score',
    order='desc'
)

# Get 360° view
view = client.crm.contacts.get_360_view('contact_abc123')

# Deals
deal = client.crm.deals.create(
    name='Enterprise License',
    amount=50000,
    pipeline_id='pipeline_sales',
    stage_id='stage_discovery'
)

client.crm.deals.move_to_stage('deal_xyz789', 'stage_negotiation', note='Sent proposal')

# Pipeline view
pipeline = client.crm.pipelines.get_view('pipeline_sales', period='this_quarter')
```

### Payments

```python
# Create payment intent
payment_intent = client.payments.intents.create(
    amount=9999,  # $99.99 in cents
    currency='usd',
    customer_id='cust_abc123'
)

# Confirm with payment method
confirmed = client.payments.intents.confirm(
    payment_intent['id'],
    payment_method_id='pm_card_xyz'
)

# Handle 3DS
if confirmed['status'] == 'requires_action':
    redirect_url = confirmed['next_action']['redirect_to_url']['url']
    # Redirect user to redirect_url

# Capture manual payment
client.payments.intents.capture(payment_intent['id'])

# Subscriptions
subscription = client.payments.subscriptions.create(
    customer_id='cust_abc123',
    plan_id='plan_premium',
    payment_method_id='pm_card_xyz',
    trial_period_days=14
)

# Cancel subscription
client.payments.subscriptions.cancel(
    subscription['id'],
    cancel_at_period_end=True
)

# Refunds
refund = client.payments.refunds.create(
    payment_intent_id='pi_abc123',
    amount=5000,  # Partial refund
    reason='requested_by_customer'
)
```

## Idempotency

For POST requests that modify state, use idempotency keys:

```python
payment = client.payments.intents.create(
    amount=9999,
    currency='usd',
    idempotency_key='order_12345_payment_1'
)
```

## Error Handling

```python
from opensase import (
    OpenSASE,
    OpenSASEError,
    ValidationError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
)

try:
    contact = client.crm.contacts.get('invalid_id')
except ValidationError as e:
    print(f'Validation failed: {e.details}')
except AuthenticationError as e:
    print('Invalid API key')
except NotFoundError as e:
    print('Contact not found')
except RateLimitError as e:
    print(f'Rate limited. Retry after {e.retry_after} seconds')
except OpenSASEError as e:
    print(f'API Error: {e.code} - {e.message}')
    print(f'Request ID: {e.request_id}')
```

## Webhooks

```python
from opensase import verify_webhook_signature, construct_webhook_event
from flask import Flask, request

app = Flask(__name__)

@app.route('/webhooks', methods=['POST'])
def webhook_handler():
    payload = request.get_data()
    signature = request.headers.get('X-OpenSASE-Signature')
    timestamp = request.headers.get('X-OpenSASE-Timestamp')
    
    try:
        event = construct_webhook_event(
            payload,
            signature,
            timestamp,
            'whsec_your_webhook_secret'
        )
        
        if event['type'] == 'payment_intent.succeeded':
            # Handle successful payment
            pass
        elif event['type'] == 'customer.subscription.created':
            # Handle new subscription
            pass
        
        return {'received': True}, 200
        
    except ValueError as e:
        return {'error': str(e)}, 400
```

## Type Hints

The SDK is fully typed for better IDE support:

```python
from opensase import OpenSASE
from typing import Dict, Any

client = OpenSASE(api_key='os_live_abc123...')

# Return types are properly annotated
user: Dict[str, Any] = client.identity.users.create(email='john@example.com')
```

## Django Integration

```python
# settings.py
OPENSASE_API_KEY = 'os_live_abc123...'

# views.py
from django.conf import settings
from opensase import OpenSASE

client = OpenSASE(api_key=settings.OPENSASE_API_KEY)

def create_contact(request):
    contact = client.crm.contacts.create(
        email=request.POST['email'],
        first_name=request.POST['first_name']
    )
    return JsonResponse(contact)
```

## FastAPI Integration

```python
from fastapi import FastAPI, Depends
from opensase import OpenSASE, AsyncOpenSASE

app = FastAPI()

def get_client():
    return OpenSASE(api_key='os_live_abc123...')

@app.post('/contacts')
async def create_contact(email: str, client: OpenSASE = Depends(get_client)):
    return client.crm.contacts.create(email=email)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.opensase.billyronks.io
- API Reference: https://docs.opensase.billyronks.io/api
- Issues: https://github.com/billyronks/opensase-python-sdk/issues
