# OpenSASE TypeScript SDK

Official TypeScript/JavaScript SDK for the OpenSASE Platform API.

[![npm version](https://badge.fury.io/js/@opensase%2Fsdk.svg)](https://www.npmjs.com/package/@opensase/sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @opensase/sdk
# or
yarn add @opensase/sdk
# or
pnpm add @opensase/sdk
```

## Quick Start

```typescript
import { OpenSASE } from '@opensase/sdk';

const client = new OpenSASE({
  apiKey: 'os_live_abc123...',
});

// Create a user
const user = await client.identity.users.create({
  email: 'john@example.com',
  profile: {
    firstName: 'John',
    lastName: 'Doe',
  },
});

// List contacts
const contacts = await client.crm.contacts.list({
  search: 'acme',
  limit: 20,
});

// Create a payment
const payment = await client.payments.intents.create({
  amount: 9999,
  currency: 'usd',
});
```

## Configuration

```typescript
import { OpenSASE } from '@opensase/sdk';

const client = new OpenSASE({
  // Required: Your API key
  apiKey: 'os_live_abc123...',
  
  // Optional: Custom base URL (default: https://api.opensase.billyronks.io/v1)
  baseUrl: 'https://api.staging.opensase.billyronks.io/v1',
  
  // Optional: Request timeout in milliseconds (default: 30000)
  timeout: 60000,
  
  // Optional: Maximum retry attempts (default: 3)
  maxRetries: 5,
  
  // Optional: Base delay between retries in milliseconds (default: 1000)
  retryDelay: 2000,
  
  // Optional: Additional headers
  headers: {
    'X-Custom-Header': 'value',
  },
});
```

## Services

### Identity

```typescript
// Users
const user = await client.identity.users.create({ email: 'john@example.com' });
const user = await client.identity.users.get('user_abc123');
const user = await client.identity.users.update('user_abc123', { profile: { firstName: 'Jane' } });
await client.identity.users.delete('user_abc123');

// List with pagination
const users = await client.identity.users.list({ page: 1, perPage: 20 });

// Auto-paginate through all users
for await (const user of client.identity.users.listAutoPaginate()) {
  console.log(user.email);
}

// Authentication
const result = await client.identity.auth.login({
  email: 'john@example.com',
  password: 'password123',
});

// MFA verification
if ('mfaRequired' in result) {
  const tokens = await client.identity.auth.verifyMFA({
    mfaToken: result.mfaToken,
    method: 'totp',
    code: '123456',
  });
}

// Groups
const group = await client.identity.groups.create({ name: 'Engineering' });
await client.identity.groups.addMembers('group_abc123', ['user_1', 'user_2']);
```

### CRM

```typescript
// Contacts
const contact = await client.crm.contacts.create({
  firstName: 'Jane',
  lastName: 'Smith',
  email: 'jane@example.com',
  companyName: 'Acme Corp',
});

const contacts = await client.crm.contacts.list({
  search: 'acme',
  status: 'qualified',
  sort: 'lead_score',
  order: 'desc',
});

// Get 360° view
const view = await client.crm.contacts.get360View('contact_abc123');

// Deals
const deal = await client.crm.deals.create({
  name: 'Enterprise License',
  amount: 50000,
  pipelineId: 'pipeline_sales',
  stageId: 'stage_discovery',
});

await client.crm.deals.moveToStage('deal_xyz789', 'stage_negotiation', 'Sent proposal');

// Pipeline view
const pipeline = await client.crm.pipelines.getView('pipeline_sales', {
  period: 'this_quarter',
});
```

### Payments

```typescript
// Create payment intent
const paymentIntent = await client.payments.intents.create({
  amount: 9999, // $99.99 in cents
  currency: 'usd',
  customerId: 'cust_abc123',
});

// Confirm with payment method
const confirmed = await client.payments.intents.confirm(paymentIntent.id, {
  paymentMethodId: 'pm_card_xyz',
});

// Handle 3DS
if (confirmed.status === 'requires_action' && confirmed.nextAction?.redirectToUrl) {
  // Redirect user to confirmed.nextAction.redirectToUrl.url
}

// Capture manual payment
await client.payments.intents.capture(paymentIntent.id);

// Subscriptions
const subscription = await client.payments.subscriptions.create({
  customerId: 'cust_abc123',
  planId: 'plan_premium',
  paymentMethodId: 'pm_card_xyz',
  trialPeriodDays: 14,
});

// Cancel subscription
await client.payments.subscriptions.cancel(subscription.id, {
  cancelAtPeriodEnd: true,
});

// Refunds
const refund = await client.payments.refunds.create({
  paymentIntentId: 'pi_abc123',
  amount: 5000, // Partial refund
  reason: 'requested_by_customer',
});
```

## Idempotency

For POST requests that modify state, use idempotency keys:

```typescript
const payment = await client.payments.intents.create(
  {
    amount: 9999,
    currency: 'usd',
  },
  {
    idempotencyKey: 'order_12345_payment_1',
  }
);
```

## Error Handling

```typescript
import { 
  OpenSASE,
  ValidationError,
  AuthenticationError,
  NotFoundError,
  RateLimitError,
} from '@opensase/sdk';

try {
  const contact = await client.crm.contacts.get('invalid_id');
} catch (error) {
  if (error instanceof ValidationError) {
    console.log('Validation failed:', error.details);
  } else if (error instanceof AuthenticationError) {
    console.log('Invalid API key');
  } else if (error instanceof NotFoundError) {
    console.log('Contact not found');
  } else if (error instanceof RateLimitError) {
    console.log(`Rate limited. Retry after ${error.retryAfter} seconds`);
  } else if (error instanceof OpenSASE.OpenSASEError) {
    console.log(`API Error: ${error.code} - ${error.message}`);
    console.log(`Request ID: ${error.requestId}`);
  }
}
```

## Webhooks

```typescript
import { verifyWebhookSignature, constructWebhookEvent } from '@opensase/sdk';
import express from 'express';

const app = express();

app.post('/webhooks', express.raw({ type: 'application/json' }), async (req, res) => {
  const signature = req.headers['x-opensase-signature'] as string;
  const timestamp = req.headers['x-opensase-timestamp'] as string;
  
  try {
    const isValid = await verifyWebhookSignature(
      req.body,
      signature,
      timestamp,
      process.env.WEBHOOK_SECRET!
    );
    
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
    
    const event = JSON.parse(req.body.toString());
    
    switch (event.type) {
      case 'payment_intent.succeeded':
        // Handle successful payment
        break;
      case 'customer.subscription.created':
        // Handle new subscription
        break;
    }
    
    res.json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(400).json({ error: 'Webhook processing failed' });
  }
});
```

## TypeScript Support

This SDK is written in TypeScript and provides full type definitions:

```typescript
import type {
  User,
  Contact,
  Deal,
  PaymentIntent,
  Subscription,
  CreateUserParams,
  CreateContactParams,
  CreatePaymentIntentParams,
} from '@opensase/sdk';

// All parameters and return types are fully typed
const createContact = async (params: CreateContactParams): Promise<Contact> => {
  return client.crm.contacts.create(params);
};
```

## Browser Support

The SDK works in modern browsers that support `fetch`:

```html
<script type="module">
  import { OpenSASE } from 'https://esm.sh/@opensase/sdk';
  
  const client = new OpenSASE({
    apiKey: 'os_live_abc123...',
  });
  
  // Use the client
</script>
```

> **Warning**: Never expose your API key in client-side code in production. Use a backend proxy or restricted API keys with appropriate scopes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.opensase.billyronks.io
- API Reference: https://docs.opensase.billyronks.io/api
- Issues: https://github.com/billyronks/opensase-typescript-sdk/issues
