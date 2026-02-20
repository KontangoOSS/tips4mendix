# SAML/SSO Payload Validation Guide

## What this is for

So you've got two domains that are both supposed to be producing the same SAML response, but something's off. Maybe one domain works fine and the other throws errors, maybe the attributes don't line up, maybe one just silently fails. This guide is how you figure out where the mismatch is.

We're also going to talk about what happens when there's a load balancer or reverse proxy in the mix (because there almost always is), and what changes when you're doing this in an ITAR or FedRAMP environment.

---

## What's actually in a SAML response

When someone logs in through SSO, the IdP sends a SAML Response back to your SP as an HTTP POST to the ACS endpoint. That response is just a base64-encoded XML document. Here's what's inside it and what each piece does:

| Section | What it does |
|---|---|
| `<saml:Issuer>` | Which IdP issued this response |
| `<samlp:Status>` | Did it succeed or fail |
| `<saml:Assertion>` | The actual claims — this is the meat of it |
| `<saml:Subject>` | The NameID, basically the user identifier |
| `<saml:Conditions>` | Time window (`NotBefore`, `NotOnOrAfter`) and who this is intended for |
| `<saml:AuthnStatement>` | How the user actually authenticated |
| `<saml:AttributeStatement>` | User attributes like email, roles, groups, whatever the IdP is sending over |
| `<ds:Signature>` | XML digital signature so you know nobody messed with it in transit |

---

## Capturing the payloads

First thing — you need to grab the raw SAML response from both domains. You've got a few options here:

**Postman** — Send a POST to the ACS endpoint and grab the `SAMLResponse` parameter from the body. If you're dealing with an SP-initiated flow, you'll need to follow the redirect chain from the SP login URL through the IdP and back. Open up Postman's console (View > Show Postman Console) and you can see every request in the chain.

**Browser DevTools** — Open the Network tab, walk through the login flow, find the POST to your ACS endpoint, and copy the `SAMLResponse` form parameter out of it.

**SAML Tracer** — There's a browser extension called "SAML-tracer" for Firefox and Chrome that will automatically decode and show you SAML payloads as you click through the login flow. Heads up though — these might not be approved on all corporate machines, so check before you install it.

Do this for both domains. You should have two base64-encoded strings when you're done.

---

## Decoding them

Now take both of those base64 blobs and turn them into something readable:

```bash
echo "<base64_payload_A>" | base64 -d | xmllint --format - > domain_a_saml.xml
echo "<base64_payload_B>" | base64 -d | xmllint --format - > domain_b_saml.xml
```

Sometimes the payload gets URL-encoded before the base64 encoding — you'll know because you see stuff like `%2B` and `%3D` instead of `+` and `=`. If that's the case, URL-decode it first:

```bash
python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.argv[1]))" "<url_encoded_value>"
```

You can also do this directly in Postman using `atob()` in the Tests or Pre-request Script tab if you'd rather stay in one tool.

---

## Diff them

Once you've got two readable XML files, throw a diff at them:

```bash
diff --color domain_a_saml.xml domain_b_saml.xml
```

Or side-by-side if that's easier for you to read:

```bash
diff -y --width=200 domain_a_saml.xml domain_b_saml.xml
```

This gets you the high-level view. Some of the differences you see will be expected (timestamps, request IDs, etc.) and some won't be. Now you go field-by-field and figure out which is which.

---

## Going through it field-by-field

### Issuer

```xml
<saml:Issuer>https://idp.example.com/saml/metadata</saml:Issuer>
```

This has to be the same in both payloads. If it's not, the two domains are talking to different IdPs or different IdP applications. That's your answer — stop here and go fix the IdP config.

### Destination

```xml
<samlp:Response Destination="https://app.domain-a.com/acs" ...>
```

This one is going to be different between domains, and that's fine. It's just the ACS URL the IdP was told to post back to. Just make sure it matches what you'd expect for each domain.

### Audience Restriction

```xml
<saml:AudienceRestriction>
  <saml:Audience>https://app.domain-a.com/saml/metadata</saml:Audience>
</saml:AudienceRestriction>
```

This trips people up all the time. If both domains are supposed to be the same SP, this value needs to match between both payloads. If the IdP was set up with two separate SP configs, these are going to be different, and the SP is going to reject whichever one doesn't match its own entity ID. We've seen this one a lot.

### NameID

```xml
<saml:Subject>
  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">
    user@example.com
  </saml:NameID>
</saml:Subject>
```

Two things to check — is the `Format` the same in both? (Common ones are `emailAddress`, `persistent`, `transient`, `unspecified`.) And for the same user logging in on both domains, is the actual value the same?

### Conditions

```xml
<saml:Conditions NotBefore="2026-02-06T10:00:00Z" NotOnOrAfter="2026-02-06T10:05:00Z">
```

The timestamps themselves will be different since these are per-request — don't worry about that. What you want to look at is the window size. If Domain A gives you a 5-minute window and Domain B gives you 30 minutes, those are different IdP policies and that's worth investigating.

### Attributes

```xml
<saml:AttributeStatement>
  <saml:Attribute Name="email">
    <saml:AttributeValue>user@example.com</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="role">
    <saml:AttributeValue>admin</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

This is the other big one where things tend to fall apart. Stuff to look for:

- Are the attribute names exactly the same? Watch for casing issues — `email` vs `Email` — or one domain using a short name while the other uses the full URI like `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`. That kind of mismatch is easy to miss and will absolutely break things on the SP side.
- Are both payloads sending the same set of attributes? If Domain A sends `email`, `role`, and `department` but Domain B only sends `email` and `role`, the SP might choke depending on what it expects.
- For the same user, are the actual values identical?

### Signature

```xml
<ds:Signature>
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  </ds:SignedInfo>
</ds:Signature>
```

First check — is the signing algorithm the same? (`rsa-sha256` vs `rsa-sha1`). Then pull out the certs and compare them:

```bash
grep -oP '(?<=<ds:X509Certificate>).*?(?=</ds:X509Certificate>)' domain_a_saml.xml | base64 -d | openssl x509 -inform DER -text -noout
grep -oP '(?<=<ds:X509Certificate>).*?(?=</ds:X509Certificate>)' domain_b_saml.xml | base64 -d | openssl x509 -inform DER -text -noout
```

Look at the Subject, Issuer, Serial Number, and fingerprint. If the certs don't match, the IdP is using different signing keys for each SP config, or you're actually dealing with two totally different IdPs.

### InResponseTo

```xml
<samlp:Response InResponseTo="_abc123" ...>
```

This is always going to be different per-request — it ties back to the original `AuthnRequest` ID, so that's expected. But here's the thing — if one payload has this field and the other one doesn't, that's telling you something. The one with `InResponseTo` is SP-initiated and the one without it is IdP-initiated. That's a real difference in how the flow works.

---

## Testing with Postman

You can use Postman to actually fire the SAML response at the ACS endpoint and see what happens:

1. Create a new POST request for each domain's ACS endpoint.
2. Set the body to `x-www-form-urlencoded` with the `SAMLResponse` parameter (throw in `RelayState` too if there is one).
3. Send it. A working SP is going to give you back a 302 redirect to the app or a 200 with a session cookie.
4. Compare what you get back from each domain. If one of them gives you a 4xx, read the error message — most SP implementations will straight up tell you what failed. Bad audience, expired assertion, bad signature, whatever it is.

For SP-initiated flows you can start from the login URL in Postman and follow the redirects to capture the whole chain. The Postman console shows you every hop.

---

## What happens when there's a load balancer or reverse proxy in the way

There almost always is one, and it can mess with SAML validation in a bunch of ways. Here's what we see the most:

### ACS URL mismatch

This is the number one thing. Your SP thinks it lives at `https://internal-host:8443/acs` but the IdP was configured with `https://public.example.com/acs`. The SP gets the SAML response, compares the `Destination` against what it thinks its own URL is, they don't match, validation fails.

**How to fix it** — Configure the SP to use the externally-visible URL as its entity ID and ACS URL. Make sure the proxy passes `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Port`, and that the SP actually trusts those headers.

### HTTP vs HTTPS scheme mismatch

The LB terminates TLS and forwards plain HTTP to the backend. So the SP sees itself as `http://` but the SAML response has `Destination=https://...`. Fails.

**How to fix it** — Make sure the proxy sends `X-Forwarded-Proto: https` and that the SP honors it.

### The proxy is messing with the POST body

Some WAFs or reverse proxies re-encode or modify POST bodies. They might re-encode `+` as `%2B` or strip parameters entirely. This corrupts the base64 payload and the signature validation blows up.

**How to fix it** — Tell the proxy to pass `application/x-www-form-urlencoded` bodies through unmodified for the ACS endpoint. Turn off body inspection/rewriting on that path.

### No sticky sessions

If the SP creates an `AuthnRequest` on Node A but then the SAML response POST lands on Node B (because the LB doesn't do session affinity), Node B has no idea what that original request ID was. `InResponseTo` validation fails.

**How to fix it** — Either turn on sticky sessions on the LB for the ACS path, or put a shared session store behind your SP nodes (Redis, a database, whatever works in your setup).

### Clock skew

If the LB introduces latency or the backend nodes have drifted clocks, the `NotBefore`/`NotOnOrAfter` window can fail even though the assertion is technically valid.

**How to fix it** — NTP on every node. Configure a clock skew tolerance on the SP — 30 to 120 seconds is usually fine.

### The payload is too big

Big SAML responses — especially when someone's in 50 AD groups and the IdP sends all of them — can blow past default proxy buffer sizes or timeout limits. You end up with a truncated payload.

**How to fix it** — Bump the buffer sizes and timeout values on the proxy for the ACS endpoint.

---

## ITAR and FedRAMP: what's different

If you're in an ITAR or FedRAMP environment, everything above still applies — but there's a bunch of extra stuff you have to think about. This isn't optional, this is the kind of thing that shows up in audits.

### Payloads stay inside the boundary

SAML payloads have PII in them — NameID, email, attributes, all of it. Everything you capture has to stay within the authorization boundary. That means you don't paste payloads into some random online SAML decoder. Decode and inspect everything locally with the commands in this guide, or use Postman running on a boundary-approved workstation.

### Your tools have to be approved

- Browser extensions like SAML Tracer might not be on the approved list for GFE (Government Furnished Equipment). Check your SSP before you install anything.
- Postman, and anything else you use for debugging, needs to be on the approved software list for your boundary.
- Stick to CLI tools that are already on the box — `base64`, `xmllint`, `openssl`, `diff` — these are on most approved Linux systems already.

### The IdP itself has to be compliant

| Standard | What that means |
|---|---|
| **FedRAMP** | The IdP has to be FedRAMP-authorized or live inside the boundary. Okta has a FedRAMP Moderate offering. Azure AD has GCC and GCC-High. Ping Identity works too. |
| **ITAR** | The IdP has to be in a US-only environment and only US persons can have access to it. Azure GCC-High and AWS GovCloud-based IdPs work. On-prem ADFS works. Standard commercial Okta or Azure AD does not cut it. |

If one domain is pointed at a compliant IdP and the other is pointed at a commercial one, that's not just a payload mismatch — that's a compliance finding. Escalate it.

### Assertions should be encrypted, not just signed

In these environments you're typically required to encrypt SAML assertions. Look for `<saml:EncryptedAssertion>` in the payload. If Domain A is sending encrypted assertions and Domain B is sending them in plaintext, that's a compliance gap on top of being a functional difference.

If you need to decrypt an assertion to actually compare it, you'll need the SP's private key:

```bash
xmlsec1 --decrypt --privkey-pem sp-private-key.pem domain_a_saml.xml
```

That private key is a critical crypto asset — do not move it off the SP host or outside the boundary. Run the decryption on the SP itself or on a boundary-approved workstation. This isn't a suggestion, it's a requirement.

### FIPS 140-2 crypto requirements

- `rsa-sha256` minimum for signatures. If you see `rsa-sha1` anywhere, that's not FIPS-compliant and needs to be fixed.
- RSA keys have to be 2048-bit or higher.
- If the SP or IdP runs OpenSSL, it needs to be the FIPS-validated module.
- TLS 1.2+ for everything — browser to SP, browser to IdP, SP to IdP metadata endpoints. No exceptions.

### Certs and key management

- Signing and encryption certs need to come from a FIPS-validated PKI or go through an approved cert management process.
- Cert rotations have to go through change management (FedRAMP CA-family controls).
- If the two domains use different SP certs, the IdP needs to have both registered, and it needs to be documented in the SSP.

### Network path stuff

The network between IdP and SP in these environments is usually more locked down than you'd expect:

- Traffic might go through a CASB or a TIC (Trusted Internet Connection), either of which can modify headers or add latency you weren't planning for.
- One domain might have VPN or private connectivity to the IdP while the other doesn't, and that alone can cause them to behave differently.
- Boundary firewalls can block metadata refresh endpoints. If they do, one side ends up with stale certs and things break without any obvious reason why.

### You have to log everything

Every debugging action needs an audit trail:
- Who looked at the SAML payloads
- When they were captured
- Where they got stored
- When they were deleted

This is FedRAMP AU controls and ITAR record-keeping. When you're done debugging, clean up. Delete the captured payloads. Auditors will absolutely flag PII sitting around in debug files.

---

## Quick reference — what you're seeing vs. what's probably wrong

| What you're seeing | What's probably going on |
|---|---|
| Different `Issuer` | The two domains are pointed at different IdP apps or tenants |
| Different `Audience` | Someone set up two separate SP registrations on the IdP |
| Attribute names don't match | Different attribute mapping profiles on the IdP side |
| Different `NameID` format | The SP metadata or IdP config is different per domain |
| One encrypted, one plaintext | The SP metadata differs — one requests encryption, the other doesn't |
| Different signing cert | The IdP rotated certs between configs, or they're actually two different IdPs |
| `Destination` mismatch errors | Load balancer or reverse proxy is rewriting the URL |
| `InResponseTo` failures | Session state got lost across load-balanced SP nodes |

---

Start with the diff, go through the fields top to bottom, and the mismatch will show up. If everything in the payload looks right but it's still not working, look at the network layer. Load balancers and proxies are almost always the culprit when two "identical" configs don't behave the same way.
