<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# Cert-Manager ClouDNS DNS01 Provider

A Cert-Manager DNS01 provider for ClouDNS.

## Configuration

Cert-Manager expects DNS01 providers to parse configuration from incoming webhook requests.

This can be used to have multiple Cert-Manager `Issuer` resources use the same instance of the provider with different credentials or configuration.
in the Cert-Manager `Issuer` resource you need to define.  

```yaml
config:
  auth-id: "your-auth-id"
  auth-password: "your-auth-password"
  authIdType: "auth-id"
  ttl: 3600
  apiKeySecretRef:
    name: "cloudns-test-zone-api-secret"
    key: "apikey"
```

## Development

### Running DNS01 provider conformance testing suite

You need to fill the `testdata/my-custom-solver/config.json` file with the following content:

```json
{
    "authId": "your-auth-id",
    "authIdType": "auth-id",
    "ttl": 3600,
    "apiKeySecretRef":     {
        "name": "cloudns-test-zone-api-secret",
        "key": "apikey"
    }
}
```

And create a secret with the following template:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloudns-test-zone-api-secret
type: Opaque
data:
  apikey: Zm1zcHJXcEt1LThMOWp0
```

```bash
# Run testing suite
TEST_ZONE_NAME="myzone.cloudns.be." make test
```
