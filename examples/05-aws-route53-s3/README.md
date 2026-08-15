# 05 — AWS Route 53 + S3 + CloudFront (static site)

MCP server covering the three AWS services that power a typical
static site: Route 53 DNS, S3 object storage, CloudFront CDN.
Uses the local `aws` CLI so SigV4 signing and credential
resolution stay in battle-tested tooling.

## Upstream

- `aws route53 ...`
- `aws s3api ...`
- `aws cloudfront ...`

## Env vars

Inherited from the shell; the binding invokes the `aws` CLI with
the default credential chain (env → shared credentials → IAM role
→ SSO).

| Var | Purpose |
|---|---|
| `AWS_PROFILE` | Optional named profile |
| `AWS_REGION` | Optional default region |

## Run

```bash
cargo run -p mcpg -- --config examples/05-aws-route53-s3/config.yaml
```

## Exposed tools

- `aws.r53.zones.list` — list hosted zones.
- `aws.r53.records.list` — list records in a zone.
- `aws.r53.change` — apply a change batch JSON.
- `aws.s3.list` — list objects with a prefix.
- `aws.s3.put` — upload a local file to S3.
- `aws.cloudfront.invalidate` — invalidate cache paths.

## Notes

- `aws.r53.change` expects the change batch JSON on local disk.
  Build it with a companion pipeline or a `Transform` step.
- For CI/CD runners use an IAM role via instance metadata; never
  paste access keys into env.
