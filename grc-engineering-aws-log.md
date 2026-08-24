# GRC Engineering for AWS — Running Log

Project context: hands-on Infrastructure as Code and cloud security skills, moving into event-driven architecture, and  Policy-as-Code (OPA, Rego) additions planned for the future as my skill grows.

\---

## Step 1: Secure S3 Bucket (CloudFormation)

**Goal:** First hands-on IaC exercise — deploy a secure S3 bucket via CloudFormation.

**Template:**

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: Secure S3 Bucket Example
Resources:
    SecureBucket:
        Type: AWS::S3::Bucket
        Properties:
            BucketName: my-secure-bucket
            PublicAccessBlockConfiguration:
                BlockPublicAcls: true
                BlockPublicPolicy: true
                IgnorePublicAcls: true
                RestrictPublicBuckets: true
            BucketEncryption:
                ServerSideEncryptionConfiguration:
                    - ServerSideEncryptionByDefault:
                        SSEAlgorithm: AES256
```

**Controls implemented and rough NIST CSF 2.0 mapping:**

* Public access block → PR.AC (Access Control)
* Server-side encryption (SSE-S3/AES256) → PR.DS (Data Security)
* (Versioning considered but not included in the final deployed version)

**Troubleshooting log (real debugging, kept as evidence of process):**

* CLI commands run from wrong working directory (`C:\\WINDOWS\\System32`) — file not found errors until navigating to the correct drive/folder.
* Literal commas mistakenly included in CLI flags — invalid syntax.
* `AccessDenied` on `cloudformation:DescribeStacks` — IAM user (`sadako000`) lacked permissions; resolved by attaching `AWSCloudFormationFullAccess` and `AmazonS3FullAccess` via root account.
* `CREATE\_FAILED`: "Bucket name should not contain uppercase characters" — root cause was in the **template file itself** (`BucketName: my-secure-Bucket`), not the CLI input. Initial troubleshooting incorrectly focused on CLI syntax before recognizing the error was in file content.
* Stack stuck in `ROLLBACK\_COMPLETE` after failure — required `delete-stack` before redeploying.
* **Result: successful deploy** after lowercasing bucket name and clearing the failed stack.

**Portfolio framing notes:**

* Not portfolio-ready as a bare deploy — needs framework mapping, control rationale ("why," not just "what"), and verification evidence (e.g. `get-public-access-block`, `get-bucket-policy-status` output).
* The uppercase-bucket-name debugging episode is worth keeping as a documented example of root-cause troubleshooting.

\---

## Step 2: SCP — Prevent Open SSH (Port 22)

**Goal:** Deny creation/modification of security group rules that open SSH to the entire internet, account-wide, via Organizations SCP (not IAM policy — enforced regardless of IAM permissions).

**Final JSON:**

```json
{
    "Version": "2012-10-17",
    "Statement": \[
        {
            "Sid": "PreventOpenSSH",
            "Effect": "Deny",
            "Action": \[
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:ModifySecurityGroupRules"
            ],
            "Resource": "\*",
            "Condition": {
                "StringEquals": {
                    "ec2:Region": "us-east-1"
                },
                "IpAddress": {
                    "ec2:SecurityGroupIngressIpRanges": \["0.0.0.0/0"]
                },
                "NumericEquals": {
                    "ec2:SecurityGroupIngressToPort": 22
                }
            }
        }
    ]
}
```

**Debugging notes (self-corrected on review):**

* Missing commas after `"Version"` and `"Sid"` values.
* Trailing comma after the `Action` array's last element.
* Typo: `ex2:SecurityGroupIngressIpRanges` → corrected to `ec2:`.

**Scope decisions and known gaps:**

* Preventative only — does **not** remediate security groups that already have open SSH before this SCP exists. Detection/remediation of existing drift is a separate concern, likely addressed via Event-Driven Architecture (EventBridge + Lambda, or AWS Config) later in the project.
* Only covers `AuthorizeSecurityGroupIngress` and `ModifySecurityGroupRules` — does not include `RevokeSecurityGroupIngress`, so revoking a deny-oriented rule isn't blocked by this statement. Scoped intentionally for this exercise.
* Region-scoped to `us-east-1` only, as suggested by the exercise. Multi-region coverage would require either a condition per region or removing the region condition — understood as a deliberate simplification, not an oversight.
* SCPs only function within AWS Organizations (applied to accounts/OUs). Won't attach at all in a standalone, non-Org account.

\---

## Step 3: SCP — Prevent CloudTrail Audit Log Deletion/Alteration

**Goal:** Prevent deletion or stopping of CloudTrail audit logging, in service of integrity and non-repudiation.

**Final JSON (current decision — see note below):**

```json
{
    "Version": "2012-10-17",
    "Statement": \[
        {
            "Effect": "Deny",
            "Action": \[
                "cloudtrail:DeleteTrail",
                "cloudtrail:StopLogging"
            ],
            "Resource": "\*"
        }
    ]
}
```

**Decision log:**

* Initial draft included `cloudtrail:UpdateTrail` alongside `DeleteTrail` and `StopLogging`, reasoning: if a trail is properly configured, no one should need to alter it — protects non-repudiation, not just deletion/stoppage.
* Explored adding a `Condition` (`StringNotEquals` on `aws:PrincipalArn`) to carve out a break-glass exception role for legitimate updates. Recognized that the SCP condition only creates the technical exception path — actual governance (approval process, MFA-gated role assumption, time-bound access, logging of the exception itself) is a separate process/IAM control layer, not something the SCP JSON handles alone.
* **Decision: cut `UpdateTrail` for now**, since break-glass/conditional-access concepts haven't been covered yet. Keeping the SCP scoped to what's been learned so far rather than front-loading architecture ahead of the material.

**Known gap to revisit:**

* Without `UpdateTrail` denied, the non-repudiation gap re-opens — someone could still modify what CloudTrail logs (e.g., disable specific event types) without deleting or stopping the trail outright. **Revisit once IAM/conditional-access concepts are covered** — likely re-add `UpdateTrail` to the deny list, paired with a break-glass role exception.
* No region scoping or resource-level scoping on this SCP (applies universally) — an asymmetry worth being deliberate about compared to the region-scoped SSH policy, if these are documented side by side later.
* CloudTrail log **destination** protection (e.g., the S3 bucket storing the logs) is a separate, related control not yet addressed — noted as further down the path.

\---

## Step 4: SCP — Prevent Removal/Disabling of S3 Default Encryption

**Goal:** Ensure S3 buckets built with server-side encryption as default (per the Step 1 CloudFormation pattern) can't have that encryption setting removed or weakened afterward.

**Final JSON:**

```json
{
    "Version": "2012-10-17",
    "Statement": \[
        {
            "Effect": "Deny",
            "Action": "s3:PutEncryptionConfiguration",
            "Resource": "\*"
        }
    ]
}
```

**Reasoning trail:**

* Initial draft attempted to deny `s3:CreateBucket` conditioned on a `Bool` check against a made-up key (`s3:BucketEncryption`/`s3:bucketEncryption`) evaluating to `false`.
* Worked through why this can't function: `CreateBucket` and `PutBucketEncryption` are separate, sequential API calls, not one atomic action — even the CloudFormation template performs them as two steps behind the scenes. At the moment `CreateBucket` fires, no encryption information exists yet for a condition to check. The `Bool` operator itself is valid (e.g. `aws:MultiFactorAuthPresent`); the problem was pairing it with a condition key that doesn't exist.
* Clarified a foundational distinction: CloudFormation's `BucketEncryption` block does not "encrypt the bucket" as a static object — it sets a *default rule* that auto-encrypts objects uploaded to it, even if the uploader's request didn't specify encryption.
* Considered two real enforcement points: (A) deny unencrypted uploads at `s3:PutObject`, or (B) protect the encryption *configuration* from being changed after the fact via `s3:PutEncryptionConfiguration`.
* Noted for context: AWS has applied SSE-S3 default encryption automatically to all newly created buckets, account-wide, since January 2023 — meaning the "require encryption at creation" gap is already partially closed by AWS itself.
* **Decision:** pivoted to the same pattern as the Step 3 CloudTrail SCP — protect an existing control from being disabled/removed, rather than trying to enforce a condition at a moment before the relevant data exists. Chose to deny `s3:PutEncryptionConfiguration`, the single API action used both to set and to change/remove a bucket's default encryption.

**Known limitations to revisit:**

* Blanket deny blocks legitimate encryption changes too (e.g., upgrading a bucket from SSE-S3/AES256 to SSE-KMS) — same trade-off pattern as the `UpdateTrail` decision in Step 3. No way to distinguish "weakening" from "upgrading" since it's the same API action either way.
* This SCP protects a baseline (AWS-default or CloudFormation-set) from removal — it does not itself establish encryption at creation, since no mechanism can act on that gap at the `CreateBucket` moment.
* Does not address `s3:PutObject`-level enforcement (requiring encryption per-upload via request headers) — a separate, complementary control not yet built.

\---

## Open threads / revisit list

* \[ ] Add S3 bucket-level protection for the CloudTrail log destination bucket.
* \[ ] Revisit `UpdateTrail` exclusion once break-glass/conditional IAM concepts are covered.
* \[ ] Revisit `PutEncryptionConfiguration` deny — same break-glass/conditional-access gap as `UpdateTrail`, revisit once those concepts are covered.
* \[ ] Consider a complementary `s3:PutObject` control requiring encryption at upload time.
* \[ ] Event-Driven Architecture as the next major concept area — likely where drift detection/remediation (e.g., for the SSH SCP gap) gets addressed.
* \[ ] Eventual portfolio packaging: framework mapping (NIST CSF 2.0), control rationale write-ups, verification evidence, and the troubleshooting narrative from Step 1.

