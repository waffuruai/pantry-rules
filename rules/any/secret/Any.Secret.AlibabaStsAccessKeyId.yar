// betterleaks v1.10.0's alibaba-sts-access-key-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_AlibabaStsAccessKeyId
{
    meta:
        description     = "Detected an Alibaba Cloud STS AccessKey ID, used as a component of the alibaba-sts-access-key-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AlibabaStsAccessKeyId"
        severity        = "high"
        score           = 80
        id              = "alibaba-sts-access-key-id"
        confidence      = "high"
        keyword         = "sts."
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(STS\.[A-Za-z0-9]{16,64})\b/  // gitleaks:allow

    condition:
        $secret
}
