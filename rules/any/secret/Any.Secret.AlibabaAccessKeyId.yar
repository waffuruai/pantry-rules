// betterleaks v1.10.0's alibaba-access-key-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_AlibabaAccessKeyId
{
    meta:
        description     = "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AlibabaAccessKeyId"
        severity        = "high"
        score           = 80
        id              = "alibaba-access-key-id"
        confidence      = "high"
        keyword         = "ltai"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(LTAI[A-Za-z0-9]{17,21})\b/  // gitleaks:allow

    condition:
        $secret
}
