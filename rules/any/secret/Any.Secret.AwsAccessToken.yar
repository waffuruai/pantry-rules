// betterleaks v1.10.0's aws-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AwsAccessToken
{
    meta:
        description       = "Identified an AWS access key ID paired with a secret access key, which together can provide full access to AWS services."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "AwsAccessToken"
        severity          = "high"
        score             = 80
        id                = "aws-access-token"
        confidence        = "high"
        keyword           = "a3t"
        keyword           = "akia"
        keyword           = "asia"
        keyword           = "abia"
        keyword           = "acca"
        component1        = "aws-secret-access-key"
        component1_within = "5L"
        skip_entropy_le   = "3.0"
        skip_regex_secret = ".+EXAMPLE$"  // gitleaks:allow

    strings:
        $secret = /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/  // gitleaks:allow

    condition:
        $secret
}
