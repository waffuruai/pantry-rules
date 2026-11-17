// betterleaks v1.10.0's pulumi-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PulumiApiToken
{
    meta:
        description     = "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PulumiApiToken"
        severity        = "high"
        score           = 80
        id              = "pulumi-api-token"
        confidence      = "high"
        keyword         = "pul-"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b(pul-[a-f0-9]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
