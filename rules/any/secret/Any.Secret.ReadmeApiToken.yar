// betterleaks v1.10.0's readme-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ReadmeApiToken
{
    meta:
        description     = "Detected a Readme API token, risking unauthorized documentation management and content exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ReadmeApiToken"
        severity        = "high"
        score           = 80
        id              = "readme-api-token"
        confidence      = "high"
        keyword         = "rdme_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b(rdme_[a-z0-9]{70})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
