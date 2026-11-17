// betterleaks v1.10.0's upcloud-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_UpcloudApiToken
{
    meta:
        description     = "Identified an UpCloud API token, which may expose cloud infrastructure resources to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "UpcloudApiToken"
        severity        = "high"
        score           = 80
        id              = "upcloud-api-token"
        confidence      = "high"
        keyword         = "ucat_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(ucat_[0-9A-Za-z]{24,32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
