// betterleaks v1.10.0's workato-developer-api-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_WorkatoDeveloperApiToken1
{
    meta:
        description     = "Workato Developer API token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "WorkatoDeveloperApiToken1"
        severity        = "high"
        score           = 80
        id              = "workato-developer-api-token.1"
        confidence      = "high"
        keyword         = "wrka"
        skip_entropy_lt = "4.0"

    strings:
        $secret = /\b(wrka(?:[a-z]{2})?-eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{64,})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
