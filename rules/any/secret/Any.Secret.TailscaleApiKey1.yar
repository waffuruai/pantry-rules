// betterleaks v1.10.0's tailscale-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_TailscaleApiKey1
{
    meta:
        description     = "Tailscale API access token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "TailscaleApiKey1"
        severity        = "high"
        score           = 80
        id              = "tailscale-api-key.1"
        confidence      = "high"
        keyword         = "tskey-api-"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(tskey-api-[A-Za-z0-9_-]{20,36})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
