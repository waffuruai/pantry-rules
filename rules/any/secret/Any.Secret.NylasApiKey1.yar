// betterleaks v1.10.0's nylas-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_NylasApiKey1
{
    meta:
        description     = "Nylas API key, which may allow application-level access to connected email, calendar, and contact data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "NylasApiKey1"
        severity        = "high"
        score           = 80
        id              = "nylas-api-key.1"
        confidence      = "high"
        keyword         = "nyk_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(nyk_[A-Za-z0-9]{67})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
