// betterleaks v1.10.0's redirect-pizza-api-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_RedirectPizzaApiToken1
{
    meta:
        description     = "redirect.pizza API token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "RedirectPizzaApiToken1"
        severity        = "high"
        score           = 80
        id              = "redirect-pizza-api-token.1"
        confidence      = "high"
        keyword         = "rpa_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(rpa_[A-Za-z0-9]{30})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
