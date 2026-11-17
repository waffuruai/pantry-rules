// betterleaks v1.10.0's vercel-integration-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_VercelIntegrationToken
{
    meta:
        description         = "Detected a Vercel Integration Token (vci_), which may allow third-party service integrations to act on behalf of users."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "VercelIntegrationToken"
        severity            = "high"
        score               = 80
        id                  = "vercel-integration-token"
        confidence          = "high"
        keyword             = "vci_"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b([vV][cC][iI]_[a-zA-ZA-Za-z0-9_-]{56})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
