// betterleaks v1.10.0's vercel-personal-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_VercelPersonalAccessToken
{
    meta:
        description         = "Detected a Vercel Personal Access Token (vcp_), which may expose full account and deployment management capabilities."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "VercelPersonalAccessToken"
        severity            = "high"
        score               = 80
        id                  = "vercel-personal-access-token"
        confidence          = "high"
        keyword             = "vcp_"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b([vV][cC][pP]_[a-zA-ZA-Za-z0-9_-]{56})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
