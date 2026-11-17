// betterleaks v1.10.0's tableau-personal-access-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_TableauPersonalAccessToken1
{
    meta:
        description       = "Tableau personal access token."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "TableauPersonalAccessToken1"
        severity          = "high"
        score             = 80
        id                = "tableau-personal-access-token.1"
        confidence        = "high"
        keyword           = "tableau"
        component1        = "tableau-personal-access-token-name.1"
        component1_within = "20L"
        component2        = "tableau-server-host.1"
        component2_within = "20L"
        skip_entropy_lt   = "3.5"

    strings:
        $secret = /(?:^|[^A-Za-z0-9+\/])([A-Za-z0-9+\/]{22}==:[A-Za-z0-9]{32})\b/  // gitleaks:allow

    condition:
        $secret
}
