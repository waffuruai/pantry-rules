// betterleaks v1.10.0's planetscale-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PlanetscaleApiToken
{
    meta:
        description     = "Identified a PlanetScale API token, potentially compromising database management and operations."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PlanetscaleApiToken"
        severity        = "high"
        score           = 80
        id              = "planetscale-api-token"
        confidence      = "high"
        keyword         = "pscale_tkn_"
        component1      = "planetscale-id"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(pscale_tkn_[\w=\.-]{32,64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
