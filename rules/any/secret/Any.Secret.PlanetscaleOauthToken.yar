// betterleaks v1.10.0's planetscale-oauth-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PlanetscaleOauthToken
{
    meta:
        description     = "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PlanetscaleOauthToken"
        severity        = "high"
        score           = 80
        id              = "planetscale-oauth-token"
        confidence      = "high"
        keyword         = "pscale_oauth_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(pscale_oauth_[\w=\.-]{32,64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
