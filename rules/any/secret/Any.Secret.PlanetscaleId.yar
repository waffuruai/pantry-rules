// betterleaks v1.10.0's planetscale-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_PlanetscaleId
{
    meta:
        description     = "Found a PlanetScale service token ID."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PlanetscaleId"
        severity        = "high"
        score           = 80
        id              = "planetscale-id"
        confidence      = "high"
        keyword         = "pscale"
        keyword         = "planetscale"
        skip_entropy_le = "3.0"

    strings:
        $secret = /(?:[pP][sS][cC][aA][lL][eE]|[pP][lL][aA][nN][eE][tT][sS][cC][aA][lL][eE])(?:.|[\n\r]){0,16}?(?:[Uu][Ss][Ee][Rr]|[Ii][Dd]|[Nn][Aa][Mm][Ee])(?:.|[\n\r]){0,16}?([A-Za-z0-9]{12})/  // gitleaks:allow

    condition:
        $secret
}
