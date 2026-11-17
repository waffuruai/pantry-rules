// betterleaks v1.10.0's figma-personal-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_FigmaPersonalAccessToken
{
    meta:
        description     = "Uncovered a Figma Personal Access Token, which may compromise design assets and team collaboration."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "FigmaPersonalAccessToken"
        severity        = "high"
        score           = 80
        id              = "figma-personal-access-token"
        confidence      = "high"
        keyword         = "figd_"
        skip_entropy_le = "3.5"

    strings:
        $secret = /\b([fF][iI][gG][dD]_[a-zA-Z0-9_-]{38,42})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
