// betterleaks v1.10.0's canva-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_CanvaClientId
{
    meta:
        description     = "Detected a Canva Connect API client ID, used as a component of the canva-client-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "CanvaClientId"
        severity        = "high"
        score           = 80
        id              = "canva-client-id"
        confidence      = "high"
        keyword         = "canva"
        skip_entropy_lt = "2.5"

    strings:
        $secret = /\b(?:[cC][aA][nN][vV][aA]|[Cc][Aa][Nn][Vv][Aa]_[Cc][Ll][Ii][Ee][Nn][Tt]_[Ii][Dd])(?:.|[\n\r]){0,32}?(?:[cC][lL][iI][eE][nN][tT][_\s-]*[iI][dD]|[aA][pP][pP][_\s-]*[iI][dD])(?:.|[\n\r]){0,16}?\b([Oo][Cc]-[a-zA-ZA-Za-z0-9_-]{8,16})\b/  // gitleaks:allow

    condition:
        $secret
}
