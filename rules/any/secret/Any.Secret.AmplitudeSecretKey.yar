// betterleaks v1.10.0's amplitude-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AmplitudeSecretKey
{
    meta:
        description         = "Detected an Amplitude secret key, which may allow unauthorized event ingestion or access to Amplitude API functionality."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AmplitudeSecretKey"
        severity            = "medium"
        score               = 50
        id                  = "amplitude-secret-key"
        confidence          = "medium"
        keyword             = "amplitude"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b[aA][mM][pP][lL][iI][tT][uU][dD][eE](?:.|[\n\r]){0,32}?(?:[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee]|[Aa][Cc][Cc][Ee][Ss][Ss]|[Kk][Ee][Yy]|[Tt][Oo][Kk][Ee][Nn]|[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn])(?:.|[\n\r]){0,16}?\b([A-Fa-f0-9]{32})\b/  // gitleaks:allow

    condition:
        $secret
}
