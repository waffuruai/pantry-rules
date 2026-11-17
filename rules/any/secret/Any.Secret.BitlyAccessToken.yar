// betterleaks v1.10.0's bitly-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_BitlyAccessToken
{
    meta:
        description         = "Detected a Bitly access token, which may allow unauthorized access to Bitly account and link management APIs."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "BitlyAccessToken"
        severity            = "high"
        score               = 80
        id                  = "bitly-access-token"
        confidence          = "high"
        keyword             = "bitly"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b[bB][iI][tT][lL][yY](?:.|[\n\r]){0,32}?(?:[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee]|[Aa][Cc][Cc][Ee][Ss][Ss]|[Kk][Ee][Yy]|[Tt][Oo][Kk][Ee][Nn])(?:.|[\n\r]){0,32}?([A-Fa-f0-9]{40})\b/  // gitleaks:allow

    condition:
        $secret
}
