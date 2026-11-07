// betterleaks v1.10.0's dropbox-long-lived-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DropboxLongLivedApiToken
{
    meta:
        description         = "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "DropboxLongLivedApiToken"
        severity            = "high"
        score               = 80
        id                  = "dropbox-long-lived-api-token"
        confidence          = "high"
        keyword             = "dropbox"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{11}([Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa])[A-Za-z0-9\-_=]{43})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
