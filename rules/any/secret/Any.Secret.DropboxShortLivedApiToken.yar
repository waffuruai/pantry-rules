// betterleaks v1.10.0's dropbox-short-lived-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DropboxShortLivedApiToken
{
    meta:
        description         = "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "DropboxShortLivedApiToken"
        severity            = "high"
        score               = 80
        id                  = "dropbox-short-lived-api-token"
        confidence          = "high"
        keyword             = "dropbox"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([sS][lL]\.[A-Za-z0-9\-=_]{135})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
