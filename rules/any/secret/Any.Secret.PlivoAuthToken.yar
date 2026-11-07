// betterleaks v1.10.0's plivo-auth-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PlivoAuthToken
{
    meta:
        description         = "Plivo Auth Token."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "PlivoAuthToken"
        severity            = "high"
        score               = 80
        id                  = "plivo-auth-token"
        confidence          = "high"
        keyword             = "plivo"
        component1          = "plivo-auth-id"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:(?:[pP][lL][iI][vV][oO](?:[_. -]*(?:[aA][uU][tT][hH]))?[_. -]*(?:[sS][eE][cC][rR][eE][tT]|[tT][oO][kK][eE][nN]|[kK][eE][yY]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
