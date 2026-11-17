// betterleaks v1.10.0's freshbooks-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_FreshbooksAccessToken
{
    meta:
        description         = "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "FreshbooksAccessToken"
        severity            = "high"
        score               = 80
        id                  = "freshbooks-access-token"
        confidence          = "high"
        keyword             = "freshbooks"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[fF][rR][eE][sS][hH][bB][oO][oO][kK][sS])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
