// betterleaks v1.10.0's fastly-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_FastlyApiToken
{
    meta:
        description         = "Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "FastlyApiToken"
        severity            = "high"
        score               = 80
        id                  = "fastly-api-token"
        confidence          = "high"
        keyword             = "fastly"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[fF][aA][sS][tT][lL][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
