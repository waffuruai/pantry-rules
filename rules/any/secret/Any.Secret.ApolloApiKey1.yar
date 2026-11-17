// betterleaks v1.10.0's apollo-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ApolloApiKey1
{
    meta:
        description         = "Apollo.io API key, which may allow access to sales intelligence and engagement data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "ApolloApiKey1"
        severity            = "medium"
        score               = 50
        id                  = "apollo-api-key.1"
        confidence          = "medium"
        keyword             = "apollo"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:(?:[aA][pP][oO][lL][lL][oO])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{22})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
