// betterleaks v1.10.0's cohere-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CohereApiToken
{
    meta:
        description         = "Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "CohereApiToken"
        severity            = "medium"
        score               = 50
        id                  = "cohere-api-token"
        confidence          = "medium"
        keyword             = "cohere"
        keyword             = "co_api_key"
        skip_entropy_lt     = "4.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:(?:[cC][oO][hH][eE][rR][eE]|[Cc][Oo]_[Aa][Pp][Ii]_[Kk][Ee][Yy])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
