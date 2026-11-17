// betterleaks v1.10.0's algolia-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AlgoliaApiKey
{
    meta:
        description         = "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AlgoliaApiKey"
        severity            = "high"
        score               = 80
        id                  = "algolia-api-key"
        confidence          = "high"
        keyword             = "algolia"
        component1          = "algolia-application-id"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[aA][lL][gG][oO][lL][iI][aA])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
