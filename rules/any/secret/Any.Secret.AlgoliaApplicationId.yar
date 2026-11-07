// betterleaks v1.10.0's algolia-application-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_AlgoliaApplicationId
{
    meta:
        description         = "Detected an Algolia application ID, used as a component of the algolia-api-key composite rule."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AlgoliaApplicationId"
        severity            = "high"
        score               = 80
        id                  = "algolia-application-id"
        confidence          = "high"
        keyword             = "algolia"
        skip_entropy_lt     = "2.75"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[aA][lL][gG][oO][lL][iI][aA])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{10})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
