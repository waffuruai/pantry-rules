// betterleaks v1.10.0's contentful-delivery-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ContentfulDeliveryApiToken
{
    meta:
        description         = "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "ContentfulDeliveryApiToken"
        severity            = "medium"
        score               = 50
        id                  = "contentful-delivery-api-token"
        confidence          = "medium"
        keyword             = "contentful"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[cC][oO][nN][tT][eE][nN][tT][fF][uU][lL])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9=_\-]{43})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
