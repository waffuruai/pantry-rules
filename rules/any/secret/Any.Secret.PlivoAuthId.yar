// betterleaks v1.10.0's plivo-auth-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_PlivoAuthId
{
    meta:
        description         = "Plivo Auth ID, used as a component of the Plivo Auth Token composite rule."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "PlivoAuthId"
        severity            = "high"
        score               = 80
        id                  = "plivo-auth-id"
        confidence          = "high"
        keyword             = "plivo"
        skip_entropy_lt     = "2.8"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[pP][lL][iI][vV][oO](?:[_. -]*(?:[aA][uU][tT][hH]|[aA][cC][cC][oO][uU][nN][tT]))?[_. -]*(?:[iI][dD]|[sS][iI][dD]))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([Mm][Aa][a-zA-Z0-9]{18})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
