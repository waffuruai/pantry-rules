// betterleaks v1.10.0's airtable-oauth-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AirtableOauthToken
{
    meta:
        description         = "Detected an Airtable OAuth token, which may allow unauthorized access to Airtable resources granted to an OAuth integration."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AirtableOauthToken"
        severity            = "high"
        score               = 80
        id                  = "airtable-oauth-token"
        confidence          = "high"
        keyword             = "airtable"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[aA][iI][rR][tT][aA][bB][lL][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]+\.[vV]1\.[a-zA-Z0-9_-]+\.[A-Fa-f0-9]+)(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
