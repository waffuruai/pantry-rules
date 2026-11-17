// betterleaks v1.10.0's okta-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_OktaAccessToken
{
    meta:
        description     = "Identified an Okta Access Token, which may compromise identity management services and user authentication data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "OktaAccessToken"
        severity        = "high"
        score           = 80
        id              = "okta-access-token"
        confidence      = "high"
        keyword         = "okta"
        skip_entropy_le = "4.0"

    strings:
        $secret = /(?:(?:(?:[Oo]kta|OKTA))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(00[\w=\-]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
