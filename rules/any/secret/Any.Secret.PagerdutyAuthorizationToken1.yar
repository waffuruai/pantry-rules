// betterleaks v1.10.0's pagerduty-authorization-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PagerdutyAuthorizationToken1
{
    meta:
        description     = "PagerDuty authorization token, which may allow access to PagerDuty account and incident data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PagerdutyAuthorizationToken1"
        severity        = "high"
        score           = 80
        id              = "pagerduty-authorization-token.1"
        confidence      = "high"
        keyword         = "pagerduty"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:(?:[pP][aA][gG][eE][rR][dD][uU][tT][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(u\+[A-Za-z0-9_+-]{18})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
