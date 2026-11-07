// betterleaks v1.10.0's exoscale-api-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_ExoscaleApiSecret
{
    meta:
        description     = "Identified an Exoscale API secret, used as a component of the exoscale-api-key composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ExoscaleApiSecret"
        severity        = "high"
        score           = 80
        id              = "exoscale-api-secret"
        confidence      = "high"
        keyword         = "exoscale"
        skip_entropy_lt = "4.0"

    strings:
        $secret = /(?:[eE][xX][oO][sS][cC][aA][lL][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9_\-]{40,60})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
