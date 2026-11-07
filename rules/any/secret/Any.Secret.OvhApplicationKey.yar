// betterleaks v1.10.0's ovh-application-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_OvhApplicationKey
{
    meta:
        description     = "OVHcloud Application Key - component of authenticated OVH API requests."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "OvhApplicationKey"
        severity        = "medium"
        score           = 50
        id              = "ovh-application-key"
        confidence      = "medium"
        keyword         = "ovh"
        skip_entropy_le = "2.0"

    strings:
        $secret = /(?:[aA][pP][pP](?:[lL][iI][cC][aA][tT][iI][oO][nN])?[_.-]{0,1}[kK][eE][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9-]{16})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
