// betterleaks v1.10.0's curl-auth-header rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_CurlAuthHeader
{
    meta:
        description     = "Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "CurlAuthHeader"
        severity        = "high"
        score           = 80
        id              = "curl-auth-header"
        confidence      = "high"
        keyword         = "curl"
        skip_entropy_le = "2.75"

    strings:
        $secret = /\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"(?:[Aa][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[ \t]{0,5}(?:[Bb][aA][sS][iI][cC][ \t]([A-Za-z0-9+\/]{8,}={0,3})|(?:[Bb][eE][aA][rR][eE][rR]|(?:[Aa][pP][iI]-)?[Tt][oO][kK][eE][nN])[ \t]([\w=~@.+\/-]{8,})|([\w=~@.+\/-]{8,}))|(?:(?:[Xx]-(?:[A-Za-z]+-)?)?(?:[Aa][pP][iI]-?)?(?:[Kk][eE][yY]|[Tt][oO][kK][eE][nN])):[ \t]{0,5}([\w=~@.+\/-]{8,}))"|'(?:[Aa][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[ \t]{0,5}(?:[Bb][aA][sS][iI][cC][ \t]([A-Za-z0-9+\/]{8,}={0,3})|(?:[Bb][eE][aA][rR][eE][rR]|(?:[Aa][pP][iI]-)?[Tt][oO][kK][eE][nN])[ \t]([\w=~@.+\/-]{8,})|([\w=~@.+\/-]{8,}))|(?:(?:[Xx]-(?:[A-Za-z]+-)?)?(?:[Aa][pP][iI]-?)?(?:[Kk][eE][yY]|[Tt][oO][kK][eE][nN])):[ \t]{0,5}([\w=~@.+\/-]{8,}))')(?:\B|\s|$)/  // gitleaks:allow

    condition:
        $secret
}
