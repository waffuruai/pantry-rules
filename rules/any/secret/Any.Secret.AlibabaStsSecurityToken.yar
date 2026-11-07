// betterleaks v1.10.0's alibaba-sts-security-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_AlibabaStsSecurityToken
{
    meta:
        description         = "Detected an Alibaba Cloud STS security token, used as a component of the alibaba-sts-access-key-secret composite rule."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AlibabaStsSecurityToken"
        severity            = "high"
        score               = 80
        id                  = "alibaba-sts-security-token"
        confidence          = "high"
        keyword             = "alibaba"
        keyword             = "aliyun"
        keyword             = "cais"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[aA][lL][iI][bB][aA][bB][aA]|[aA][lL][iI][yY][uU][nN]|[sS][eE][cC][rR][eE][tT]|[kK][eE][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([Cc][Aa][Ii][Ss][a-zA-ZA-Za-z0-9+\/_=-]{20,1000}[a-zA-ZA-Za-z0-9+\/_=-]{0,24})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
