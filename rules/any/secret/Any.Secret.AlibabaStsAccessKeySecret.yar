// betterleaks v1.10.0's alibaba-sts-access-key-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AlibabaStsAccessKeySecret
{
    meta:
        description         = "Detected an Alibaba Cloud STS AccessKey secret, which may allow temporary Alibaba Cloud API access when paired with an STS AccessKey ID and security token."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AlibabaStsAccessKeySecret"
        severity            = "high"
        score               = 80
        id                  = "alibaba-sts-access-key-secret"
        confidence          = "high"
        keyword             = "alibaba"
        keyword             = "aliyun"
        component1          = "alibaba-sts-access-key-id"
        component1_within   = "10L"
        component2          = "alibaba-sts-security-token"
        component2_within   = "10L"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[aA][lL][iI][bB][aA][bB][aA]|[aA][lL][iI][yY][uU][nN]|[sS][eE][cC][rR][eE][tT]|[kK][eE][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9]{30,64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
