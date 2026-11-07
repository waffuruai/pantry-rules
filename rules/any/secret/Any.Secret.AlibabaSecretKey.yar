// betterleaks v1.10.0's alibaba-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AlibabaSecretKey
{
    meta:
        description         = "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AlibabaSecretKey"
        severity            = "high"
        score               = 80
        id                  = "alibaba-secret-key"
        confidence          = "high"
        keyword             = "alibaba"
        keyword             = "aliyun"
        component1          = "alibaba-access-key-id"
        component1_within   = "5L"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[aA][lL][iI][bB][aA][bB][aA]|[aA][lL][iI][yY][uU][nN]|[sS][eE][cC][rR][eE][tT]|[kK][eE][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9]{30})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
