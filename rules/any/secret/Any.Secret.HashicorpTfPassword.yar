// betterleaks v1.10.0's hashicorp-tf-password rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_HashicorpTfPassword
{
    meta:
        description     = "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "HashicorpTfPassword"
        severity        = "medium"
        score           = 50
        id              = "hashicorp-tf-password"
        confidence      = "medium"
        keyword         = "administrator_login_password"
        keyword         = "password"
        skip_entropy_le = "2.0"

    strings:
        $secret = /(?:[aA][dD][mM][iI][nN][iI][sS][tT][rR][aA][tT][oO][rR]_[lL][oO][gG][iI][nN]_[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][oO][rR][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}("[A-Za-z0-9=_\-]{8,20}")(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret and filepath matches /\.(?:[tT][fF]|[hH][cC][lL])$/
}
