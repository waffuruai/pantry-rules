// betterleaks v1.10.0's nuget-config-password rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_NugetConfigPassword
{
    meta:
        description       = "Identified a password within a Nuget config file, potentially compromising package management access."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "NugetConfigPassword"
        severity          = "high"
        score             = 80
        id                = "nuget-config-password"
        confidence        = "high"
        keyword           = "<add key="
        skip_entropy_le   = "1.0"
        skip_regex_secret = "33f!!lloppa"  // gitleaks:allow
        skip_regex_secret = "hal\\+9ooo_da!sY"  // gitleaks:allow
        skip_regex_secret = "^\\%\\S.*\\%$"  // gitleaks:allow

    strings:
        $secret = /<[aA][dD][dD] [kK][eE][yY]=\"(?:(?:[Cc][lL][eE][aA][rR][Tt][eE][xX][tT])?[Pp][aA][sS][sS][wW][oO][rR][dD])\"\s*[vV][aA][lL][uU][eE]=\"(.{8,})\"\s*\/>/  // gitleaks:allow

    condition:
        $secret and filepath matches /[nN][uU][gG][eE][tT]\.[cC][oO][nN][fF][iI][gG]$/
}
