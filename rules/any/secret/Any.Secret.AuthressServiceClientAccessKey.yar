// betterleaks v1.10.0's authress-service-client-access-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AuthressServiceClientAccessKey
{
    meta:
        description     = "Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AuthressServiceClientAccessKey"
        severity        = "high"
        score           = 80
        id              = "authress-service-client-access-key"
        confidence      = "high"
        keyword         = ".acc_"
        keyword         = ".acc-"
        skip_entropy_lt = "4.0"

    strings:
        $secret = /\b((?:[sS][cC]|[eE][xX][tT]|[sS][cC][aA][uU][tT][hH]|[aA][uU][tT][hH][rR][eE][sS][sS])_[A-Za-z0-9]{5,30}\.[A-Za-z0-9]{4,6}\.[aA][cC][cC][_-][A-Za-z0-9-]{10,32}\.[A-Za-z0-9+\/_=-]{30,120})\b/  // gitleaks:allow

    condition:
        $secret
}
