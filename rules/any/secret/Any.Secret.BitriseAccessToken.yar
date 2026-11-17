// betterleaks v1.10.0's bitrise-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_BitriseAccessToken
{
    meta:
        description         = "Detected a Bitrise personal or workspace access token, which may expose CI/CD applications and builds."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "BitriseAccessToken"
        severity            = "high"
        score               = 80
        id                  = "bitrise-access-token"
        confidence          = "high"
        keyword             = "bitrise"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:(?:[bB][iI][tT][rR][iI][sS][eE](?:[ _-]*(?:[pP][eE][rR][sS][oO][nN][aA][lL]|[wW][oO][rR][kK][sS][pP][aA][cC][eE]))?(?:[ _-]*(?:[aA][cC][cC][eE][sS][sS]|[aA][pP][iI]))?[ _-]*[tT][oO][kK][eE][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{60,120})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
