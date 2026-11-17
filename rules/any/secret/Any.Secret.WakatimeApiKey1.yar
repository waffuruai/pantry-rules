// betterleaks v1.10.0's wakatime-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_WakatimeApiKey1
{
    meta:
        description     = "WakaTime API key version 1 (UUID format)."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "WakatimeApiKey1"
        severity        = "high"
        score           = 80
        id              = "wakatime-api-key.1"
        confidence      = "high"
        keyword         = "wakatime"
        keyword         = "waka_time"
        keyword         = "waka-time"
        keyword         = "waka time"
        keyword         = "waka.time"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:(?:[wW][aA][kK][aA][_. -]?[tT][iI][mM][eE](?:[_. -]*(?:[aA][pP][iI]))?[_. -]*(?:[sS][eE][cC][rR][eE][tT]|[kK][eE][yY]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
