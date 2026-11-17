// betterleaks v1.10.0's kimi-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_KimiApiKey
{
    meta:
        description     = "Detected a Kimi API key, which may expose Moonshot AI model access and usage to unauthorized parties."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "KimiApiKey"
        severity        = "high"
        score           = 80
        id              = "kimi-api-key"
        confidence      = "high"
        keyword         = "kimi"
        keyword         = "moonshot"
        skip_entropy_le = "3.5"

    strings:
        $secret = /(?:[kK][iI][mM][iI]|[mM][oO][oO][nN][sS][hH][oO][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([sS][kK]-[a-zA-ZA-Za-z0-9_-]{48})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
