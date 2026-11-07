// betterleaks v1.10.0's deepgram-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DeepgramApiKey
{
    meta:
        description         = "Detected a Deepgram API Key, which may expose speech recognition services and audio data to unauthorized access."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "DeepgramApiKey"
        severity            = "high"
        score               = 80
        id                  = "deepgram-api-key"
        confidence          = "high"
        keyword             = "deepgram"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[dD][eE][eE][pP][gG][rR][aA][mM])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
