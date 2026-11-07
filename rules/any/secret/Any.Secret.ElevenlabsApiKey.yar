// betterleaks v1.10.0's elevenlabs-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ElevenlabsApiKey
{
    meta:
        description     = "Detected an ElevenLabs API Key, which may expose AI voice synthesis services to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ElevenlabsApiKey"
        severity        = "high"
        score           = 80
        id              = "elevenlabs-api-key"
        confidence      = "high"
        keyword         = "elevenlabs"
        skip_entropy_le = "3.5"

    strings:
        $secret = /(?:[eE][lL][eE][vV][eE][nN][lL][aA][bB][sS])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([sS][kK]_[A-F0-9a-f]{48})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
