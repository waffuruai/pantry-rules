// betterleaks v1.10.0's assemblyai-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AssemblyaiApiKey
{
    meta:
        description         = "Detected an AssemblyAI API Key, which may expose speech-to-text services and associated audio data to unauthorized access."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AssemblyaiApiKey"
        severity            = "medium"
        score               = 50
        id                  = "assemblyai-api-key"
        confidence          = "medium"
        keyword             = "assemblyai"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[aA][sS][sS][eE][mM][bB][lL][yY][aA][iI])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
