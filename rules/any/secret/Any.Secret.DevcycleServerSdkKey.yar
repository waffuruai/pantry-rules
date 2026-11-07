// betterleaks v1.10.0's devcycle-server-sdk-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_DevcycleServerSdkKey
{
    meta:
        description     = "DevCycle server SDK key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DevcycleServerSdkKey"
        severity        = "high"
        score           = 80
        id              = "devcycle-server-sdk-key"
        confidence      = "high"
        keyword         = "dvc_server_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(dvc_server_[A-Za-z0-9]{8,32})/  // gitleaks:allow

    condition:
        $secret
}
