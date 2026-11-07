// betterleaks v1.10.0's configcat-sdk-key-extended rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ConfigcatSdkKeyExtended
{
    meta:
        description     = "Detected an extended ConfigCat SDK key, which may allow access to feature flag configuration data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ConfigcatSdkKeyExtended"
        severity        = "high"
        score           = 80
        id              = "configcat-sdk-key-extended"
        confidence      = "high"
        keyword         = "configcat-sdk-1"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(configcat-sdk-1\/[A-Za-z0-9_-]{22}\/[A-Za-z0-9_-]{22})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
