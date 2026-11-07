// betterleaks v1.10.0's unkey-root-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_UnkeyRootKey1
{
    meta:
        description     = "Unkey administrative root key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "UnkeyRootKey1"
        severity        = "high"
        score           = 80
        id              = "unkey-root-key.1"
        confidence      = "high"
        keyword         = "unkey_"
        skip_entropy_lt = "3.5"
        require_secret  = "[0-9]"  // gitleaks:allow
        require_secret  = "[A-Z]"  // gitleaks:allow
        require_secret  = "[a-z]"  // gitleaks:allow

    strings:
        $secret = /\b(unkey_[A-Za-z0-9]{20,32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
