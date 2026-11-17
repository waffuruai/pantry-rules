// betterleaks v1.10.0's cloudflare-api-key.2 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CloudflareApiKey2
{
    meta:
        description         = "Detected a Cloudflare API key version 2 (cfut/cfat format), potentially granting access to Cloudflare account and service resources."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "CloudflareApiKey2"
        severity            = "high"
        score               = 80
        id                  = "cloudflare-api-key.2"
        confidence          = "high"
        keyword             = "cfut_"
        keyword             = "cfat_"
        component1          = "cloudflare-account-id.1"
        component1_within   = "5L"
        component1_optional = true
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(cf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
