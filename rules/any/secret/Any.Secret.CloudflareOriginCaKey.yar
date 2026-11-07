// betterleaks v1.10.0's cloudflare-origin-ca-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_CloudflareOriginCaKey
{
    meta:
        description         = "Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "CloudflareOriginCaKey"
        severity            = "high"
        score               = 80
        id                  = "cloudflare-origin-ca-key"
        confidence          = "high"
        keyword             = "cloudflare"
        keyword             = "v1.0-"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
