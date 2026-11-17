// betterleaks v1.10.0's gcp-service-account rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GcpServiceAccount
{
    meta:
        description      = "Google (GCP) Service-account"
        author           = "betterleaks"
        reference        = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license          = "MIT"
        os               = "any"
        category         = "secret"
        family           = "GcpServiceAccount"
        severity         = "high"
        score            = 80
        id               = "gcp-service-account"
        confidence       = "high"
        keyword          = "provider_x509"
        skip_word_secret = "image-pulling@authenticated-image-pulling.iam.gserviceaccount.com"  // gitleaks:allow

    strings:
        $secret = /\{[^\{]+(?:(?:"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----[^\}]+auth_provider_x509_cert_url)|(?:auth_provider_x509_cert_url[^\}]+"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----))[^\}]+\}/  // gitleaks:allow

    condition:
        $secret
}
