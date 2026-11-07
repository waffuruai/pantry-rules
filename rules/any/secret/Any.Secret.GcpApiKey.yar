// betterleaks v1.10.0's gcp-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GcpApiKey
{
    meta:
        description       = "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "GcpApiKey"
        severity          = "high"
        score             = 80
        id                = "gcp-api-key"
        confidence        = "high"
        keyword           = "aiza"
        skip_entropy_le   = "4.0"
        skip_regex_secret = "AIzaSyabcdefghijklmnopqrstuvwxyz1234567"  // gitleaks:allow
        skip_regex_secret = "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs"  // gitleaks:allow
        skip_regex_secret = "AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM"  // gitleaks:allow
        skip_regex_secret = "AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU"  // gitleaks:allow
        skip_regex_secret = "AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0"  // gitleaks:allow
        skip_regex_secret = "AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A"  // gitleaks:allow
        skip_regex_secret = "AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c"  // gitleaks:allow
        skip_regex_secret = "AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4"  // gitleaks:allow
        skip_regex_secret = "AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY"  // gitleaks:allow
        skip_regex_secret = "AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM"  // gitleaks:allow
        skip_regex_secret = "AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ"  // gitleaks:allow
        skip_regex_secret = "AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g"  // gitleaks:allow
        skip_regex_secret = "AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU"  // gitleaks:allow
        skip_regex_secret = "AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw"  // gitleaks:allow
        skip_regex_secret = "AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE"  // gitleaks:allow
        skip_regex_secret = "AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY"  // gitleaks:allow

    strings:
        $secret = /\b(AIza[\w-]{35})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
