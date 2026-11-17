// betterleaks v1.10.0's global prefilter (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// It never matches: the scanner reads its meta.

private rule Any_Secret_Prefilter
{
    meta:
        description     = "betterleaks' global prefilter: files Pantry never reads for secrets"
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        skip_regex_path = "gitleaks\\.toml"  // gitleaks:allow
        skip_regex_path = "(?i)\\.(?:bmp|gif|jpe?g|png|svg|tiff?)$"  // gitleaks:allow
        skip_regex_path = "(?i)\\.(?:eot|[ot]tf|woff2?)$"  // gitleaks:allow
        skip_regex_path = "(?i)\\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|dll|pdb|exe|gltf)$"  // gitleaks:allow
        skip_regex_path = "go\\.(?:mod|sum|work(?:\\.sum)?)$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)vendor/modules\\.txt$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)gradlew(?:\\.bat)?$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)gradle\\.lockfile$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)mvnw(?:\\.cmd)?$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)\\.mvn/wrapper/MavenWrapperDownloader\\.java$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)node_modules(?:/.*)?$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)(?:bun\\.lockb?|deno\\.lock|npm-shrinkwrap\\.json|package-lock\\.json|pnpm-lock\\.yaml|yarn\\.lock)$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)bower_components(?:/.*)?$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\\.min)?\\.js(?:\\.map)?$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)javascript\\.json$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)(?:Pipfile|poetry)\\.lock$"  // gitleaks:allow
        skip_regex_path = "(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$"  // gitleaks:allow
        skip_regex_path = "(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\\.\\d{1,2})+|python/[23](?:\\.\\d{1,2})+/lib(?:64)?)(?:/.*)?$"  // gitleaks:allow
        skip_regex_path = "(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\\.dist-info(?:/.+)?$"  // gitleaks:allow
        skip_regex_path = "(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$"  // gitleaks:allow
        skip_regex_path = "\\.gem$"  // gitleaks:allow
        skip_regex_path = "verification-metadata\\.xml"  // gitleaks:allow
        skip_regex_path = "Database.refactorlog"  // gitleaks:allow
        skip_regex_path = "(?:^|/)\\.git$"  // gitleaks:allow

    condition:
        false
}
