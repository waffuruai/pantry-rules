// betterleaks v1.10.0's kubernetes-secret-yaml rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_KubernetesSecretYaml
{
    meta:
        description       = "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments"
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "KubernetesSecretYaml"
        severity          = "high"
        score             = 80
        id                = "kubernetes-secret-yaml"
        confidence        = "high"
        keyword           = "secret"
        skip_regex_secret = "[\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:\\{\\{[ \\t\\w\"|$:=,.-]+}}|\"\"|'')"  // gitleaks:allow
        skip_regex_match  = "(kind:(?s:.)+\\n---\\n(?s:.)+\\bdata:|data:(?s:.)+\\n---\\n(?s:.)+\\bkind:)"  // gitleaks:allow

    strings:
        $secret = /(?:\b[kK][iI][nN][dD]:[ \t]*["']?\b[sS][eE][cC][rR][eE][tT]\b["']?(?:.){0,1000}?\b[dD][aA][tT][aA]:(?:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[A-Za-z0-9+\/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+\}\}|""|''))|\b[dD][aA][tT][aA]:(?:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[A-Za-z0-9+\/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+\}\}|""|''))(?:.){0,1000}?\b[kK][iI][nN][dD]:[ \t]*["']?\b[sS][eE][cC][rR][eE][tT]\b["']?)/  // gitleaks:allow

    condition:
        $secret and filepath matches /\.[yY][aA]?[mM][lL]$/
}
