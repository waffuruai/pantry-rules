// betterleaks v1.10.0's azure-storage-account-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AzureStorageAccountKey
{
    meta:
        description       = "Detected an Azure Storage account key."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "AzureStorageAccountKey"
        severity          = "high"
        score             = 80
        id                = "azure-storage-account-key"
        confidence        = "high"
        keyword           = "accountkey"
        keyword           = "storage"
        keyword           = "accesskey"
        keyword           = "access_key"
        keyword           = "access-key"
        component1        = "azure-storage-account-name"
        component1_within = "8L"
        skip_entropy_le   = "4.0"

    strings:
        $secret = /\b(?:[Aa][cC][cC][oO][uU][nN][tT][Kk][eE][yY]|(?:[aA][zZ][uU][rR][eE][_\s.-]*)?(?:[sS][tT][oO][rR][aA][gG][eE][_\s.-]*)?(?:[aA][cC][cC][oO][uU][nN][tT][_\s.-]*)?(?:[aA][cC][cC][eE][sS][sS][_\s.-]*)?[kK][eE][yY])\b(?:.{0,24}?)([a-zA-ZA-Za-z0-9+\/]{86}==)/  // gitleaks:allow

    condition:
        $secret
}
