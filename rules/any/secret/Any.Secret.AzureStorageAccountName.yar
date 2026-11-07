// betterleaks v1.10.0's azure-storage-account-name rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_AzureStorageAccountName
{
    meta:
        description     = "Detected an Azure Storage account name, used as a component of Azure Storage key validation."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AzureStorageAccountName"
        severity        = "medium"
        score           = 50
        id              = "azure-storage-account-name"
        confidence      = "medium"
        keyword         = "accountname"
        keyword         = "blob.core.windows.net"
        keyword         = "storage"
        skip_entropy_le = "1.5"

    strings:
        $secret = /(?:\b[Aa][cC][cC][oO][uU][nN][tT][Nn][aA][mM][eE]\s*=\s*([A-Za-z0-9]{3,24})\b|[hH][tT][tT][pP][sS]:\/\/([A-Za-z0-9]{3,24})\.[bB][lL][oO][bB]\.[cC][oO][rR][eE]\.[wW][iI][nN][dD][oO][wW][sS]\.[nN][eE][tT]\b|\b(?:[aA][zZ][uU][rR][eE][_\s.-]*[sS][tT][oO][rR][aA][gG][eE][_\s.-]*(?:[aA][cC][cC][oO][uU][nN][tT][_\s.-]*)?[nN][aA][mM][eE]|[sS][tT][oO][rR][aA][gG][eE][_\s.-]*[aA][cC][cC][oO][uU][nN][tT][_\s.-]*[nN][aA][mM][eE])\b(?:.{0,24}?)([A-Za-z0-9]{3,24})\b)/  // gitleaks:allow

    condition:
        $secret
}
