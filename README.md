# splunk-credential-manager
Set of scripts that can be used to integrate credential sync between some credential provider service and splunk

CredentialRetriever interface can be used to write another python class that knows how to reach whichever application/utility needed.

# config.ini
| Setting | Description |
| -------- | --------- |
| ssl: | contains configurations for server identity validation
| ssl.rootca: | cacert used to validate connection to splunk and credential manager
| privileged-account: | contains configurations for the account used within splunk to make password updates/changes
| privileged-account.provider: | contains configurations to point to CredentialManager class
| privileged-account.provider.type: | ['PAM']
| privileged-account.provider.url: | Credential management application host. Full path to the api used to retrieve credentials
| privileged-account.provider.config: | ini config containing settings for provider



| privileged-account.provider.type: | PAM |
| -------- | --------- |
| | |
| privileged-account.name: | Name of privileged account
| privileged-account.safe: | Vault containing privileged account
| privileged-account.appid: | Cyberark appid
| privileged-account.extra-params: | Contains configurations for any extra parameters used to send to cyberark when retrieving credentials
| privileged-account.extra-params.address: | Example. Sends another field to match in cyberark object named address



| Setting | Description |
| -------- | --------- |
| sync-accounts: | Contains configurations for which accounts to sync between credential manager and splunk
| sync-accounts.provider: | Contains configurations to point to CredentialManager class
| sync-accounts.provider.type: | ['PAM']
| sync-accounts.provider.url: | Credential management application host. Full path to the api used to retrieve credentials
| sync-accounts.provider.config: | ini config containing settings for provider
| sync-accounts.safe: | Vault containing splunk account
| sync-accounts.appid: | Cyberark vault appid
| sync-accounts.force: | Forces the password update on splunk regardless of if its different
| sync-accounts.accounts: | Contains the configurations for which accounts to keep in sync between credential manager and splunk
| sync-accounts.accounts.pamUsername: | Username of cyberark object
| sync-accounts.accounts.hostname: | Splunk host to sync password
| sync-accounts.accounts.username: | Username in splunk
| sync-accounts.accounts.app: | App that splunk uses to store credential
| sync-accounts.accounts.realm: | Splunk realm that the credential exists in
| sync-accounts.accounts.type: | Type of Splunk account ['CUSTOM_API', 'PASSWORDS_CONF']
| sync-accounts.accounts.extra: | Defines extra settings for CUSTOM_API
| sync-accounts.accounts.extra.api: | Contains configurations for splunk API
| sync-accounts.accounts.extra.api.endpoint: | /servicesNS/... endpoint used to update credentials (e.g. /servicesNS/nobody/<splunk_app_for_credential_storage>/configs/conf-authentication)
| sync-accounts.accounts.extra.api.reload: | _reload endpoint used to trigger a reload of configuration (e.g. /services/authentication/providers/services/_reload)
| sync-accounts.accounts.extra.api.stanza: | Configuration stanza that contains field which we will update with new password
| sync-accounts.accounts.extra.api.field: | Fieldname that will be associated with the new password
| sync-accounts.accounts.extra.api.encrypt: | Whether or not will pre-encrypt credential so splunk doesnt need to restart
| sync-accounts.accounts.extra-params: | Contains configurations for any extra parameters used to send to cyberark when retrieving credentials
