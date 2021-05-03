
# poudriereakv

This program can be configured as an external signing command in `poudriere.conf`
to sign package repositories using a key stored in Azure Key Vault.

It takes one parameter: the key URI to be used for signing. Credentials can be passed
in via the `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID` variables; but
unless it's for testing you'll want to use a managed service identity, which is used
by default as long as there's only one (system- or user-managed) available.

This is not an official Microsoft project.

## Badges

[![MIT License](https://img.shields.io/apm/l/atomic-design-ui.svg?)](https://github.com/tterb/atomic-design-ui/blob/master/LICENSEs)

## License

[MIT](https://choosealicense.com/licenses/mit/)

  