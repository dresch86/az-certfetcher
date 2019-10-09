# __Azure Certificate Fetcher__
The Azure Certificate Fetcher grabs SSL certificates from the Azure Key Vault via the REST API for use inside Ubuntu Virtual Machines.

## __Install Instructions__
### __Requirements__:
* NodeJS
* OpenSSL

### __Setup:__
1. `git clone`
2. `cd az-certfetcher`
1. `cp .env.sample .env`
1. Edit `.env` to include Azure credentials and set install path / filename
1. `chmod 600 .env`
1. `cp az-certfetcher.service /etc/systemd/system/az-certfetcher.service`
1. `cp az-certfetcher.timer /etc/systemd/system/az-certfetcher.timer`
1. `systemctl enable az-certfetcher.timer`