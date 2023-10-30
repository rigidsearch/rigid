# Rigid

<img src=static/rigid.png>

Unscalable, uncomplex, inflexible, inelastic. Rigid.

Is it a bird? Is it a plane? Is it yet another security product?

Is it an API-first SIEM that no one will ever use?

## Usage

Build container:

`docker build -t rigid .`

Set admin password:

`export ADMIN_AUTH=$(echo -n admin:supersecurepassw0rd | base64)`

Run it:

`docker run -it -p 5000:5000 -e ADMIN_AUTH rigid`

## Ingesting logs

See example usage script [example_api_use.py](example_api_use.py), or curl testing script [test.sh](test.sh)



