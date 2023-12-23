docker rmi lockout-enclave
docker build -t lockout-enclave .
nitro-cli terminate-enclave --enclave-name lockout
nitro-cli build-enclave --docker-uri lockout-enclave:latest --output-file lockout.eif
nitro-cli run-enclave --config enclave-config.json