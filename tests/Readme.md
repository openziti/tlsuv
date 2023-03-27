Running TLSUV test
-------
We use custom test server to test various use cases (working golang installation is required).
The test server opens the following endpoints:


| port | description                                              |
|------|----------------------------------------------------------|
| 8080 | HTTP test endpoint (httpbin API)                         |
| 8443 | HTTPS test endpoint (httpbin API)                        |
| 9443 | client auth endpoint: checks supplied client certificate |


Start test server:
```console
cd ./tests/test_server
go run ./test-server.go -keyfile ../certs/server.key -certfile ../certs/server.crt
```

now you're ready to run tests