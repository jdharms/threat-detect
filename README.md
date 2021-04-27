## Note (4/27/2021)
This project was created to fulfill a "coding challenge" as part of a job interview.  I've
committed the assignment to [a file](<./REDACTED GoLang Coding Challenger V3.pdf>) after renaming
the file to protect the innocent.

# threat-detect
`detect` is an http service that allows users to issue requests to check IPv4 addresses
against the Spamhaus DNSBL.  It provides a GraphQL interface, uses SQLite to cache the lookup
results, and can be deployed natively or inside a Docker container.

## Deployment

### Native Deployment
Assuming your machine has Go, gcc, make, and sqlite3 installed and configured, you can deploy
`detect` natively using the command:


```
$ make run
```

This will create a SQLite database file at ./data.db, download the Go dependencies, compile
the service as a file named `detect` and execute it listening on port 8080.

To wipe the database file, delete it or run `$ make clean_db`.

### Docker Deployment
To deploy the service to a Docker container, you can use the command:

```
$ make docker && make docker_run
```

If you would prefer, you can use the Docker commands:

```
$ docker build -t detect:latest .
$ docker run -v detect-data:/app/data -p 8080:8080 --rm --name detect detect
```

To run on a port other than 8080, use the following command:

```
$ docker run -v detect-data:/app/data -p [port]:[port] --rm --name detect -e PORT=[port] detect
```

... where `[port]` is the numeric port for the server to listen on.

The command `$ make docker_volume` will create a Docker volume that will allow the service
to persist its data through multiple executions.  Alternatively, use the Docker command
`docker volume create detect-data`.  `$ make clean_docker` will remove the volume.

Implementation note: The Spamhaus DNSBL may return multiple result codes for a given IP address.  These codes are all returned inside the `response_code` field of the getIPDetails GraphQL query, separated by
comma (',') characters.

## Development
Clone the repository locally

```$ git clone https://github.com/jdharms/threat-detect.git```

Ensure a recent version of Go is installed on your machine, as well as sqlite3. (Go 1.15 was used to develop this.)

The project's unit tests can be executed using `$ make test`, or `$ go test ./...`.

### Project Organization
The project is organized as follows:

`./server.go`: The service's main package/function.  Responsible for starting up an HTTP server using the GraphQL handler, as well as initializing dependencies.

`./internal/auth`: This package contains the service's authorization related code.  Included is an implementation that uses Basic Authentication against a known username/password combination as an example.

`./internal/db`: This package is responsible for the persistence layer of the service.  The included implementation uses SQLite.

`./internal/dnsbl`: This package provides functionality for looking up an IPv4 address using a DNSBL.  The included implementation uses Spamhaus's DNSBL.

`./graph`: This package contains the generated code from gqlgen as well as the implementations of the query/mutation provided.  This is the "business logic" of the application, with the rest of the packages above providing functionality that will be depended on by the GraphQL Resolver.  All of these packages have unit tests.

### Dependencies
* github.com/99designs/gqlgen, github.com/vektah/gqlparser/v2 -- Used to bootstrap the GraphQL service and provides a framework for dependency injection.
* github.com/DATA-DOG/go-sqlmock -- Used for writing unit tests for the persistence layer. go-sqlmock allows us to inject a mock database into our persistence code and assert on the queries/execs called.
* github.com/google/uuid -- This library is used to generate random UUIDs.
* github.com/jmoiron/sqlx -- A very thin abstraction layer on top of the standard library sql package.
* github.com/mattn/go-sqlite3 -- Provides the database driver for SQLite3.
