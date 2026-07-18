<!-- This file conforms to the Standard Readme Style -->

# Dragonite

<!-- INSERT BANNER HERE -->

![dragonite-carteiro](https://github.com/user-attachments/assets/cefe6da0-fe98-467f-a5e5-9af78dbf255e)

<!-- INSERT BADGES HERE -->

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
[![Go Reference](https://img.shields.io/badge/go-1.26.1-blue?style=flat-square&logo=go)](./go.mod)
[![Element compatible](https://img.shields.io/badge/client-element-0DBD8B?style=flat-square&logo=element)](https://element.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](./LICENSE)

<!-- INSERT SHORT DESCRIPTION HERE -->

A Federated Multi-Party Chat System in Golang, using Matrix Protocol.

<!-- LONG DESCRIPTION HERE -->

This project is in the scope of a Distribuited Systems Introduction Course. **Dragonite** is a _multi-party federated chat_, using the [Matrix](https://matrix.org) Protocol. The server is written in Go and implements the Matrix client-server API, so it can be used with [Element](https://element.io) or any other standard Matrix client — as the banner suggests, the whole thing is inspired by the Dragonite mailer from the Pokémon&copy; franchise.

<!-- ## Table of Contents -->

## Table of Contents
 
- [Background](#background)
- [Install](#install)
  - [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Running the Server](#running-the-server)
  - [Connecting with Element](#connecting-with-element)
- [Project Structure](#project-structure)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [License](#license)

<!-- ## Security -->

<!--## Background-->

## Background
 
Dragonite explores how a federated chat system can be built on top of the [Matrix protocol](https://matrix.org/docs/matrix-concepts/elements-of-matrix/) instead of a centralized architecture. The goal is to understand, in practice, the trade-offs of federation, event synchronization, and multi-server communication — concepts covered in a Distributed Systems course.
 
The backend acts as a Matrix homeserver/bridge written in Go, implementing the Matrix client-server API so any standard Matrix client — such as [Element](https://element.io) — can connect to it directly, without a custom frontend. Key backend dependencies include [pgx](https://github.com/jackc/pgx) and [lib/pq](https://github.com/lib/pq) for PostgreSQL, [minio-go](https://github.com/minio/minio-go) for media storage, and [godotenv](https://github.com/joho/godotenv) for environment configuration (see [go.mod](./go.mod) for the full list).

## Install

### Prerequisites

- [Go](https://go.dev/) 1.26.1 or later
- [Docker](https://www.docker.com/) (used to run PostgreSQL, Redis, and MinIO locally)
- [migrate](https://github.com/golang-migrate/migrate) CLI (used by `migrate.sh`)
- [Element](https://element.io/download) (or any other [Matrix client](https://matrix.org/ecosystem/clients/)) to connect to the running server

Clone the repository:
 
```sh
git clone https://github.com/caio-bernardo/dragonite.git
cd dragonite
```
 
Download the Go module dependencies:
 
```sh
go mod download
```
## Usage

Considering you have cloned this project. Make a copy of the `.env.example` file and rename to `.env`. Fill the environmet variables.

```sh
cp .env.example .env
```

| Variable | Description |
| --- | --- |
| `BACKEND_PORT` | Port the Go server listens on |
| `SERVER_NAME` | Public host/port used to build URLs (e.g. media links) |
| `VERSION` | App version reported by the server |
| `DRAGONITE_DB_*` | PostgreSQL connection settings (username, password, database, port, schema, host) |
| `JWT_TOKEN` | Secret used to sign/verify JWT auth tokens |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` | Redis connection settings |
| `MINIO_ENDPOINT` / `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` / `MINIO_USE_SSL` | MinIO connection settings for media storage |
| `MAX_UPLOAD_BYTES` | Maximum allowed upload size, in bytes (default: 50 MB) |
 
See [`.env.example`](.env.example) for the full file with default values.


### Connecting with Element
 
1. Open [Element Web](https://app.element.io) or your installed Element app.
2. On the sign-in screen, choose **"Edit"** next to the homeserver field (or **"Sign in with a different account"**, depending on the version).
3. Enter your server's address — e.g. `http://localhost:8080` for a local run, or the value you set in `SERVER_NAME` for a deployed instance.
4. Sign in or register using the credentials created through Dragonite's own registration flow.
> Element expects the homeserver to expose the standard [Matrix client-server API](https://spec.matrix.org/latest/client-server-api/) endpoints (`/_matrix/client/...`). If Element can't discover the server automatically, make sure `SERVER_NAME` and `BACKEND_PORT` are reachable from wherever Element is running, and that any required `.well-known` delegation is set up for non-local deployments.

### Running the Server

1. (Optional) Start a local database container:

```sh
make docker-run
```

2. After running the container for the first time you need to create the tables inside the database do that using the `migrate.sh` script as follows:

```sh
export DB_URL=postgres://user:pass@localhost:5432/dbname?sslmode=disable
./migrate.sh up
```

Use the same values as in `.env` file.

3. Run the server (see more commands at [Makefile](./Makefile)).

```sh
make run
```

3. Use `Ctrl-C` to stop the server and `make docker-down` to disable the container.

<!-- ### CLI/Others -->

<!-- ## EXtra Sections -->

## Project Structure
 
```
.
├── air.toml
├── cmd
│   └── api
├── docker-compose.yml
├── go.mod
├── go.sum
├── internal
│   ├── delivery
│   ├── domain
│   ├── infrastructure
│   ├── usecase
│   └── util
├── LICENSE
├── Makefile
├── migrate.sh
├── migrations
│   ├── 000001_usuario_table.down.sql
│   ├── 000001_usuario_table.up.sql
│   ├── 000002_evento_table.down.sql
│   ├── 000002_evento_table.up.sql
│   ├── 000004_canal_table.down.sql
│   ├── 000004_canal_table.up.sql
│   ├── 000005_filter_receipt_table.down.sql
│   ├── 000005_filter_receipt_table.up.sql
│   ├── 000006_midia_table.down.sql
│   ├── 000006_midia_table.up.sql
│   ├── 000007_matrix_sync_client_func.down.sql
│   ├── 000007_matrix_sync_client_func.up.sql
│   ├── 000008_add_evento_unsigned_filed.down.sql
│   ├── 000008_add_evento_unsigned_filed.up.sql
│   ├── 000009_presence_table.down.sql
│   ├── 000009_presence_table.up.sql
│   ├── 000010_typing_state.up.sql
│   ├── 000011_backup_version_table.down.sql
│   └── 000011_backup_version_table.up.sql
├── README.md
├── static
└── TASKS.md
```

Following [Clean/Hexagonal Architecture](https://github.com/caio-bernardo/dragonite/tree/main/internal) conventions, business rules live in `internal/domain` and `internal/usecase`, while `internal/delivery` and `internal/infrastructure` handle HTTP/Matrix I/O and external dependencies respectively.

## Maintainers

- [Caio Bernardo](https://github.com/caio-bernardo)
- [Lucas Neves](https://github.com/fatorarpolinomio)
- [Willian Farias](https://github.com/willianjsf)

<!-- ## Acknowledgements -->

## Contributing

Feel free to [open a new issue](https://github.com/caio-bernardo/dragonite/issues/new) or [submit a pull request](https://github.com/caio-bernardo/dragonite/compare).
See our [CONTRIBUTING](CONTRIBUTING.md) guide for details on how to report bugs, suggest enhancements, and submit your first pull request.

<!-- ### Contributors -->

### Contributors

<a href="https://github.com/caio-bernardo/dragonite/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=caio-bernardo/dragonite" alt="Dragonite contributors" />
</a>

## License

This project is under the MIT license. For more info see [LICENSE](LICENSE).

This file was made with [Make Your Reads](https://github.com/caio-bernardo/make-your-reads).
