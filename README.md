<!-- This file conforms to the Standard Readme Style -->

# Dragonite

<!-- INSERT BANNER HERE -->

![dragonite-carteiro](https://github.com/user-attachments/assets/cefe6da0-fe98-467f-a5e5-9af78dbf255e)

<!-- INSERT BADGES HERE -->

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

<!-- INSERT SHORT DESCRIPTION HERE -->

A Federated Multi-Party Chat System in Golang and Svelte, using Matrix Protocol.

<!-- LONG DESCRIPTION HERE -->

This project is in the scope of a Distribuited Systems Introduction Course. **Dragonite** is a _multi-party federated chat_, using the [Matrix.org](https://matrix.org) Protocol, to create a federated chat-app, our server is built using the Go programming language, while the client uses SvelteKit and the `matrix-js-sdk`. Finnaly, as you can see on the banner, we're inspired by the dragonite mailer from the Pokemon&copy; franchise.

<!-- ## Table of Contents -->

<!-- ## Security -->

<!--## Background-->

## Install

### Prerequisites

- [npm](https://npmjs.com/)
- [Go](https://godoc.org/)
- [Docker](https://www.docker.com/)

1. To install the client, clone this project.

```sh
git clone https://github.com/caio-bernardo/dragonite.git
```

See the following for the frontend:

1. Enter the `frontend` folder

```sh
cd frontend
```

2. Install the dependencies

```sh
npm install
```

## Usage

Considering you have cloned this project. Make a copy of the `.env.example` file and rename to `.env`. Fill the environmet variables.

### Client

To run the client just use `npm`:

```sh
npm run dev
```

Access the endpoint on the terminal, normally http://localhost:5173.

### Server

1. (Optionally) create a container for the database

```sh
make docker-run
```

2. Run the project using the Makefile (see more commands at [Makefile](./Makefile)).

```sh
make run
```

3. Use `Ctrl-C` to stop the server and `make docker-down` to disable the container.

<!-- ### CLI/Others -->

<!-- ## EXtra Sections -->

<!-- ## API -->

## Maintainers

- Caio Bernardo
- Lucas Neves
- Willian Farias

<!-- ## Acknowledgements -->

## Contributing

Feel free to [Open a New Issue](/issues/new) or [Submit a Pull Request](/compare).
See our [CONTRIBUTING](CONTRIBUTING.md) file for more information in how to contribute in more specific ways.
Don't forget to check our [Code of Conduct](CODE_OF_CONDUCT.md) for the repository guidelines.

<!-- ### Contributors -->

## License

This project is under the MIT license. For more info see [LICENSE](LICENSE).

This file was made with [Make Your Reads](https://github.com/caio-bernardo/make-your-reads).
