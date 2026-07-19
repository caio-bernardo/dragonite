# Contributing to Dragonite

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued. See the **Table of Contents** for the different ways to help and details about how this project handles them. Please read the relevant section before making your contribution — it makes things a lot easier for the maintainers and smoother for everyone involved.

> And if you like the project but don't have time to contribute, that's fine too. There are other easy ways to support it:
>
> - Star the project
> - Refer to it in your own project's README
> - Mention it to friends, colleagues, or at meetups

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [I Have a Question](#i-have-a-question)
- [I Want to Contribute](#i-want-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Improving the Documentation](#improving-the-documentation)
- [Styleguides](#styleguides)
  - [Commit Messages](#commit-messages)
  - [Go Code](#go-code)
- [Join the Project Team](#join-the-project-team)

## Code of Conduct

This project doesn't have a separate Code of Conduct document yet, but participants are expected to be respectful and constructive in issues, pull requests, and any other project space. Harassment or abusive behavior will not be tolerated.

## I Have a Question

Before asking a question, please search the existing [Issues](https://github.com/caio-bernardo/dragonite/issues) to see if it has already been answered. It's also worth checking the [README](README.md) first, since setup and usage instructions live there.

If you still need help:

- Open an [Issue](https://github.com/caio-bernardo/dragonite/issues/new).
- Provide as much context as you can about what you're running into.
- Include relevant versions (Go, Node, Docker) where applicable.

## I Want to Contribute

> ### Legal Notice
> When contributing to this project, you must agree that you have authored 100% of the content, that you have the necessary rights to the content, and that the content you contribute may be provided under the project license.

### Reporting Bugs

#### Before Submitting a Bug Report

- Make sure you're using the latest version of the project.
- Check that it's actually a bug and not an environment/configuration issue (e.g. missing `.env` variables — see [`.env.example`](.env.example)).
- Search [existing issues](https://github.com/caio-bernardo/dragonite/issues) to see if it has already been reported.
- Collect relevant information: stack trace, OS/platform, Go version, Node version, and steps to reproduce.

> Please do not report security-related issues, vulnerabilities, or bugs involving sensitive information (credentials, tokens, etc.) in public issues. Contact a maintainer directly instead.

#### How Do I Submit a Good Bug Report?

We use GitHub Issues to track bugs:

- Open a [new Issue](https://github.com/caio-bernardo/dragonite/issues/new).
- Explain the expected behavior vs. the actual behavior.
- Provide clear reproduction steps someone else can follow, including relevant code or `.env` configuration (with secrets removed).
- If possible, isolate the problem into a minimal reproducible example.

### Suggesting Enhancements

This section guides you through submitting a suggestion, including new features and improvements to existing functionality.

#### Before Submitting an Enhancement

- Make sure you're using the latest version.
- Check the [README](README.md) to confirm the functionality isn't already covered or configurable.
- Search [existing issues](https://github.com/caio-bernardo/dragonite/issues) to avoid duplicates — feel free to comment on an existing one instead of opening a new issue.
- Consider whether the enhancement benefits most users of the project, not just a specific use case.

#### How Do I Submit a Good Enhancement Suggestion?

Enhancement suggestions are also tracked as [GitHub Issues](https://github.com/caio-bernardo/dragonite/issues):

- Use a **clear and descriptive title**.
- Describe the **current behavior** and the **behavior you'd expect**, and why.
- Include screenshots or short clips if it helps illustrate a UI/UX suggestion.
- Explain why the enhancement would be useful to most Dragonite users.

### Your First Code Contribution

1. Clone the repository:

   ```sh
   git clone https://github.com/caio-bernardo/dragonite.git
   cd dragonite
   ```

2. Create a new branch describing what your change does (kebab-case is preferred):

   ```sh
   git checkout -b add-media-preview
   ```

3. Set up your environment following the [Install](README.md#install) and [Usage](README.md#usage) sections of the README.

4. Make your changes. For backend changes, run:

   ```sh
   go build ./...
   go test ./...
   go fmt ./...
   ```

5. To manually test your changes end-to-end, run the server (`make run`) and connect to it with [Element](https://element.io) as described in the [README](README.md#connecting-with-element).

6. Commit your changes following the [Commit Messages](#commit-messages) convention below.

7. Open a [pull request](https://github.com/caio-bernardo/dragonite/compare), describing what you changed and referencing any related issue.

8. Wait for a review, address any feedback, and repeat until it's merged. 🎉

### Improving the Documentation

Issues and pull requests about documentation — README, code comments, examples, typos — are always welcome, no matter how small.

## Styleguides

### Commit Messages

This project follows the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#summary) specification:

```
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

- Common types: `feat`, `fix`, `refactor`, `chore`, `docs`, `test`.
- Use `!` and a `BREAKING CHANGE:` footer to flag breaking changes.
- Add a scope when the change targets a specific part of the codebase, e.g. `feat(auth): add JWT refresh endpoint`.

### Go Code

- Run `go fmt ./...` before committing.
- Keep new code aligned with the existing layered structure (`internal/domain`, `internal/usecase`, `internal/delivery`, `internal/infrastructure`) — see [Project Structure](README.md#project-structure) in the README.

## Join the Project Team

Interested in becoming a regular contributor or maintainer? Open an issue or reach out to one of the current [maintainers](README.md#maintainers) and we'll figure out the best way forward.

---

This guide is based on the [contributing.md](https://contributing.md/example/) template, adapted with inspiration from [make-your-reads](https://github.com/caio-bernardo/make-your-reads/blob/main/CONTRIBUTING.md).