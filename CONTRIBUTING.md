# Contributing to IONA

Thank you for your interest in contributing to IONA.

IONA is an experimental open-source framework focused on deterministic execution, reproducibility, upgrade safety, and operator reliability in distributed systems. Contributions that improve clarity, correctness, validation, and operational usability are especially valuable.

## Project Approach

IONA is developed as a research and engineering repository.

This means contributions should generally prioritize:

- correctness over novelty
- explicit behavior over implicit assumptions
- reproducibility over convenience
- safety over premature complexity
- documentation and validation alongside implementation changes

## Types of Contributions

Helpful contributions include:

- protocol and node implementation improvements
- reproducibility and replay tooling
- integration and regression tests
- upgrade and migration validation
- documentation and architecture clarification
- observability and operational tooling
- bug fixes and code quality improvements
- issue triage and review feedback

## Before You Start

Before opening large changes, please:

- read the current repository documentation
- check whether related work is already in progress
- open an issue or discussion for major design changes when appropriate
- keep changes aligned with the repository’s stated scope and current maturity

## Development Expectations

Contributors are encouraged to:

- keep changes scoped and understandable
- prefer explicit, well-documented behavior
- include tests where practical
- document important assumptions and edge cases
- avoid introducing unnecessary complexity
- preserve deterministic and reproducibility-oriented behavior where relevant

## Coding Style

General expectations:

- prefer readable, maintainable code
- use clear naming and explicit control flow
- keep modules cohesive
- avoid hidden side effects where practical
- document behavior that affects determinism, upgrades, compatibility, or operational safety

Repository-specific formatting, linting, or test workflows should be followed where available.

## Testing

Changes should be validated as thoroughly as practical before submission.

Depending on the area touched, this may include:

- unit tests
- integration tests
- reproducibility-oriented checks
- replay or regression validation
- upgrade or migration scenario testing
- local multi-node environment testing

If a change affects behavior but does not include tests, the reason should be clear.

## Documentation Expectations

Documentation is part of the contribution surface, not an afterthought.

Please update documentation when changes affect:

- architecture
- protocol assumptions
- upgrade behavior
- reproducibility workflows
- operator procedures
- configuration
- repository structure or setup

## Pull Requests

When opening a pull request, please try to include:

- a short summary of the change
- the reason for the change
- any relevant context or linked issue
- testing performed
- any operational, compatibility, or determinism implications

Smaller, focused pull requests are generally easier to review than very large multi-purpose changes.

## Security Issues

If you believe you have found a security vulnerability, please do **not** open a public issue.

Follow the process described in [`SECURITY.md`](SECURITY.md).

## Scope Discipline

IONA is intentionally focused.

Changes are more likely to be accepted when they improve one or more of the following:

- deterministic execution validation
- reproducibility workflows
- upgrade safety and compatibility
- observability and operator tooling
- documentation and engineering clarity

Changes that introduce major new scope without clear alignment may require additional discussion.

## Communication

Good-faith technical discussion is welcome.

Please keep contributions:

- constructive
- technically grounded
- respectful of review time
- aligned with the project’s current stage and goals

## License

By contributing to this repository, you agree that your contributions are provided under the same license as the project unless explicitly stated otherwise.
