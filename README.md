# Pixiewps Extend

A simple offline WPS analysis tool with Reaver-style compatibility flags.

## What is this?

This project is a lightweight WPS testing and analysis utility for authorized security research and network testing. It focuses on offline analysis, compatibility with common CLI flags, and basic router detection heuristics.

## Main features

- Offline WPS analysis support
- Reaver-style compatibility flags such as --pixie-dust and --detect
- Basic router fingerprinting and detection hints
- Simple build and test workflow

## Quick start

Build the tool:

```bash
cmake -S . -B build
cmake --build build
```

Run the help command:

```bash
./build/pixiewps-1.2 --help
```

## Documentation suite

- Setup guide: [Setup.Md](Setup.Md)
- Usage guide: [USAGES.md](USAGES.md)
- Tests: [tests](tests)

## Notes

Use this tool only on networks you own or are authorized to test. Make sure your wireless environment supports the required operations.

## Open-source credit

This repository builds on the original Pixiewps work by wiire and includes compatibility and integration work by @anbuinfosec. Please preserve attribution when redistributing or modifying the source.
