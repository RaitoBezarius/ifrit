# Ifrit

In respect of the naming traditions of [Goblin](https://github.com/m4b/goblin), [Faerie](https://github.com/m4b/faerie), [Scroll](https://github.com/m4b/scroll), this is an impish, demonic library… to write PE binaries, it relies on Goblin for a lot of the heavy lifting and provide its own meta writer structure.

## Features and modus operandi

The idea is that you can start from a given binary and mutate it, e.g. add sections, add certificates, remove certificates and more.

It's built towards UEFI usecases in the [Lanzaboote](https://github.com/nix-community/lanzaboote) project, which is a UEFI stub in Rust for Secure Boot enablement in the [NixOS](https://nixos.org/) Linux distribution.
