#!/usr/bin/env sh

cbindgen --config cbindgen.toml --crate turtls --output include/turtls.h --lang c
