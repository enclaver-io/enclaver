#!/usr/bin/env bash

set -euo pipefail

target=""
args=("$@")

for ((i=0; i<${#args[@]}; i++)); do
	case "${args[$i]}" in
		--target=*)
			target="${args[$i]#--target=}"
			;;
		--target)
			if (( i + 1 < ${#args[@]} )); then
				target="${args[$((i+1))]}"
			fi
			;;
	esac
done

if [[ -n "$target" ]]; then
	toolchain="$(rustup show active-toolchain | awk '{print $1}')"
	echo "Installing Rust target '$target' for toolchain '$toolchain'"
	rustup target add "$target" --toolchain "$toolchain"
fi

exec cargo zigbuild "$@"