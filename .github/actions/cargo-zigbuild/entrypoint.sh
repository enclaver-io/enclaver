#!/usr/bin/env bash

set -euo pipefail

target=""

# In GitHub Actions docker actions, `with.args: |` is passed as ONE argument
# containing newlines. Locally you might pass multiple argv items.
if [[ $# -eq 1 ]]; then
	args_string="$1"
	args_string="${args_string//$'\n'/ }"
	read -r -a args <<< "$args_string"
else
	args=("$@")
fi

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

exec cargo zigbuild "${args[@]}"