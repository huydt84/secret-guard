#!/usr/bin/env sh
set -eu

if (set -o pipefail) >/dev/null 2>&1; then
  set -o pipefail
fi

OWNER="huydt84"
REPO="secret-guard"
APP="secretguard"

err() {
  printf '%s\n' "$*" >&2
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    err "missing dependency: $1"
    exit 1
  }
}

os_name() {
  case "$(uname -s)" in
    Darwin) printf '%s' darwin ;;
    Linux) printf '%s' linux ;;
    *) err "unsupported OS: $(uname -s)"; exit 1 ;;
  esac
}

arch_name() {
  case "$(uname -m)" in
    arm64|aarch64) printf '%s' arm64 ;;
    x86_64|amd64) printf '%s' amd64 ;;
    *) err "unsupported arch: $(uname -m)"; exit 1 ;;
  esac
}

release_tag() {
  if [ -n "${VERSION:-}" ]; then
    case "$VERSION" in
      v*) printf '%s' "$VERSION" ;;
      *) printf 'v%s' "$VERSION" ;;
    esac
    return
  fi

  need curl
  curl -fsSL "https://api.github.com/repos/${OWNER}/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
    | head -n1
}

main() {
  need curl
  need tar

  os=$(os_name)
  arch=$(arch_name)
  tag=$(release_tag)
  if [ -z "$tag" ]; then
    err "could not determine latest release"
    exit 1
  fi

  version=${tag#v}
  archive="${APP}_${version}_${os}_${arch}.tar.gz"
  url="https://github.com/${OWNER}/${REPO}/releases/download/${tag}/${archive}"
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT INT TERM

  install_dir=${INSTALL_DIR:-${HOME}/.local/bin}
  mkdir -p "$install_dir"

  tmp_archive="${tmpdir}/${archive}"
  err "Downloading ${url}"
  curl -fsSL "$url" -o "$tmp_archive"
  tar -xzf "$tmp_archive" -C "$tmpdir"
  install -m 0755 "$tmpdir/${APP}" "$install_dir/${APP}"

  case ":${PATH}:" in
    *:"$install_dir":*) ;;
    *)
      err "Installed to ${install_dir}, but dir is not on PATH"
      err "Add: export PATH=\"${install_dir}:$PATH\""
      ;;
  esac

  printf 'Installed %s %s to %s/%s\n' "$APP" "$tag" "$install_dir" "$APP"
}

if [ "${INSTALL_SH_TEST:-0}" = "1" ]; then
  return 0 2>/dev/null || exit 0
fi

main "$@"
