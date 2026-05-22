#!/bin/bash
# Termux build recipe for pixiewps-extend
# This file is used by Termux package manager and termux-community-repo

TERMUX_PKG_HOMEPAGE="https://github.com/anbuinfosec/pixiewps-extend"
TERMUX_PKG_DESCRIPTION="WPS pixie-dust attack tool with worldwide router database and 65+ router optimization"
TERMUX_PKG_LICENSE="GPL-3.0"
TERMUX_PKG_MAINTAINER="@anbuinfosec <anbuinfosec@gmail.com>"
TERMUX_PKG_VERSION=1.4.4
TERMUX_PKG_REVISION=1
TERMUX_PKG_SRCURL="https://github.com/anbuinfosec/pixiewps-extend/archive/refs/tags/v${TERMUX_PKG_VERSION}.tar.gz"
TERMUX_PKG_SHA256="replace_with_actual_sha256"
TERMUX_PKG_DEPENDS="cmake, make, clang"
TERMUX_PKG_BUILD_IN_SRC=true
TERMUX_PKG_NO_STATICSPLIT=true

termux_step_configure() {
	cmake \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_INSTALL_PREFIX=$TERMUX_PREFIX \
		.
}

termux_step_make() {
	cmake --build . --config Release
}

termux_step_make_install() {
	install -Dm755 pixiewps $TERMUX_PREFIX/bin/pixiewps-extend
	install -Dm644 README.md $TERMUX_PREFIX/share/doc/pixiewps-extend/README.md
	install -Dm644 LICENSE.md $TERMUX_PREFIX/share/doc/pixiewps-extend/LICENSE.md
	install -Dm644 CHANGELOG.md $TERMUX_PREFIX/share/doc/pixiewps-extend/CHANGELOG.md
}
