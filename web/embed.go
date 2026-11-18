// SPDX-License-Identifier: Apache-2.0

package web

import "embed"

//go:embed all:templates all:static all:i18n all:ui
var FS embed.FS
