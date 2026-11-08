package loader

import _ "embed"

//go:embed bpf/xdp_filter.o
var programBytes []byte
