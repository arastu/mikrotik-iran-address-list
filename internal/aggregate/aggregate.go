package aggregate

import (
	"net/netip"

	"go4.org/netipx"
)

func Merge(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix.Masked())
	}

	set, err := builder.IPSet()
	if err != nil {
		return nil, err
	}

	return set.Prefixes(), nil
}
