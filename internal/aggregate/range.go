package aggregate

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"
)

func RangeToPrefixes(start, end netip.Addr) ([]netip.Prefix, error) {
	if !start.IsValid() || !end.IsValid() {
		return nil, fmt.Errorf("invalid IP range %q-%q", start, end)
	}
	if start.BitLen() != end.BitLen() {
		return nil, fmt.Errorf("mixed-family IP range %q-%q", start, end)
	}
	if end.Less(start) {
		return nil, fmt.Errorf("descending IP range %q-%q", start, end)
	}

	return netipx.IPRangeFrom(start, end).Prefixes(), nil
}
