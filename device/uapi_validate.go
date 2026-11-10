package device

// validate checks a complete candidate configuration before any device state is
// changed. UAPI updates are incremental, so validation belongs after parsing.
func (d *ipcSetDevice) validate() error {
	return AWGParameters{
		JunkCount: d.junk.count, JunkMin: d.junk.min, JunkMax: d.junk.max,
		InitiationPadding: d.paddings.init, ResponsePadding: d.paddings.response,
		CookiePadding: d.paddings.cookie, TransportPadding: d.paddings.transport,
		InitiationHeader: d.headers.init, ResponseHeader: d.headers.response,
		CookieHeader: d.headers.cookie, TransportHeader: d.headers.transport,
		HeaderProtectionKey: d.headerProtectionKey,
	}.Validate()
}
