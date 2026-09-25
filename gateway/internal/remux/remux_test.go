package remux

import "testing"

func TestLooksLikeMPEGTS(t *testing.T) {
	packet := make([]byte, 188*3+7)
	for i := 0; i < 3; i++ {
		packet[7+i*188] = 0x47
	}
	if !LooksLikeMPEGTS(packet) {
		t.Fatal("expected TS sync bytes with leading offset")
	}
	if LooksLikeMPEGTS([]byte("#EXTM3U\n#EXTINF:2,\nsegment.ts\n")) {
		t.Fatal("playlist must not be detected as transport stream")
	}
}
