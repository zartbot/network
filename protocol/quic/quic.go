package quic

/*
Long Header Packet {
	Header Form (1) = 1,
	Fixed Bit (1) = 1,
	Long Packet Type (2),
	Type-Specific Bits (4),
	Version (32),
	DCID Length (8),
	Destination Connection ID (0..160),
	SCID Length (8),
	Source Connection ID (0..160),
  }
*/
