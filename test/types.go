package test

var (
	SeedPre = [16]uint8{
		0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
		0xe5}
	Threshold                   = 3 // Security threshold (t-out-of-n)
	N                           = 6 // Number of servers
	K                           = 2 // Presignature to create
	Indices                     = [][]int{{1, 3, 5}, {1, 5, 2}, {2, 4, 5}}
	IndicesSimple               = [][]int{{1, 2, 3}, {1, 2, 3}, {1, 2, 3}}
	IndicesSignersTestTauOutOfN = []int{0, 1, 2}
	IndicesSignersTestNOutOfN   = []int{0, 1, 2, 3, 4, 5}
)
