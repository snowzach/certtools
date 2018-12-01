package autocert

// InsecureGlobalStatic is a non-random byte reader that can be used to generaate an insecure private key
// This will generate the same bytes on every box (all zeros). It is horribly insecure.
type InsecureGlobalStatic struct{}

func InsecureGlobalStaticReader() InsecureGlobalStatic {
	return InsecureGlobalStatic{}
}

func (r InsecureGlobalStatic) Read(s []byte) (int, error) {
	// Set it to all zeros
	l := len(s)
	for x := 0; x < l; x++ {
		s[x] = 0
	}
	return l, nil
}

// InsecureString is a non-random bytes reader that can be used to generate an insecure private key based on a provided string
// The upside of this is that the same string input should yield the same bytes so you can send in something like the hostname
// and it will generate the same output everytime you run your program.
// The downside is that it is very insecure and should only be used for testing
type InsecureString struct {
	seed   []byte
	pos    int
	length int
}

func InsecureStringReader(seed string) *InsecureString {
	// Ensure there is at least one character in seed
	if len(seed) == 0 {
		seed = " "
	}
	return &InsecureString{
		seed:   []byte(seed),
		pos:    0,
		length: len(seed),
	}
}
func (r *InsecureString) Read(s []byte) (int, error) {
	// Just repead the string over and over
	l := len(s)
	for x := 0; x < l; x++ {
		s[x] = r.seed[r.pos%r.length]
		r.pos++
	}
	return l, nil
}
