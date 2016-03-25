package reverseproxy

type BackendStrategy interface {
	NextBackend() Backend
}

type RoundRobinStrategy struct {
	Backends []Backend
	idx      int
}

func (s *RoundRobinStrategy) NextBackend() Backend {
	n := len(s.Backends)

	if n == 1 {
		return s.Backends[0]
	} else {
		s.idx = (s.idx + 1) % n
		return s.Backends[s.idx]
	}
}
