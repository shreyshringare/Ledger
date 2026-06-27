package fraud

// DetectRings runs Tarjan's strongly connected components algorithm over adjList
// and returns all SCCs with size >= minSize. An SCC with size >= 2 means money
// can cycle back to its origin account — a potential fraud ring.
// Time complexity: O(V+E) where V = accounts, E = transaction edges.
func DetectRings(adjList map[string][]string, minSize int) [][]string {
	index := 0
	stack := []string{}
	onStack := map[string]bool{}
	indices := map[string]int{}
	lowlink := map[string]int{}
	var sccs [][]string

	var strongconnect func(v string)
	strongconnect = func(v string) {
		indices[v] = index
		lowlink[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		for _, w := range adjList[v] {
			if _, seen := indices[w]; !seen {
				strongconnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}

		if lowlink[v] == indices[v] {
			var scc []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			if len(scc) >= minSize {
				sccs = append(sccs, scc)
			}
		}
	}

	for v := range adjList {
		if _, seen := indices[v]; !seen {
			strongconnect(v)
		}
	}
	return sccs
}
