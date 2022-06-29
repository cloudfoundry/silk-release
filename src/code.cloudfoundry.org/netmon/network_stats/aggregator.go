package network_stats

type IntAggregator struct {
	Average     int
	AverageRaw  float64
	Maximum     int
	Minimum     int
	Total       int
	UpdateCount int
}

func NewIntAggregator() *IntAggregator {
	return &IntAggregator{}
}

func (agg *IntAggregator) UpdateStats(count int) {
	if agg.UpdateCount == 0 {
		agg.Maximum = count
		agg.Minimum = count
		agg.AverageRaw = float64(count)
		agg.Average = count
		agg.Total = count
		agg.UpdateCount = 1
		return
	}

	if agg.Maximum < count {
		agg.Maximum = count
	}

	if agg.Minimum > count {
		agg.Minimum = count
	}

	agg.UpdateCount++
	agg.Total += count

	agg.AverageRaw = float64(agg.Total) / float64(agg.UpdateCount)
	agg.Average = int(agg.AverageRaw)
}

func (agg *IntAggregator) Flush() {
	agg.Maximum = 0
	agg.Minimum = 0
	agg.AverageRaw = 0.0
	agg.Average = 0
	agg.Total = 0
	agg.UpdateCount = 0
}
