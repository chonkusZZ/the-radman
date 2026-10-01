package manager

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"
)

// Charts are rendered server-side as inline SVG: no JavaScript, no external library (the UI's CSP forbids both),
// themeable through CSS variables, and every bar carries a native tooltip.

type chartSeries struct {
	Name, Class string
	Values      []int64
}

// niceMax returns an axis maximum that splits into four whole, round steps (e.g. 220 -> 240 with ticks 60/120/180/240).
func niceMax(v int64) int64 {
	if v <= 4 {
		return 4
	}
	raw := float64(v) / 4
	exp := math.Pow(10, math.Floor(math.Log10(raw)))
	for _, m := range []float64{1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10} {
		if step := math.Round(m * exp); step*4 >= float64(v) && step >= 1 {
			return int64(step) * 4
		}
	}
	return int64(10*exp) * 4
}

// stackedBars draws one stacked bar per label. tips[i] is the tooltip of bar i.
func stackedBars(alt string, labels, tips []string, series []chartSeries) template.HTML {
	const W, H, left, right, top, bottom = 760.0, 260.0, 52.0, 10.0, 12.0, 40.0
	n := len(labels)
	var maxV int64
	for i := 0; i < n; i++ {
		var s int64
		for _, se := range series {
			s += se.Values[i]
		}
		if s > maxV {
			maxV = s
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %.0f %.0f" role="img" aria-label="%s" preserveAspectRatio="xMidYMid meet">`, W, H, html.EscapeString(alt))
	if maxV == 0 {
		fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" text-anchor="middle" class="empty-note">No data in this period</text></svg>`, W/2, H/2)
		return template.HTML(b.String())
	}
	top0 := niceMax(maxV)
	plotW, plotH := W-left-right, H-top-bottom
	for i := 0; i <= 4; i++ {
		y := top + plotH - plotH*float64(i)/4
		fmt.Fprintf(&b, `<line class="grid" x1="%.0f" x2="%.0f" y1="%.1f" y2="%.1f"/><text class="axis" x="%.0f" y="%.1f" text-anchor="end">%s</text>`,
			left, W-right, y, y, left-6, y+4, compact(top0*int64(i)/4))
	}
	slot := plotW / float64(n)
	bw := math.Max(1, slot*0.72)
	step := int(math.Ceil(float64(n) / 12))
	for i := 0; i < n; i++ {
		x := left + slot*float64(i) + (slot-bw)/2
		fmt.Fprintf(&b, `<g><title>%s</title>`, html.EscapeString(tips[i]))
		base := top + plotH
		for _, se := range series {
			h := plotH * float64(se.Values[i]) / float64(top0)
			if se.Values[i] > 0 && h < 1 {
				h = 1
			}
			fmt.Fprintf(&b, `<rect class="%s" x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="1.5"/>`, se.Class, x, base-h, bw, h)
			base -= h
		}
		b.WriteString(`<rect class="hit" x="` + fmt.Sprintf("%.1f", left+slot*float64(i)) + `" y="` + fmt.Sprintf("%.0f", top) + `" width="` + fmt.Sprintf("%.1f", slot) + `" height="` + fmt.Sprintf("%.0f", plotH) + `"/></g>`)
		if i%step == 0 {
			fmt.Fprintf(&b, `<text class="axis" x="%.1f" y="%.0f" text-anchor="middle">%s</text>`, left+slot*float64(i)+slot/2, H-bottom+16, html.EscapeString(labels[i]))
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// compact renders 12500 as "12.5k".
func compact(v int64) string {
	switch {
	case v >= 1_000_000:
		return trimZero(fmt.Sprintf("%.1f", float64(v)/1e6)) + "M"
	case v >= 1000:
		return trimZero(fmt.Sprintf("%.1f", float64(v)/1e3)) + "k"
	}
	return fmt.Sprint(v)
}

func trimZero(s string) string { return strings.TrimSuffix(s, ".0") }
