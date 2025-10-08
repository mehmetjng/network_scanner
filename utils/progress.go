// File: utils/progress.go
package utils

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type ProgressTracker struct {
	total       int
	current     int
	startTime   time.Time
	mu          sync.Mutex
	description string
	done        bool
	spinner     []string
	spinnerIdx  int
}

func NewProgressTracker(total int, description string) *ProgressTracker {
	return &ProgressTracker{
		total:       total,
		current:     0,
		startTime:   time.Now(),
		description: description,
		spinner:     []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		spinnerIdx:  0,
	}
}

func (p *ProgressTracker) Start() {
	go p.animate()
}

func (p *ProgressTracker) animate() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for !p.done {
		<-ticker.C
		p.mu.Lock()
		p.spinnerIdx = (p.spinnerIdx + 1) % len(p.spinner)
		p.render()
		p.mu.Unlock()
	}
}

func (p *ProgressTracker) render() {
	percentage := float64(p.current) / float64(p.total) * 100
	elapsed := time.Since(p.startTime)

	// Calculate ETA
	var eta string
	if p.current > 0 {
		avgTimePerItem := elapsed / time.Duration(p.current)
		remaining := time.Duration(p.total-p.current) * avgTimePerItem
		eta = formatDuration(remaining)
	} else {
		eta = "calculating..."
	}

	// Progress bar
	barWidth := 30
	filled := int(float64(barWidth) * percentage / 100)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	// Clear line and print
	fmt.Printf("\r%s %s [%s] %d/%d (%.1f%%) | Elapsed: %s | ETA: %s   ",
		p.spinner[p.spinnerIdx],
		p.description,
		bar,
		p.current,
		p.total,
		percentage,
		formatDuration(elapsed),
		eta,
	)
}

func (p *ProgressTracker) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current++
	if p.current >= p.total {
		p.done = true
		p.finish()
	}
}

func (p *ProgressTracker) SetCurrent(current int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = current
	if p.current >= p.total {
		p.done = true
		p.finish()
	}
}

func (p *ProgressTracker) finish() {
	elapsed := time.Since(p.startTime)
	fmt.Printf("\r✅ %s [%s] %d/%d (100%%) | Completed in %s          \n",
		p.description,
		strings.Repeat("█", 30),
		p.total,
		p.total,
		formatDuration(elapsed),
	)
}

func (p *ProgressTracker) Complete() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done = true
	p.current = p.total
	p.finish()
}

func (p *ProgressTracker) UpdateDescription(desc string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.description = desc
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// Simple spinner for indeterminate progress
type Spinner struct {
	message  string
	frames   []string
	frameIdx int
	done     bool
	mu       sync.Mutex
}

func NewSpinner(message string) *Spinner {
	return &Spinner{
		message: message,
		frames:  []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"},
	}
}

func (s *Spinner) Start() {
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for !s.done {
			<-ticker.C
			s.mu.Lock()
			fmt.Printf("\r%s %s   ", s.frames[s.frameIdx], s.message)
			s.frameIdx = (s.frameIdx + 1) % len(s.frames)
			s.mu.Unlock()
		}
	}()
}

func (s *Spinner) Stop() {
	s.mu.Lock()
	s.done = true
	s.mu.Unlock()
	fmt.Print("\r")
}

func (s *Spinner) Success(message string) {
	s.Stop()
	fmt.Printf("✅ %s\n", message)
}

func (s *Spinner) Error(message string) {
	s.Stop()
	fmt.Printf("❌ %s\n", message)
}
