package nuclei

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/itchyny/gojq"
	"github.com/projectdiscovery/dsl"
)

// CompileMatchers compiles all matchers in the template
func (t *Template) CompileMatchers() error {
	for i := range t.HTTP {
		for j := range t.HTTP[i].Matchers {
			if err := t.HTTP[i].Matchers[j].Compile(); err != nil {
				return fmt.Errorf("failed to compile HTTP matcher: %w", err)
			}
		}
	}

	for i := range t.TCP {
		for j := range t.TCP[i].Matchers {
			if err := t.TCP[i].Matchers[j].Compile(); err != nil {
				return fmt.Errorf("failed to compile TCP matcher: %w", err)
			}
		}
	}

	for i := range t.Network {
		for j := range t.Network[i].Matchers {
			if err := t.Network[i].Matchers[j].Compile(); err != nil {
				return fmt.Errorf("failed to compile Network matcher: %w", err)
			}
		}
	}

	return nil
}

// CompileExtractors compiles all extractors in the template
func (t *Template) CompileExtractors() error {
	for i := range t.HTTP {
		for j := range t.HTTP[i].Extractors {
			if err := t.HTTP[i].Extractors[j].Compile(); err != nil {
				return fmt.Errorf("failed to compile HTTP extractor: %w", err)
			}
		}
	}

	for i := range t.TCP {
		for j := range t.TCP[i].Extractors {
			if err := t.TCP[i].Extractors[j].Compile(); err != nil {
				return fmt.Errorf("failed to compile TCP extractor: %w", err)
			}
		}
	}

	for i := range t.Network {
		for j := range t.Network[i].Extractors {
			if err := t.Network[i].Extractors[j].Compile(); err != nil {
				return fmt.Errorf("failed to compile Network extractor: %w", err)
			}
		}
	}

	return nil
}

// Compile compiles the matcher regex and DSL expressions
func (m *Matcher) Compile() error {
	// Compile regex patterns
	for _, regex := range m.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		m.regexCompiled = append(m.regexCompiled, compiled)
	}

	// Compile DSL expressions
	for _, dslExpr := range m.DSL {
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpr, dsl.HelperFunctions())
		if err != nil {
			return fmt.Errorf("could not compile DSL: %s", dslExpr)
		}
		m.dslCompiled = append(m.dslCompiled, compiled)
	}

	return nil
}

// Compile compiles the extractor regex, JSON queries, and DSL expressions
func (e *Extractor) Compile() error {
	// Compile regex patterns
	for _, regex := range e.Regex {
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not compile regex: %s", regex)
		}
		e.regexCompiled = append(e.regexCompiled, compiled)
	}

	// Normalize KVal keys to lowercase
	if e.CaseInsensitive {
		for i := range e.KVal {
			e.KVal[i] = strings.ToLower(e.KVal[i])
		}
	}

	// Compile JSON queries (JQ-style)
	for _, query := range e.JSON {
		parsed, err := gojq.Parse(query)
		if err != nil {
			return fmt.Errorf("could not parse JSON query: %s", query)
		}
		compiled, err := gojq.Compile(parsed)
		if err != nil {
			return fmt.Errorf("could not compile JSON query: %s", query)
		}
		e.jsonCompiled = append(e.jsonCompiled, compiled)
	}

	// Compile DSL expressions
	for _, dslExpr := range e.DSL {
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpr, dsl.HelperFunctions())
		if err != nil {
			return fmt.Errorf("could not compile DSL: %s", dslExpr)
		}
		e.dslCompiled = append(e.dslCompiled, compiled)
	}

	return nil
}
