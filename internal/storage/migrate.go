package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
)

type SchemaVersion int

type Migration struct {
	From        SchemaVersion
	To          SchemaVersion
	Description string
	Apply       func(stateDir string) error
}

var ErrNoSchemaVersion = errors.New("schema version file missing")
var ErrBackwardMigration = errors.New("backward migration is not supported")

var (
	migrationsMu sync.Mutex
	migrations   []Migration
)

func RegisterMigration(m Migration) error {
	if m.Apply == nil {
		return fmt.Errorf("migration Apply function is nil: %w", errors.New("invalid migration"))
	}
	if m.From >= m.To {
		return fmt.Errorf("migration From (%d) must be less than To (%d): %w", m.From, m.To, errors.New("invalid migration"))
	}
	migrationsMu.Lock()
	defer migrationsMu.Unlock()
	for _, existing := range migrations {
		if existing.From == m.From && existing.To == m.To {
			return fmt.Errorf("migration (%d->%d) already registered: %w", m.From, m.To, errors.New("duplicate migration"))
		}
	}
	migrations = append(migrations, m)
	return nil
}

func DetectSchemaVersion(stateDir string) (SchemaVersion, error) {
	versionPath := filepath.Join(stateDir, ".schema_version")
	data, err := os.ReadFile(versionPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("DetectSchemaVersion: %w", ErrNoSchemaVersion)
		}
		return 0, fmt.Errorf("DetectSchemaVersion: %w", err)
	}
	v, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, fmt.Errorf("DetectSchemaVersion: %w", err)
	}
	return SchemaVersion(v), nil
}

func WriteSchemaVersion(stateDir string, v SchemaVersion) error {
	versionPath := filepath.Join(stateDir, ".schema_version")
	tmpPath := versionPath + ".tmp." + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmpPath, []byte(strconv.Itoa(int(v))), 0644); err != nil {
		return fmt.Errorf("WriteSchemaVersion: %w", err)
	}
	if err := os.Rename(tmpPath, versionPath); err != nil {
		return fmt.Errorf("WriteSchemaVersion: %w", err)
	}
	return nil
}

func MigrateForward(stateDir string, target SchemaVersion, log func(string)) error {
	current, err := DetectSchemaVersion(stateDir)
	if err != nil && !errors.Is(err, ErrNoSchemaVersion) {
		return fmt.Errorf("migrate: %w", err)
	}
	if target < current {
		return fmt.Errorf("migrate: %w", ErrBackwardMigration)
	}
	if target == current {
		return nil
	}

	migrationsMu.Lock()
	// Sort migrations by From, then To
	sort.Slice(migrations, func(i, j int) bool {
		if migrations[i].From != migrations[j].From {
			return migrations[i].From < migrations[j].From
		}
		return migrations[i].To < migrations[j].To
	})

	// Build adjacency list for current->target search
	type step struct {
		from SchemaVersion
		to   SchemaVersion
	}
	adj := make(map[SchemaVersion][]SchemaVersion)
	for _, m := range migrations {
		adj[m.From] = append(adj[m.From], m.To)
	}

	// BFS to find path from current to target
	type node struct {
		version SchemaVersion
		path    []Migration
	}
	queue := []node{{version: current, path: nil}}
	visited := make(map[SchemaVersion]bool)
	var foundPath []Migration

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.version == target {
			foundPath = curr.path
			break
		}

		if visited[curr.version] {
			continue
		}
		visited[curr.version] = true

		for _, to := range adj[curr.version] {
			if !visited[to] {
				newPath := make([]Migration, len(curr.path)+1)
				copy(newPath, curr.path)
				for _, m := range migrations {
					if m.From == curr.version && m.To == to {
						newPath[len(curr.path)] = m
						break
					}
				}
				queue = append(queue, node{version: to, path: newPath})
			}
		}
	}
	migrationsMu.Unlock()

	if foundPath == nil {
		return fmt.Errorf("migrate: no path found from %d to %d: %w", current, target, errors.New("migration failed"))
	}

	for _, m := range foundPath {
		if err := m.Apply(stateDir); err != nil {
			return fmt.Errorf("migrate: step %d->%d (%s): %w", m.From, m.To, m.Description, err)
		}
		if log != nil {
			log(fmt.Sprintf("applied %d->%d: %s", m.From, m.To, m.Description))
		}
		if err := WriteSchemaVersion(stateDir, m.To); err != nil {
			return fmt.Errorf("migrate: step %d->%d: %w", m.From, m.To, err)
		}
	}

	return nil
}
