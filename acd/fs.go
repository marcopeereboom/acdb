package acd

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

var (
	ErrNotFound = errors.New("object not found")
)

func (c *Client) GetMetadataFS(filepath string) (*Asset, error) {
	c.Log(DebugTrace, "[TRC] GetMetadataFS %v", filepath)

	file := path.Base(filepath)

	elements := strings.Split(filepath, "/")
	parent := c.root
	for _, v := range elements {
		if v == "" {
			continue
		}
		c.Log(DebugTrace, "[TRC] looking for: %v", v)
		assets, err := c.GetChildrenJSON(parent, "?filters=name:"+v)
		if err != nil {
			return nil, err
		}

		// sanity
		if assets.Count != 1 {
			c.Log(DebugTrace, "[TRC] unexpected count: %v",
				assets.Count)
			return nil, ErrNotFound
		}

		if assets.Data[0].Name != v {
			return nil, fmt.Errorf("returned invalid name")
		}

		found := false
		for _, vv := range assets.Data[0].Parents {
			if vv == parent {
				parent = assets.Data[0].ID
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("parent not found %v", parent)
		}

		if v == file {
			return &assets.Data[0], nil
		}
	}

	return nil, ErrNotFound
}
