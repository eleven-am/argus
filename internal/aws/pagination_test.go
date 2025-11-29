package aws

import (
	"context"
	"errors"
	"testing"
)

func TestCollectPages_SinglePage(t *testing.T) {
	pages := [][]string{{"a", "b", "c"}}
	pageIndex := 0

	hasMore := func() bool {
		return pageIndex < len(pages)
	}

	nextPage := func(ctx context.Context) ([]string, error) {
		if pageIndex >= len(pages) {
			return nil, errors.New("no more pages")
		}
		result := pages[pageIndex]
		pageIndex++
		return result, nil
	}

	extract := func(page []string) []string {
		return page
	}

	result, err := CollectPages(context.Background(), hasMore, nextPage, extract)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 items, got %d", len(result))
	}

	expected := []string{"a", "b", "c"}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("expected result[%d] = %s, got %s", i, v, result[i])
		}
	}
}

func TestCollectPages_MultiplePages(t *testing.T) {
	pages := [][]int{{1, 2}, {3, 4}, {5}}
	pageIndex := 0

	hasMore := func() bool {
		return pageIndex < len(pages)
	}

	nextPage := func(ctx context.Context) ([]int, error) {
		if pageIndex >= len(pages) {
			return nil, errors.New("no more pages")
		}
		result := pages[pageIndex]
		pageIndex++
		return result, nil
	}

	extract := func(page []int) []int {
		return page
	}

	result, err := CollectPages(context.Background(), hasMore, nextPage, extract)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 5 {
		t.Errorf("expected 5 items, got %d", len(result))
	}

	expected := []int{1, 2, 3, 4, 5}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("expected result[%d] = %d, got %d", i, v, result[i])
		}
	}
}

func TestCollectPages_EmptyPages(t *testing.T) {
	hasMore := func() bool {
		return false
	}

	nextPage := func(ctx context.Context) ([]string, error) {
		return nil, errors.New("should not be called")
	}

	extract := func(page []string) []string {
		return page
	}

	result, err := CollectPages(context.Background(), hasMore, nextPage, extract)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 items, got %d", len(result))
	}
}

func TestCollectPages_Error(t *testing.T) {
	callCount := 0
	expectedErr := errors.New("API error")

	hasMore := func() bool {
		return callCount < 3
	}

	nextPage := func(ctx context.Context) ([]string, error) {
		callCount++
		if callCount == 2 {
			return nil, expectedErr
		}
		return []string{"item"}, nil
	}

	extract := func(page []string) []string {
		return page
	}

	_, err := CollectPages(context.Background(), hasMore, nextPage, extract)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestCollectPages_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	callCount := 0

	hasMore := func() bool {
		return true
	}

	nextPage := func(ctx context.Context) ([]string, error) {
		callCount++
		if callCount == 2 {
			cancel()
			return nil, ctx.Err()
		}
		return []string{"item"}, nil
	}

	extract := func(page []string) []string {
		return page
	}

	_, err := CollectPages(ctx, hasMore, nextPage, extract)
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
}

type mockOutput struct {
	Items     []string
	NextToken *string
}

func TestCollectPages_WithStructExtractor(t *testing.T) {
	token1 := "token1"
	pages := []mockOutput{
		{Items: []string{"a", "b"}, NextToken: &token1},
		{Items: []string{"c"}, NextToken: nil},
	}
	pageIndex := 0

	hasMore := func() bool {
		return pageIndex < len(pages)
	}

	nextPage := func(ctx context.Context) (mockOutput, error) {
		if pageIndex >= len(pages) {
			return mockOutput{}, errors.New("no more pages")
		}
		result := pages[pageIndex]
		pageIndex++
		return result, nil
	}

	extract := func(out mockOutput) []string {
		return out.Items
	}

	result, err := CollectPages(context.Background(), hasMore, nextPage, extract)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 items, got %d", len(result))
	}

	expected := []string{"a", "b", "c"}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("expected result[%d] = %s, got %s", i, v, result[i])
		}
	}
}
