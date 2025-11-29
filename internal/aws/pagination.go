package aws

import "context"

func CollectPages[Output any, Item any](
	ctx context.Context,
	hasMore func() bool,
	nextPage func(context.Context) (Output, error),
	extract func(Output) []Item,
) ([]Item, error) {
	var items []Item
	for hasMore() {
		page, err := nextPage(ctx)
		if err != nil {
			return nil, err
		}
		items = append(items, extract(page)...)
	}
	return items, nil
}
