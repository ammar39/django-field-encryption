publish:
	uv run python -m build
	uv run twine upload dist/*

release:
	@if [ -z "$(TAG)" ]; then \
		echo "Usage: make release TAG=v$(VERSION)"; \
		exit 1; \
	fi
	gh release create $(TAG) --generate-notes
